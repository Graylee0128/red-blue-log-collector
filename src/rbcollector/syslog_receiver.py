"""TCP syslog receiver for Metis's log plane (架構 §十一, deploy/logship.sh).

Metis's rsyslog forwards RFC5424 lines shaped by its own template:

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - [metis@1 src="<file>" role="<red|blue|host>"] MSG

-- newline-framed (rsyslog's default "traditional" TCP framing; logship.sh's
omfwd action doesn't set TCP_Framing, so it's not octet-counted). This module
parses that line shape, reconstructs the same ingest payload the manual
forwarders in scripts/forward-*.sh build from raw log lines, and calls the
existing adapters/store directly -- same normalization, same idempotency, no
second network hop through the HTTP API.

role="host" carries docker-events/audit lines, not red/blue team activity --
there is no normalized_events row for it (yet). Logged and skipped.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

from .adapters import blue, red
from .store import EventStore

logger = logging.getLogger("rbcollector.syslog_receiver")

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5140  # host side maps real syslog :514 -> this; see docker-compose.yml

# RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\[.*?\]|-)\s?"
    r"(?P<msg>.*)$"
)
_SD_ROLE_RE = re.compile(r'role="([^"]*)"')
_SD_SRC_RE = re.compile(r'src="([^"]*)"')
_IP_RE = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
_BLUE_ALERT_RE = re.compile(
    r"Failed password|Invalid user|authentication failure|Failed publickey|POSSIBLE BREAK-IN ATTEMPT"
)
_BLUE_ATTACKER_IP_RE = re.compile(r"from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")

# 手動測試用的寬鬆格式：一行 "red: <訊息>" 或 "blue: <訊息>"，不用組出完整的
# Metis RFC5424 structured-data。沒有 role 資訊就不知道該歸哪隊，所以團隊
# 前綴是必要的，不能再省——沒有前綴的純文字沒有安全的預設值可以猜。
_PLAIN_RE = re.compile(r"^(red|blue)\s*[:=]\s*(.+)$", re.IGNORECASE)


def parse_syslog_line(line: str) -> dict[str, str] | None:
    """RFC5424 line -> {timestamp, hostname, appname, role, src, msg}, or None if unparsable."""
    match = _SYSLOG_RE.match(line)
    if not match:
        return None
    sd = match.group("sd")
    role_match = _SD_ROLE_RE.search(sd)
    src_match = _SD_SRC_RE.search(sd)
    return {
        "timestamp": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "appname": match.group("appname"),
        "role": role_match.group(1) if role_match else "",
        "src": src_match.group(1) if src_match else "",
        "msg": match.group("msg"),
    }


def parse_plain_line(line: str) -> tuple[str, str] | None:
    """"red: <msg>" / "blue: <msg>" -> (team, msg), or None if it doesn't match."""
    match = _PLAIN_RE.match(line)
    if not match:
        return None
    return match.group(1).lower(), match.group(2)


def red_payload_from_syslog(parsed: dict[str, str]) -> dict[str, Any]:
    """Mirrors scripts/forward-red-bash-history.sh's payload shape."""
    payload: dict[str, Any] = {
        "observed_at": parsed["timestamp"],
        "command": parsed["msg"],
        "source": parsed["hostname"],
    }
    ip_match = _IP_RE.search(parsed["msg"])
    if ip_match:
        payload["target_ip"] = ip_match.group(1)
    return payload


def blue_payload_from_syslog(parsed: dict[str, str]) -> dict[str, Any]:
    """Mirrors scripts/forward-blue-authlog.sh's payload shape."""
    msg = parsed["msg"]
    event_type = "blue.alert" if _BLUE_ALERT_RE.search(msg) else "blue.log"
    payload: dict[str, Any] = {
        "observed_at": parsed["timestamp"],
        "message": msg,
        "host": parsed["hostname"],
        "event_type": event_type,
    }
    ip_match = _BLUE_ATTACKER_IP_RE.search(msg)
    if ip_match:
        payload["attacker_ip"] = ip_match.group(1)
    return payload


def ingest_syslog_line(store: EventStore, line: str) -> None:
    """Parse one syslog line and, for role=red/blue, normalize + store it.

    Never raises for a single bad line -- a malformed or unexpected line
    (role=host docker-events/audit, a truncated frame, rsyslog's own
    keepalive noise) is logged and skipped so one bad line can't take the
    whole TCP connection down.
    """
    line = line.strip("\r\n")
    if not line:
        return

    # 不管後面解不解析得出來，先把原始內容印出來——讓人可以直接
    # `docker logs -f` 看到「東西真的送到了」，不用等它進資料庫或猜
    # 格式對不對。
    logger.info("received line: %r", line[:500])

    parsed = parse_syslog_line(line)
    if parsed is not None:
        role = parsed["role"]
        if role == "red":
            adapter_normalize, team, payload = red.normalize, "red", red_payload_from_syslog(parsed)
        elif role == "blue":
            adapter_normalize, team, payload = blue.normalize, "blue", blue_payload_from_syslog(parsed)
        else:
            # host (docker-events/audit) or missing role: not a red/blue event.
            logger.debug("skipping non-team syslog line (role=%r, tag=%s)", role, parsed["appname"])
            return
        raw_payload = {"raw_line": line, "hostname": parsed["hostname"], "src": parsed["src"], "tag": parsed["appname"]}
    else:
        # 不是 Metis 的 RFC5424 格式 -- 試試看寬鬆的手動測試格式
        # ("red: ..." / "blue: ...") 再放棄。
        plain = parse_plain_line(line)
        if plain is None:
            logger.warning("unparsable syslog line, skipping: %r", line[:200])
            return
        team, message = plain
        adapter_normalize = red.normalize if team == "red" else blue.normalize
        payload = {"message": message}
        raw_payload = {"raw_line": line, "hostname": None, "src": None, "tag": "manual-plain-text"}

    try:
        event = adapter_normalize(payload)
    except ValueError:
        logger.exception("failed to normalize syslog-derived %s payload: %r", team, payload)
        return

    store.append(team=team, raw_payload=raw_payload, event=event)


async def _handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, store: EventStore) -> None:
    peer = writer.get_extra_info("peername")
    logger.info("syslog connection opened: %s", peer)
    try:
        while True:
            raw = await reader.readline()
            if not raw:  # EOF
                break
            try:
                line = raw.decode("utf-8", errors="replace")
            except Exception:
                logger.exception("failed to decode syslog line from %s", peer)
                continue
            try:
                ingest_syslog_line(store, line)
            except Exception:
                # A single bad line (or a transient DB hiccup) must not kill the
                # connection -- rsyslog's disk queue will keep retrying delivery
                # otherwise, and one poison line would then wedge the whole feed.
                logger.exception("error ingesting syslog line from %s: %r", peer, line[:200])
    finally:
        logger.info("syslog connection closed: %s", peer)
        writer.close()


async def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, store: EventStore | None = None) -> None:
    store = store or EventStore.from_env()
    store.ensure_schema()
    server = await asyncio.start_server(
        lambda r, w: _handle_connection(r, w, store), host=host, port=port
    )
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logger.info("syslog receiver listening on %s", addrs)
    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    host = os.environ.get("SYSLOG_HOST", DEFAULT_HOST)
    port = int(os.environ.get("SYSLOG_PORT", str(DEFAULT_PORT)))
    asyncio.run(serve(host=host, port=port))


if __name__ == "__main__":
    main()
