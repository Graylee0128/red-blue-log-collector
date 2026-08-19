"""Heuristic "possible breach" detector for the attack-topology panel
(issue #21).

Tails red-*.out -- the *raw terminal output* Metis's `script` wrapper
records (not the .cmd command log seat_log_receiver.py reads) -- looking for
one specific, real, observable signal: the terminal window-title escape
sequence a Debian/Kali-family default bashrc emits on every prompt draw
(`ESC ] 0 ; user@host: cwd BEL`). If that title's host suddenly differs from
the seat's own baseline hostname *within the same ttyd session* (not across
a reconnect/session restart, which also changes the container's own random
hex hostname whenever Metis recreates the seat container), that's a real
signal an interactive shell showed up on a different machine -- i.e. a
plausible pivot.

THIS IS A HEURISTIC, NOT AN AUTHORITATIVE "attack succeeded" JUDGMENT (see
issue #21's discussion of why action_result can't be used for this):
  - requires the target machine's own shell to emit the same OSC title
    convention -- common on Debian-family defaults, not guaranteed for
    every possible target image
  - a red teamer who edits PS1/unsets PROMPT_COMMAND defeats it silently
  - it says "an interactive shell appeared on a different host", not
    "the red team achieved their objective" -- those aren't the same claim

Consumers (the Purple Console attack-topology panel) must present this as
suspected/unconfirmed, never mixed into the confirmed hit/gap correlation
data that drives detection_rate/MTTD.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path

from .store import EventStore

logger = logging.getLogger("rbcollector.breach_detector")

DEFAULT_SEAT_LOG_DIR = "/var/log/metis/seat"
DEFAULT_POLL_INTERVAL = 10.0  # seconds

# 每次 ttyd 連線／重連，.out 都會留一行這種標頭。COMMAND 裡的容器名稱是
# 「這個席位自己的身份」（例如 red-01），不是入侵目標——這個席位的容器
# 被 Metis 重建時，它自己的內部 hostname（見下面 _OSC_TITLE_RE）會換成
# 新的隨機值，那不是 pivot，只是同一個席位換了個容器，所以每次看到這行
# 都要重設「目前 session 的基準 host」。
_SESSION_RE = re.compile(r'Script started on .*?\[COMMAND="docker exec -it (\S+) bash"')

# xterm/Debian 系預設 bashrc 常見的「設終端機視窗標題」跳脫序列：
# ESC ] 0 ; user@host: cwd BEL。每畫一次新 prompt 就會重發一次，內容包含
# 「目前是在哪台機器的 shell 裡」——比硬解析花俏的 Kali box-drawing prompt
# 更穩定（不受顏色碼、多位元組 UTF-8 邊框字元干擾）。
_OSC_TITLE_RE = re.compile(r"\x1b\]0;[^@\x07]*@([^:\x07]+):")


def find_pivot_targets(content: str) -> list[str]:
    """掃過整份 .out 內容，回傳「跟該次 session 第一次看到的 host 不同」的
    所有相異 host，依第一次出現的順序。session 邊界見 _SESSION_RE。"""
    events: list[tuple[int, str, str]] = []
    for m in _SESSION_RE.finditer(content):
        events.append((m.start(), "session", m.group(1)))
    for m in _OSC_TITLE_RE.finditer(content):
        events.append((m.start(), "host", m.group(1)))
    events.sort(key=lambda e: e[0])

    baseline: str | None = None
    pivots: list[str] = []
    seen: set[str] = set()
    for _, kind, value in events:
        if kind == "session":
            baseline = None
            continue
        if baseline is None:
            baseline = value
            continue
        if value != baseline and value not in seen:
            seen.add(value)
            pivots.append(value)
    return pivots


def ingest_out_file(store: EventStore, seat: str, content: str) -> None:
    """對一份 .out 內容跑 pivot 偵測，把新發現的目標寫進去。store 端
    ON CONFLICT DO NOTHING，同一個 (seat, target_host) 重複呼叫是安全的。"""
    for target_host in find_pivot_targets(content):
        try:
            store.record_possible_breach(seat=seat, target_host=target_host)
        except Exception:
            logger.exception("failed to record possible breach: seat=%s target=%s", seat, target_host)


class BreachDetector:
    """輪詢 red-*.out，每次整份重讀——pivot 判斷需要看整份 session 邊界的
    順序脈絡，跟 seat_log_receiver 的逐行增量 tail 是不同的模式。檔案通常
    幾十 KB，重讀成本可以接受；長到有效能問題時再改增量。"""

    def __init__(self, seat_log_dir: str, store: EventStore, poll_interval: float = DEFAULT_POLL_INTERVAL):
        self.seat_log_dir = Path(seat_log_dir)
        self.store = store
        self.poll_interval = poll_interval

    def _poll_once(self) -> None:
        if not self.seat_log_dir.exists():
            logger.warning("seat log directory does not exist: %s", self.seat_log_dir)
            return

        for path in sorted(self.seat_log_dir.glob("red-*.out")):
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.exception("failed to read %s", path.name)
                continue
            ingest_out_file(self.store, path.stem, content)

    async def run(self) -> None:
        logger.info("breach detector started, monitoring %s", self.seat_log_dir)
        while True:
            try:
                self._poll_once()
            except Exception:
                logger.exception("error in breach detector loop, continuing")
            await asyncio.sleep(self.poll_interval)


async def serve(
    seat_log_dir: str = DEFAULT_SEAT_LOG_DIR,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    store: EventStore | None = None,
) -> None:
    store = store or EventStore.from_env()
    store.ensure_schema()
    await BreachDetector(seat_log_dir, store, poll_interval).run()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    seat_log_dir = os.environ.get("SEAT_LOG_DIR", DEFAULT_SEAT_LOG_DIR)
    poll_interval = float(os.environ.get("BREACH_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL)))
    asyncio.run(serve(seat_log_dir=seat_log_dir, poll_interval=poll_interval))


if __name__ == "__main__":
    main()
