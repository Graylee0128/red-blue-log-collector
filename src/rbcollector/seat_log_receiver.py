"""File-based log receiver that tails /var/log/metis/seat/*.cmd files.

Instead of relying on rsyslog's TCP syslog (which has permission/role/buffering
issues per issue #16), this module directly monitors the Metis seat log files.

File naming convention automatically determines the team:
  - red-*.cmd → red team
  - blue-a-*.cmd, blue-b-*.cmd → blue team

This bypasses rsyslog's role-tagging issues and operates at the source filesystem
level where team ownership is unambiguous.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from .adapters import blue, red
from .store import EventStore

logger = logging.getLogger("rbcollector.seat_log_receiver")

DEFAULT_SEAT_LOG_DIR = "/var/log/metis/seat"
DEFAULT_POLL_INTERVAL = 1.0  # seconds


def get_team_from_filename(filename: str) -> str | None:
    """Extract team from Metis seat log filename.

    Returns:
        "red" if filename matches red-*.cmd
        "blue" if filename matches blue-{a,b}-*.cmd
        None otherwise
    """
    basename = Path(filename).name
    if re.match(r"^red-.*\.cmd$", basename):
        return "red"
    if re.match(r"^blue-[ab]-.*\.cmd$", basename):
        return "blue"
    return None


def parse_command_line(line: str) -> dict[str, Any] | None:
    """Parse a single command line from a seat log file.

    Seat log format: each line is a command executed, with optional timestamp
    and other metadata. At minimum, extract the command itself.

    Expected format (loose, from issue context):
      [timestamp] command [args...]

    For now, treat the entire non-empty line as the command and extract
    timestamp if available. Timestamp parsing is lenient.
    """
    line = line.strip()
    if not line:
        return None

    # Try to extract ISO timestamp at the beginning
    # Pattern: 2026-08-19T11:00:00+08:00 or similar
    # 時區/毫秒尾段用 [^\s']* 卡在遇到空白就停，不能用 [^']*——貪婪比對搭配
    # 後面的 \s+ 會反過來從指令內容最後一個空白切開，把指令前幾個字吃進
    # timestamp 群組（指令是多個字詞時就會踩到，e.g. "nmap -sV 10.0.0.20"）。
    ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s']*)\s+(.+)$", line)

    if ts_match:
        timestamp_str, command = ts_match.groups()
        return {
            "timestamp": timestamp_str,
            "command": command,
        }

    # Fallback: no timestamp, entire line is the command
    return {
        "timestamp": None,
        "command": line,
    }


def red_payload_from_seat_log(parsed: dict[str, Any], filename: str) -> dict[str, Any]:
    """Build red team ingest payload from seat log entry."""
    payload: dict[str, Any] = {
        "command": parsed["command"],
        "source": Path(filename).stem,  # e.g., "red-seat-1" from red-seat-1.cmd
    }
    if parsed.get("timestamp"):
        payload["observed_at"] = parsed["timestamp"]

    # Extract target IP if present in command
    ip_match = re.search(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", parsed["command"])
    if ip_match:
        payload["target_ip"] = ip_match.group(1)

    return payload


def blue_payload_from_seat_log(parsed: dict[str, Any], filename: str) -> dict[str, Any]:
    """Build blue team ingest payload from seat log entry."""
    payload: dict[str, Any] = {
        "message": parsed["command"],
        # "source"，不是 "host"：這裡代表「哪個席位打的指令」，跟
        # red_payload_from_seat_log 的 source 語意一致（誰做的）。BlueAdapter
        # 的 source 候選欄位是 source/producer/sensor，沒有 host——原本用
        # "host" 會被 BlueAdapter 的 destination 候選欄位撿走，變成「目標是
        # 誰」，跟語意剛好相反，畫面上也因此看不到實際席位名稱。
        "source": Path(filename).stem,  # e.g., "blue-a-monitor" from blue-a-monitor.cmd
    }
    if parsed.get("timestamp"):
        payload["observed_at"] = parsed["timestamp"]

    return payload


def is_noise(command: str) -> bool:
    """判斷一行指令是否明顯是雜訊（純數字、重複字元等打字測試）。

    Returns:
        True if the line is obvious noise, False if it looks like a real command
    """
    if not command:
        return True

    # 純數字
    if command.isdigit():
        return True

    # 單一字元重複（如 "aaaa"、"1111"）— 留意 len >= 3 才當雜訊
    # 兩個字元可能是縮寫（"ls"、"cd"），不過濾
    if len(command) >= 3 and len(set(command)) == 1:
        return True

    # 單一字元重複的變種，留個空白（退格測試："a a a"）
    if len(set(c for c in command if c != ' ')) == 1 and command.count(' ') >= 2:
        return True

    return False


def ingest_seat_log_line(store: EventStore, team: str, filename: str, line: str) -> None:
    """Parse one seat log line and normalize + store it.

    Like syslog_receiver.ingest_syslog_line, a single bad line is logged and
    skipped rather than raising, to keep file monitoring resilient.
    """
    parsed = parse_command_line(line)
    if parsed is None:
        return

    # 不在 ingest 層過濾——原始日誌完整存入 normalized_events，明顯雜訊的
    # 過濾工作交給顯示層（前端 buildChain 根據 status 決定顯示）。這樣保留
    # 完整資料以供稽核，也避免把「沒命中規則但確實被偵測到」的真實案例
    # 誤隱（issue #20 審查意見）。

    if team == "red":
        adapter_normalize = red.normalize
        payload = red_payload_from_seat_log(parsed, filename)
    elif team == "blue":
        adapter_normalize = blue.normalize
        payload = blue_payload_from_seat_log(parsed, filename)
    else:
        logger.warning("unexpected team %r for file %s", team, filename)
        return

    try:
        event = adapter_normalize(payload)
    except ValueError:
        logger.exception("failed to normalize seat-log-derived %s payload: %r", team, payload)
        return

    raw_payload = {
        "raw_line": line,
        "filename": filename,
        "team": team,
    }
    store.append(team=team, raw_payload=raw_payload, event=event)


class SeatLogTailer:
    """Monitors a set of .cmd files in /var/log/metis/seat and tails new lines."""

    def __init__(self, seat_log_dir: str, store: EventStore, poll_interval: float = DEFAULT_POLL_INTERVAL):
        self.seat_log_dir = Path(seat_log_dir)
        self.store = store
        self.poll_interval = poll_interval
        # Track file position (inode, size) to detect rotations
        self.file_state: dict[Path, tuple[int, int]] = {}  # path -> (inode, size)
        # Track open file handles for efficient tailing
        self.open_handles: dict[Path, tuple[int, Any]] = {}  # path -> (last_pos, file_handle)

    def _get_seat_log_files(self) -> list[Path]:
        """List all .cmd files in the seat log directory."""
        if not self.seat_log_dir.exists():
            logger.warning("seat log directory does not exist: %s", self.seat_log_dir)
            return []

        try:
            return sorted([f for f in self.seat_log_dir.glob("*.cmd")])
        except OSError as e:
            logger.exception("error listing seat log directory: %s", e)
            return []

    def _tail_file(self, filepath: Path) -> None:
        """Tail new lines from a file, starting from last known position."""
        team = get_team_from_filename(filepath.name)
        if team is None:
            logger.debug("skipping file with unknown team naming: %s", filepath.name)
            return

        # 記「這個紅隊席位真的存在」——只看檔名/檔案存不存在，不看有沒有
        # 新內容可以 tail，這樣才能算出真實紅隊席位數（見 issue #21 後續
        # 討論，攻擊拓樸面板的左側來源格改成不再跟藍隊格數綁死）。跟藍隊
        # 那邊的 blue_seats（blue_score_receiver.py）是對稱設計，只是紅隊
        # 這邊本來就在 tail *.cmd，順手記，不用另開一支輪詢程式。
        if team == "red":
            try:
                self.store.record_known_red_seat(seat=filepath.stem)
            except Exception:
                logger.exception("failed to record known red seat %s", filepath.stem)

        try:
            # Check if file has been rotated
            stat = filepath.stat()
            inode = stat.st_ino
            size = stat.st_size

            last_inode, last_size = self.file_state.get(filepath, (0, 0))
            if last_inode != 0 and last_inode != inode:
                # File was rotated, reset position
                logger.info("detected file rotation for %s", filepath.name)
                if filepath in self.open_handles:
                    _, handle = self.open_handles.pop(filepath)
                    handle.close()
                self.file_state[filepath] = (inode, 0)
                last_pos = 0
            elif last_size > size:
                # File was truncated
                logger.info("detected file truncation for %s", filepath.name)
                if filepath in self.open_handles:
                    _, handle = self.open_handles.pop(filepath)
                    handle.close()
                self.file_state[filepath] = (inode, 0)
                last_pos = 0
            else:
                last_pos = self.open_handles.get(filepath, (0, None))[0] if filepath in self.open_handles else 0

            # Open and read new lines
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    try:
                        ingest_seat_log_line(self.store, team, filepath.name, line)
                    except Exception:
                        logger.exception("error ingesting seat log line from %s: %r", filepath.name, line[:200])

                # Update state
                pos = f.tell()
                self.file_state[filepath] = (inode, size)
                self.open_handles[filepath] = (pos, None)

        except FileNotFoundError:
            # File was deleted between listing and reading
            logger.debug("file disappeared: %s", filepath.name)
            self.file_state.pop(filepath, None)
            self.open_handles.pop(filepath, None)
        except PermissionError:
            logger.error("permission denied reading %s (need adm group or equivalent)", filepath.name)
        except OSError:
            logger.exception("error tailing file %s", filepath.name)

    async def run(self) -> None:
        """Main loop: periodically scan for new files and tail them."""
        logger.info("seat log tailer started, monitoring %s", self.seat_log_dir)

        while True:
            try:
                files = self._get_seat_log_files()
                for filepath in files:
                    self._tail_file(filepath)

                # Clean up state for files that no longer exist
                for tracked_path in list(self.file_state.keys()):
                    if tracked_path not in files:
                        logger.debug("forgetting deleted file: %s", tracked_path.name)
                        self.file_state.pop(tracked_path, None)
                        if tracked_path in self.open_handles:
                            _, handle = self.open_handles.pop(tracked_path)
                            if handle:
                                handle.close()

                await asyncio.sleep(self.poll_interval)
            except KeyboardInterrupt:
                raise
            except Exception:
                logger.exception("error in seat log tailer loop, continuing")
                await asyncio.sleep(self.poll_interval)


async def serve(
    seat_log_dir: str = DEFAULT_SEAT_LOG_DIR,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    store: EventStore | None = None,
) -> None:
    """Start the seat log receiver."""
    store = store or EventStore.from_env()
    store.ensure_schema()

    tailer = SeatLogTailer(seat_log_dir, store, poll_interval)
    await tailer.run()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    seat_log_dir = os.environ.get("SEAT_LOG_DIR", DEFAULT_SEAT_LOG_DIR)
    poll_interval = float(os.environ.get("SEAT_LOG_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL)))
    asyncio.run(serve(seat_log_dir=seat_log_dir, poll_interval=poll_interval))


if __name__ == "__main__":
    main()
