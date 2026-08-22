"""Correlates cmdlog commands with their exit codes (issue #41).

`action_result` has been wired end-to-end since the beginning (models.py／
store.py／adapters/*.py) but was always "unknown" -- cmdlog never carried a
command's execution result. Metis's se-218/Metis#143 (`deploy/seat-exit-rc.sh`)
now prints a marker line `[[METIS_EXIT:<code>]]` into `<seat>.out` every time
bash redraws its prompt (via a PROMPT_COMMAND hook injected at `docker exec`
time, not baked into the seat image -- see that file's own comments for the
Kali PROMPT_COMMAND-self-overwrite workaround).

The marker lands in `.out` (the raw terminal screen), *not* `.cmd` (the
command text seat_log_receiver.py already ingests) -- cmdlog.sh itself is
unchanged. Correlating the two requires real timestamps for both sides:

  - `.cmd` entries already have one (cmdlog.sh's own `[timestamp] command`
    format, parsed by seat_log_receiver.parse_command_line()).
  - `.out` bytes don't carry timestamps by themselves -- `script --log-timing`
    writes a companion `<seat>.timing` file (delay-since-last-write, byte-count
    pairs) instead. Reconstructing a wall-clock time for a given byte offset
    means summing timing deltas up to that offset and adding it to the
    session's start time (parsed from `.out`'s own "Script started on ..."
    header line -- see breach_detector.py's _SESSION_RE for the sibling
    pattern that already parses that same line for a different purpose).

Ordinal matching ("the Nth exit marker belongs to the Nth command") would be
wrong: bash's PROMPT_COMMAND fires on *every* prompt redraw, including a bare
Enter on an empty line -- that produces an extra marker (carrying whatever
$? already was) with no corresponding .cmd entry, which would silently shift
every later pairing by one. Time-window matching sidesteps this: for each
command, take the *first* marker that lands strictly after it and before the
next command (or +30s for the last command in the file) -- extra "empty
Enter" markers just end up ignored because they land after that first real
one, inside the same window.

KNOWN LIMITATION -- untested against a real Metis "Script started on ..."
header format: `script`'s exact date format is locale/build-dependent and
this module hasn't been run against a live seat yet. `_parse_session_timestamp()`
tries a short list of formats and returns None (skip this seat's file this
poll, log a warning, never raise) rather than guess wrong -- same "don't
assert what hasn't been verified against real data" rule breach_detector.py's
own header-parsing regex was built under (see that module's docstring).

Also unverified: `--append` reconnects mean `.out`/`.timing` can contain
multiple sessions back to back, each restarting its own local clock (a new
`script` invocation, own "Script started on ..." line, own timing delays
counted from 0). find_last_session() only processes the most recent one --
correct in spirit (older sessions' correlation windows have long since
closed), but the exact re-invocation semantics of `--log-timing` across
`--append` haven't been confirmed against a real reconnect yet either.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .seat_log_receiver import get_team_from_filename
from .store import EventStore

logger = logging.getLogger("rbcollector.exit_code_receiver")

DEFAULT_SEAT_LOG_DIR = "/var/log/metis/seat"
DEFAULT_POLL_INTERVAL = 5.0  # seconds

# 跟 breach_detector.py 的 _SESSION_RE 認同一行,但這裡要的是日期本身,
# 不是容器名稱。script 的日期格式在不同版本/locale 下不保證一致,列出
# 幾種常見格式輪流試,都失敗就放棄(見模組開頭「已知限制」)。
_SESSION_START_RE = re.compile(rb"Script started on (.+?)\s*\[COMMAND=")
_SESSION_START_FORMATS = (
    "%Y-%m-%d %H:%M:%S%z",
    "%a %d %b %Y %I:%M:%S %p %Z",
    "%a %b %d %H:%M:%S %Y",
)

_EXIT_MARKER_RE = re.compile(rb"\[\[METIS_EXIT:(-?\d+)\]\]")

# 事後應對比對窗口跟 analysis.py 的 _RESPONSE_WINDOW_SECONDS 是不同的
# 用途,這裡是「最後一句指令之後,願意等多久去抓它的離開碼標記」的上限,
# 太久沒出現就當作抓不到,不是判定藍隊有沒有回應。
_LAST_COMMAND_WINDOW_SECONDS = 30


def _parse_session_timestamp(raw: bytes) -> datetime | None:
    text = raw.decode("utf-8", errors="replace").strip()
    for fmt in _SESSION_START_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    logger.warning("could not parse session start timestamp: %r", text)
    return None


def find_last_session(out_bytes: bytes) -> tuple[int, datetime] | None:
    """`--append`（見 seat-shell.sh）代表重連會把新一輪 `Script started on
    ...` 疊在舊內容後面，`.timing` 的秒數/位元組數也是每次重連各自從 0
    重新累計——不是整份檔案共用同一份連續時間軸。只處理**最後一個**
    session：往回配對舊 session 的標記，早在那次重連發生時視窗就已經
    關閉，補救也沒有意義；只有「目前這一輪」的指令還可能等著配對離開碼。

    回傳 (該 session 在 .out 裡的起始位元組偏移, session 開始時間)，
    找不到／解析不出時間就回傳 None（見模組開頭「已知限制」，不猜格式）。"""
    last: tuple[int, datetime] | None = None
    for match in _SESSION_START_RE.finditer(out_bytes):
        ts = _parse_session_timestamp(match.group(1))
        if ts is not None:
            last = (match.start(), ts)
    return last


def slice_timing_from_offset(timing_pairs: list[tuple[float, int]], offset: int) -> list[tuple[float, int]]:
    """回傳從「累積位元組數超過 offset」那個區塊開始的 timing 清單，
    給 find_last_session() 抓到的重連邊界用——這個區塊本身橫跨邊界前後
    兩段時間，第一筆的秒數會混進一點邊界之前的等待時間，這是跟其他地方
    一致的「以區塊為單位」精度取捨，不是遺漏。"""
    cumulative = 0
    for i, (_, nbytes) in enumerate(timing_pairs):
        cumulative += nbytes
        if cumulative > offset:
            return timing_pairs[i:]
    return []


def parse_timing_file(path: Path) -> list[tuple[float, int]]:
    """`<seat>.timing` 的每一行是「距上次寫入的延遲秒數 位元組數」。壞行
    （非兩欄、非數字）直接跳過,不讓一行壞資料拖垮整份檔案的重建。"""
    pairs: list[tuple[float, int]] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return pairs
    for line in content.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pairs.append((float(parts[0]), int(parts[1])))
        except ValueError:
            continue
    return pairs


def find_exit_markers(
    out_bytes: bytes, timing_pairs: list[tuple[float, int]], session_start: datetime
) -> list[tuple[datetime, int]]:
    """回傳 (時間, exit code) 清單,依 .out 裡出現的先後順序(即時間順序)。

    .timing 每一筆代表「這批位元組是在累積到目前這個時間點時寫入的」,
    不是逐位元組給時間戳——同一批 timing 區間內的所有位元組都當同一個
    時間點處理,精細度就到這裡,不需要更細(marker 本身只有幾十個位元組,
    不會橫跨太多個 timing 區間造成誤差累積)。
    """
    # 累積時間到累積位元組數的區間表:cumulative_bytes[i] 之前寫完的內容,
    # 對應時間是 cumulative_seconds[i]。
    boundaries: list[tuple[int, float]] = []  # (累積位元組數上限, 累積秒數)
    total_bytes = 0
    total_seconds = 0.0
    for delay, nbytes in timing_pairs:
        total_seconds += delay
        total_bytes += nbytes
        boundaries.append((total_bytes, total_seconds))

    def _time_at_offset(offset: int) -> datetime:
        for byte_limit, elapsed in boundaries:
            if offset < byte_limit:
                return session_start + timedelta(seconds=elapsed)
        # 超過 .timing 涵蓋範圍(理論上不該發生,.out/.timing 應該同步寫入)
        # ——退回最後一個已知時間點,好過整批標記直接漏掉。
        return session_start + timedelta(seconds=total_seconds)

    markers: list[tuple[datetime, int]] = []
    for match in _EXIT_MARKER_RE.finditer(out_bytes):
        ts = _time_at_offset(match.start())
        markers.append((ts, int(match.group(1))))
    return markers


def correlate_exit_codes(
    commands: list[tuple[str, datetime]], markers: list[tuple[datetime, int]]
) -> dict[str, str]:
    """`commands` 是 (event_id, observed_at) 依時間排序的清單,`markers` 是
    find_exit_markers() 回傳的 (時間, exit code) 依時間排序的清單。

    每句指令取「這句指令之後、下一句指令之前(最後一句用 +30 秒代替)」
    這個時間窗裡**第一個**出現的標記——不是硬性一對一,窗口裡如果有額外
    的標記(例如空白 Enter 產生的),第一個之後的都被忽略,不會往後拖累
    下一句指令的配對(見模組開頭文件說明為什麼不能用順序配對)。"""
    result: dict[str, str] = {}
    for i, (event_id, cmd_time) in enumerate(commands):
        window_end = (
            commands[i + 1][1] if i + 1 < len(commands)
            else cmd_time + timedelta(seconds=_LAST_COMMAND_WINDOW_SECONDS)
        )
        for marker_time, exit_code in markers:
            if cmd_time <= marker_time < window_end:
                result[event_id] = str(exit_code)
                break
    return result


class ExitCodeCorrelator:
    """輪詢 <seat>.out + <seat>.timing,把還原出來的離開碼寫回對應的
    cmdlog 事件。跟 breach_detector.py 一樣整份重讀(檔案通常不大,pivot
    偵測那邊的效能考量在這裡同樣適用),不是逐行增量 tail。"""

    def __init__(self, seat_log_dir: str, store: EventStore, poll_interval: float = DEFAULT_POLL_INTERVAL):
        self.seat_log_dir = Path(seat_log_dir)
        self.store = store
        self.poll_interval = poll_interval

    def _poll_once(self) -> None:
        if not self.seat_log_dir.exists():
            logger.warning("seat log directory does not exist: %s", self.seat_log_dir)
            return

        for out_path in sorted(self.seat_log_dir.glob("*.out")):
            # get_team_from_filename() 認的是 .cmd 檔名——只是規則跟副檔名
            # 無關(純看 red-*/blue-{a,b}- 前綴),換個副檔名去問一樣準,
            # 不用為了 .out 另外重寫一份一模一樣的規則。
            team = get_team_from_filename(out_path.with_suffix(".cmd").name)
            if team is None:
                continue
            self._process_seat(out_path, team)

    def _process_seat(self, out_path: Path, team: str) -> None:
        timing_path = out_path.with_suffix(".timing")
        try:
            out_bytes = out_path.read_bytes()
        except OSError:
            logger.exception("failed to read %s", out_path.name)
            return

        session = find_last_session(out_bytes)
        if session is None:
            logger.debug("no parseable session start in %s, skipping this poll", out_path.name)
            return
        session_offset, session_start = session

        timing_pairs = parse_timing_file(timing_path)
        if not timing_pairs:
            return

        # 只看最後一次重連之後的內容/時間——見 find_last_session() 的說明。
        markers = find_exit_markers(
            out_bytes[session_offset:],
            slice_timing_from_offset(timing_pairs, session_offset),
            session_start,
        )
        if not markers:
            return

        seat = out_path.stem
        try:
            events: list[dict[str, Any]] = self.store.list_events(team=team, limit=5000)
        except Exception:
            logger.exception("failed to list events for exit-code correlation: seat=%s", seat)
            return

        # 只挑這個席位、還沒解過離開碼的 cmdlog 事件——source 是
        # seat_log_receiver.py 寫入時設的席位名稱(見該檔案的
        # red_payload_from_seat_log()/blue_payload_from_seat_log())。
        pending = [
            e for e in events
            if e.get("source") == seat and (e.get("action_result") or "unknown") == "unknown"
        ]
        if not pending:
            return

        commands: list[tuple[str, datetime]] = []
        for e in pending:
            try:
                observed_at = datetime.fromisoformat(str(e["observed_at"]).replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            commands.append((e["event_id"], observed_at))
        commands.sort(key=lambda pair: pair[1])

        resolved = correlate_exit_codes(commands, markers)
        for event_id, action_result in resolved.items():
            try:
                self.store.update_action_result(event_id, action_result)
            except Exception:
                logger.exception("failed to update action_result: event_id=%s", event_id)

    async def run(self) -> None:
        logger.info("exit code correlator started, monitoring %s", self.seat_log_dir)
        while True:
            try:
                self._poll_once()
            except Exception:
                logger.exception("error in exit code correlator loop, continuing")
            await asyncio.sleep(self.poll_interval)


async def serve(
    seat_log_dir: str = DEFAULT_SEAT_LOG_DIR,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    store: EventStore | None = None,
) -> None:
    store = store or EventStore.from_env()
    store.ensure_schema()
    await ExitCodeCorrelator(seat_log_dir, store, poll_interval).run()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    seat_log_dir = os.environ.get("SEAT_LOG_DIR", DEFAULT_SEAT_LOG_DIR)
    poll_interval = float(os.environ.get("EXIT_CODE_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL)))
    asyncio.run(serve(seat_log_dir=seat_log_dir, poll_interval=poll_interval))


if __name__ == "__main__":
    main()
