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

# issue #41 在真實 VM 上驗證時撞到的真的 bug：cmdlog.sh 記錄指令時間、跟
# .out/.timing 重建出來的標記時間,是兩個獨立的時鐘來源——"Script started
# on ..." 這行本身只精確到整秒(沒有次秒位數),重建時間一律當成該整秒的
# 0 毫秒起算,但 script 真正開始的時間點其實落在那一整秒內的任何時刻,
# 加上 cmdlog.sh 自己寫入 .cmd 那行也有自己的緩衝延遲——兩邊加總起來,
# 實測抓到同一句指令的標記時間比 cmd_time 早了 0.8~3.6 秒都有。嚴格要求
# marker_time >= cmd_time 會把這種(完全正常的)情況整筆排除,永遠配不到。
# 往前留一點寬限,讓「稍微早於指令時間」的標記還是能配對回這句指令。
_CLOCK_SKEW_GRACE_SECONDS = 4.0


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


def parse_timing_file(path: Path) -> list[tuple[float, int, bool]]:
    """`<seat>.timing` 實測（issue #41 在真實 VM 上驗證時發現）是 util-linux
    ≥2.35 的多串流「進階」計時格式，不是傳統單純兩欄「延遲 位元組」——
    `seat-shell.sh` 同時用 `--log-in`／`--log-out`／`--log-timing`，這種
    組合會讓 `script` 改寫成三欄、開頭一個字母標串流：

      H <秒數> <欄位...>  —— header/metadata（START_TIME、COMMAND 等），
                             不是真的寫入事件，但秒數一樣要算進經過時間。
      O <秒數> <位元組數> —— `.out`（畫面輸出）的一筆寫入，這是要重建
                             時間軸用的那一半。
      I <秒數> <位元組數> —— `.in`（使用者輸入）的一筆寫入。

    **關鍵：秒數是「距離上一筆事件（不分 H/I/O 串流）的延遲」，是共用同
    一條時間軸，不是各自獨立計時**——H/I 那些行的秒數如果整批跳過不算，
    會把使用者發呆／打字的真正間隔（通常記在 I 行上）漏算掉，讓還原出來
    的時間軸被壓縮到不合理的短。所以這裡回傳完整三欄
    `(delay, byte_count, is_output)`，`is_output` 只用來決定要不要把
    這筆的位元組數算進 `.out` 的累積位移，delay 每一筆都要算。

    同時保留舊版單純兩欄格式的相容判斷（沒有字母前綴、剛好兩個欄位，
    視為單一串流、全部當 output）。壞行（欄位數不對、非數字）直接跳過，
    不讓一行壞資料拖垮整份檔案的重建。
    """
    entries: list[tuple[float, int, bool]] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return entries
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("H", "I", "O", "S"):
            # H 行後面接的是 metadata（如 "START_TIME 2026-... ..."），
            # 欄位數不固定——不能要求剛好三欄，只認第一、二欄（型別、
            # 延遲），第三欄嘗試當位元組數解析，解不出來就是 0（H 行
            # 本來就不貢獻 .out 位移，這個數字不會被用到）。
            delay_str = parts[1]
            is_output = parts[0] == "O"
            try:
                nbytes = int(parts[2]) if len(parts) >= 3 else 0
            except ValueError:
                nbytes = 0
        elif len(parts) == 2:
            delay_str, nbytes_str = parts
            is_output = True
            try:
                nbytes = int(nbytes_str)
            except ValueError:
                continue
        else:
            continue
        try:
            entries.append((float(delay_str), nbytes, is_output))
        except ValueError:
            continue
    return entries


def find_exit_markers(
    out_bytes: bytes, timing_entries: list[tuple[float, int, bool]], session_start: datetime
) -> list[tuple[datetime, int]]:
    """回傳 (時間, exit code) 清單,依 .out 裡出現的先後順序(即時間順序)。

    `timing_entries` 是 parse_timing_file() 回傳的完整三欄清單，要照原始
    檔案順序處理——每一筆的 delay 都要累加進經過時間（不分是不是
    output），只有 is_output 那些才把位元組數累加進 `.out` 的位移量。
    這樣才能正確算出「.out 累積到第 N 個位元組時，經過了多少秒」，不會
    因為漏算 I／H 行的延遲而把整段時間軸壓縮成不合理的短。

    同一批 output 區間內的所有位元組都當同一個時間點處理，精細度就到
    這裡，不需要更細（marker 本身只有幾十個位元組，不會橫跨太多個
    timing 區間造成誤差累積）。
    """
    boundaries: list[tuple[int, float]] = []  # (累積 output 位元組數上限, 累積秒數)
    cumulative_out_bytes = 0
    elapsed_seconds = 0.0
    for delay, nbytes, is_output in timing_entries:
        elapsed_seconds += delay
        if is_output:
            cumulative_out_bytes += nbytes
            boundaries.append((cumulative_out_bytes, elapsed_seconds))

    def _time_at_offset(offset: int) -> datetime:
        for byte_limit, elapsed in boundaries:
            if offset < byte_limit:
                return session_start + timedelta(seconds=elapsed)
        # 超過 .timing 涵蓋範圍(理論上不該發生,.out/.timing 應該同步寫入)
        # ——退回最後一個已知時間點,好過整批標記直接漏掉。
        return session_start + timedelta(seconds=elapsed_seconds)

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

    每句指令取「這句指令之前留一點時鐘偏差寬限、之後、下一句指令之前
    (最後一句用 +30 秒代替)」這個時間窗裡**第一個**出現的標記——不是
    硬性一對一,窗口裡如果有額外的標記(例如空白 Enter 產生的),第一個
    之後的都被忽略,不會往後拖累下一句指令的配對(見模組開頭文件說明
    為什麼不能用順序配對)。

    往前留的寬限(_CLOCK_SKEW_GRACE_SECONDS)會讓相鄰兩句指令的窗口出現
    一小段重疊——用 `consumed` 記錄已經配走的標記索引,確保同一個標記
    不會同時配給前後兩句指令(不然會出現同一個離開碼被重複寫進兩筆事件
    的情況)。"""
    result: dict[str, str] = {}
    consumed: set[int] = set()
    for i, (event_id, cmd_time) in enumerate(commands):
        window_start = cmd_time - timedelta(seconds=_CLOCK_SKEW_GRACE_SECONDS)
        window_end = (
            commands[i + 1][1] if i + 1 < len(commands)
            else cmd_time + timedelta(seconds=_LAST_COMMAND_WINDOW_SECONDS)
        )
        for idx, (marker_time, exit_code) in enumerate(markers):
            if idx in consumed:
                continue
            if window_start <= marker_time < window_end:
                result[event_id] = str(exit_code)
                consumed.add(idx)
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

        timing_entries = parse_timing_file(timing_path)
        if not timing_entries:
            return

        # 只看最後一次重連之後的內容/時間——見 find_last_session() 的說明。
        #
        # 實測發現（issue #41 在真實 VM 上驗證時）：.timing 不像 .out／.in
        # 那樣跨重連累積——每次 metis-ttyd@ 服務重啟等於全新的 script
        # 行程，.timing 只描述「這一次」自己的位元組流，座標本來就是從 0
        # 算起，不是整份 .out 檔案的絕對位移，所以不用（也不能）拿
        # session 在 .out 裡的絕對偏移去切 .timing——直接整份跟切過的
        # `out_bytes[session_offset:]` 對齊即可。
        markers = find_exit_markers(out_bytes[session_offset:], timing_entries, session_start)
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
