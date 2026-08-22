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

external vs internal layer: Metis declined to provide a container id->name
mapping (see issue #21 discussion), so we can't resolve *which* machine was
hit -- but we don't need names for external/internal. compose.seat.yml's own
topology guarantees red only has a route to blue-a (DMZ); reaching blue-b
(internal) requires already being on blue-a first. So "hop count away from
the seat's own baseline" (see find_pivot_targets()) doubles as the layer
signal for free: hop=1 is necessarily the DMZ hop, hop>=2 necessarily means
a second, deeper hop that could only happen from inside blue-a. This still
can't tell a real blue-a/blue-b breach apart from an accidental hop onto
another red seat (no id/name to check against) -- see issue #21's note that
this scenario currently has no red-vs-red gameplay mode, so that edge case
is low-probability in practice, not eliminated.

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
#
# `bash` 後面不能寫死接引號結尾——se-218/Metis#143（exit code hook）之後，
# 有 hook 生效的連線指令變成 `docker exec -it <seat> bash --rcfile
# /tmp/.metis-exit-rc.sh -i`，原本只認 `bash"` 的版本對不上這種格式，
# 會讓這一行沒被判定成新 session，繼續沿用舊基準主機名——容器重連換了
# 新的隨機 hostname 就會被誤判成「pivot 到新主機」（實測在 issue #41
# 驗證期間真的撞到這個 false positive）。`bash` 後面允許任意非引號字元
# 到收尾引號為止，涵蓋「有沒有接 --rcfile」兩種情況。
_SESSION_RE = re.compile(r'Script started on .*?\[COMMAND="docker exec -it (\S+) bash(?:\s[^"]*)?"')

# xterm/Debian 系預設 bashrc 常見的「設終端機視窗標題」跳脫序列：
# ESC ] 0 ; user@host: cwd BEL。每畫一次新 prompt 就會重發一次，內容包含
# 「目前是在哪台機器的 shell 裡」——比硬解析花俏的 Kali box-drawing prompt
# 更穩定（不受顏色碼、多位元組 UTF-8 邊框字元干擾）。
_OSC_TITLE_RE = re.compile(r"\x1b\]0;[^@\x07]*@([^:\x07]+):")


def find_pivot_targets(content: str) -> list[tuple[str, int]]:
    """掃過整份 .out 內容，回傳 (target_host, hop) 清單，依第一次出現的
    順序。hop 是「離自己的 session 基準幾步」：

      hop=1：從自己的席位直接換到另一個 host——對應 Metis 的網路拓樸
             （compose.seat.yml），紅隊只碰得到 blue-a（DMZ），所以第一
             層 pivot 只可能是「打進外網」。
      hop>=2：已經站在某個 pivot host 上，又換到另一個不同的 host（不是
             跳回自己的基準）——因為 blue-b（內網）在拓樸上沒有到紅隊的
             直接路由，唯一碰得到的方式是先站在 blue-a 上再往裡跳，所以
             第二層以上對應「打穿到內網」。

    這個分層不需要知道容器真正的名字（Metis 不提供 id→name 對照），純粹
    從「換了幾次地方」這個已經有的資料推論，跟拓樸文件裡寫死的路由限制
    對得上。session 邊界見 _SESSION_RE，跳回自己的基準會重設 hop（例如
    pivot 完 exit 回來，之後重新 pivot 算重新從 hop=1 開始）。"""
    events: list[tuple[int, str, str]] = []
    for m in _SESSION_RE.finditer(content):
        events.append((m.start(), "session", m.group(1)))
    for m in _OSC_TITLE_RE.finditer(content):
        events.append((m.start(), "host", m.group(1)))
    events.sort(key=lambda e: e[0])

    baseline: str | None = None
    current_host: str | None = None
    hop = 0
    pivots: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    for _, kind, value in events:
        if kind == "session":
            baseline = None
            current_host = None
            hop = 0
            continue
        if baseline is None:
            baseline = value
            current_host = value
            hop = 0
            continue
        if value == current_host:
            continue  # 沒變化
        if value == baseline:
            current_host = value
            hop = 0
            continue
        hop += 1
        current_host = value
        key = (value, hop)
        if key not in seen:
            seen.add(key)
            pivots.append(key)
    return pivots


def ingest_out_file(store: EventStore, seat: str, content: str) -> None:
    """對一份 .out 內容跑 pivot 偵測，把新發現的目標寫進去。store 端
    ON CONFLICT DO NOTHING，同一個 (seat, target_host) 重複呼叫是安全的。"""
    for target_host, hop in find_pivot_targets(content):
        layer = "external" if hop == 1 else "internal"
        try:
            store.record_possible_breach(seat=seat, target_host=target_host, layer=layer)
        except Exception:
            logger.exception("failed to record possible breach: seat=%s target=%s layer=%s", seat, target_host, layer)


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
