# Red/Blue Log Collector

紫隊獨立收集器，接紅／藍雙方的原始資料，正規化成同一套方便關聯比對的事件格式，再把整合後的時間軸提供給後續分析／投影使用。

## 從 `cyber` 沿用了什麼

這個 repo 不是從零重寫，保留了 `cyber` Purple 那套已經驗證過的邊界：

- **HTTP 接收邊界**（來自 `src/purple/receiver/server.py`）
- **adapter 隔離**（來自 `src/purple/receiver/adapters.py`）
- **event-id ＋ 正規化模式**（來自 `src/purple/receiver/core.py`）
- **四欄位遙測契約**（來自 `src/purple/telemetry_fields.py`）
  - `source_ip`
  - `destination`
  - `time` → `observed_at`
  - `action_result`
- **PostgreSQL 事件儲存＋冪等模式**（來自 `src/purple/store/events.py`）
- **Docker化 receiver 模式**（來自 `deploy/receiver/Dockerfile`）

Cyber-range 特有的概念（exercise/scenario、Grafana webhook 生命週期、response agent、Falco 規則、disclosure/visibility）刻意沒有搬進這個獨立收集器。

## 啟動

```bash
docker compose up -d --build
curl http://localhost:8001/healthz
```

API 文件：

```text
http://localhost:8001/docs
```

**單純 `docker compose up -d --build` 不夠**，還需要：

1. **Metis 那邊要先起來**：`/var/log/metis/seat`、`/var/log/metis/leaderboard` 兩個目錄要真的存在且可讀，這是 Metis 部署（`install.sh red/blue`）先跑完才會有的，順序上 Metis 要先起，我們的 collector 才有東西可讀。
2. **藍隊計分（`checker.py`）已經由 Metis 自動起了**：`install.sh` 透過 `metis-checker@.service` 這個 systemd unit 幫每個藍隊 a 座位各自跑一支 `checker.py --loop`，輸出固定寫進 `/var/log/metis/leaderboard/`（`docker-compose.yml` 的預設值已對齊，見下方[藍隊計分接收器](#藍隊計分接收器)），一般情況不用手動起、也不用另外設定。只有本機開發環境不是走 systemd 部署時才需要手動跑：

   ```bash
   cd <Metis>/blue/scoring-engine
   sudo python3 checker.py <target> --loop 15 --out /var/log/metis/leaderboard   # 要 sudo，checker.py 靠 docker exec 判定，沒有 docker 群組權限會全部誤判成 fail
   ```

   這種情況如果輸出目錄跟預設不同，用 `METIS_BLUE_SCORE_HOST_DIR` 環境變數覆寫（見下方[藍隊計分接收器](#藍隊計分接收器)）。

## Purple Console（投影戰況板）

```bash
docker compose up -d --build purple-console
```

開 `http://<host>:8090`。純靜態頁面（沒有自己的後端），由獨立 nginx container 提供，跟 collector API 分開。每 3 秒輪詢一次 `GET /analysis`，全部面板都是真資料，沒有 demo/mock：

- **攻防事件關聯時間軸**：四色分類——快速應對（綠，1 分鐘內事後應對）／延遲應對（紫，超過 1 分鐘）／主動修補（藍，紅隊完全沒動作、藍隊自己抓到並修好）／未被偵測（紅色虛線）。這個場景藍隊沒有自動告警機制，「應對速度」是照藍隊實際的人工反應時間分類，不是「告警速度」。
- **紅隊攻擊拓樸**（左側）：紅隊來源格＋藍隊靶機格（外網/內網成對），疑似突破（靠 `breach_detector.py` 用終端機標題跳脫序列做的啟發式 pivot 偵測）時亮紅燈＋光束動畫。
- **藍隊整體修補進度**（右側）：checker.py 判分結果（7 項漏洞修補檢查，5 公開＋2 隱藏加分題），格子逐項顯示通過席位數。
- **Red Shell／Blue Shell**：兩隊終端機打過的原始指令，直接讀 seat log。
- **頂列統計**：應對（藍隊應對數／紅隊事件數）、快速應對、修補（應對＋主動修補加總）、反應時間。
- **`admin.html`**（獨立管理頁，故意不從 `index.html` 連結過去）：`/admin/clear` 一鍵清空六張表，開新的一局演練前用，需要 `INGEST_TOKEN`。

### 時間軸什麼時候會出現一列

關聯邏輯（[`analysis.py`](src/rbcollector/analysis.py) 的 `correlate()`）只認兩種來源，缺一不可：

- **任何紅隊事件**——只要紅隊終端機打過任何一行指令（不管內容、不管有沒有意義），就會產生一列，狀態預設是「未被偵測」（紅色虛線），除非後續配對到藍隊回應：
  - **快速應對／延遲應對**（`hit`，`detection_method="response"`）：紅隊事件之後 **5 分鐘內**，同時出現兩種訊號才算數——(1) 藍隊 cmdlog 含關鍵字（`chmod`／`chown`／`iptables`／`ufw`／`firewall-cmd`／`nft `／`drop`／`deny`／`block`／`rm -f`／`delete from`／`sudoers`），(2) checker.py 真的驗到某項檢查從 fail 翻 pass（`blue.remediation` 事件）。缺一不可——單靠關鍵字可能是打錯指令根本沒修好，單靠 checker.py 通過不知道是不是跟這次紅隊行動有關。1 分鐘內算快速，超過算延遲。
  - **快速偵測／延遲偵測**（`detection_method="alert"`，即時告警路徑）：目前這個場景**完全用不到**，藍隊沒有自動告警機制，這條路徑是死的，保留給以後真的接上告警系統。
- **藍隊主動修補**（`hit`，`detection_method="autonomous"`，`red` 是 `null`）：紅隊完全沒動作也會出現——只要藍隊自己抓到並修好一項漏洞（一樣要求 cmdlog 關鍵字 + `blue.remediation` 雙訊號都在 5 分鐘窗口內），不需要任何紅隊事件觸發。

**不會觸發任何東西的情況**（Blue Shell 看得到打字內容，但時間軸不會有任何反應）：
- 藍隊隨便打字、沒有真的修東西——沒有 checker.py 驗證通過，不算數。
- 對一個**已經合規**的檔案下 `chmod`（例如檔案權限本來就對）——指令文字符合關鍵字，但 checker.py 不會有 fail→pass 的轉換，不會產生 `blue.remediation`。
- 純紅隊活動、沒有任何藍隊訊號——會產生「未被偵測」列（紅色虛線），不是完全沒反應，但也不算「應對」。

### 前端額外過濾（不影響資料庫，只影響畫面）

Purple Console 的時間軸另外套了兩層跟資料品質有關的過濾（`ui/purple-console/index.html`），資料庫本身完整保留，不受影響：

- `isNoiseMessage()`：純數字或同一字元重複 ≥3 次的紅隊訊息（如打字測試留下的 `123456`）不顯示。
- `collapseBursts()`：同一來源在 5 秒內連續出現多筆事件，只保留最後一筆——偶爾會看到一次操作被切成好幾筆殘缺片段（如 `y`／`pyh`／`yp` 才接著出現完整的指令），這支是治標的緩解，不是治本（根因還沒定案，見已關閉的 [issue #39](../../issues/39) 討論），也可能誤合併真的連續快打的不同指令，是接受的取捨。

## 紅／藍隊真實資料來源

Metis 把紅／藍隊終端機的操作直接寫到 host 端檔案（`/var/log/metis/seat/<seat>.cmd`），[`seat_log_receiver.py`](src/rbcollector/seat_log_receiver.py) 直接 tail 那個目錄（唯讀掛載進 `seat-log-receiver` container）——不用 forwarder 腳本、不用 `/ingest/*`、不用 bearer token。隊伍別（紅/藍）從檔名判斷（`red-*.cmd` vs `blue-{a,b}-*.cmd`）。

[`blue_score_receiver.py`](src/rbcollector/blue_score_receiver.py) 對藍隊計分做一樣的事——見下方[藍隊計分接收器](#藍隊計分接收器)。

[`breach_detector.py`](src/rbcollector/breach_detector.py) 也是同一套「直接讀 Metis 自己的檔案」模式，tail `red-*.out`（終端機錄影），靠 OSC 跳脫序列（`ESC ] 0 ; user@host: cwd BEL`）判斷紅隊有沒有換過終端機視窗標題，heuristically 推論有沒有 pivot 到別台主機——純推論，不是確認過的攻擊成功事件。

[`exit_code_receiver.py`](src/rbcollector/exit_code_receiver.py)（issue #41）補上 `action_result` 這一欄——Metis（se-218/Metis#143）把每句指令的離開碼印進 `<seat>.out`（畫面輸出，不是 `.cmd`），這支重建 `.out`／`.timing` 的時間軸把離開碼配回對應的 cmdlog 事件，寫回 `normalized_events`。同樣是啟發式訊號（來賓是容器內 root，能自己偽造離開碼），不是竄改不了的資安邊界。


## 藍隊計分接收器

Metis 的藍隊計分（`blue/scoring-engine/checker.py`，每席 7 項漏洞修補檢查，5 公開＋2 隱藏加分題，每題 20 分）也沒有 API——每次重新檢查會把結果寫進 host 端的 `leaderboard_<target>.json`。[`src/rbcollector/blue_score_receiver.py`](src/rbcollector/blue_score_receiver.py) 直接輪詢那個目錄（跟 seat log receiver 同一套「讀 Metis 自己的檔案」模式），並套用 `checker.py` 自己在推分數進來賓容器前用的**同一套**洩題過濾：2 題隱藏加分題在 5 題公開題全過之前，`GET /blue-scores` 不會吐出來，這支 API 可以公開曝露。

```bash
docker compose up -d --build blue-score-receiver
```

**`BLUE_SCORE_DIR` 預設對到 `/var/log/metis/leaderboard/`**——這個路徑原本沒有固定慣例（`checker.py` 早期版本用純相對路徑寫檔，實際落在誰手動執行當下的工作目錄），已回報 Metis（[se-218/Metis#137](https://github.com/se-218/Metis/issues/137)），對方在 [PR #138](https://github.com/se-218/Metis/pull/138) 定案：`checker.py` 預設輸出目錄改成 `/var/log/metis/leaderboard/`，且透過新增的 `metis-checker@.service` systemd unit 自動幫每個藍隊 a 座位起一支——這是 Metis 官方確認的正式慣例（2026-08-21），`docker-compose.yml` 的預設值已對齊，一般部署不用另外設定。

只有本機開發環境不是走 systemd 部署（`checker.py` 手動帶 `--out` 指到別的目錄）時才需要覆寫，設環境變數 `METIS_BLUE_SCORE_HOST_DIR` 即可（`docker-compose.yml` 已經支援 `${METIS_BLUE_SCORE_HOST_DIR:-/var/log/metis/leaderboard}`），或建一份沒進版控的 `docker-compose.override.yml`：

```yaml
services:
  blue-score-receiver:
    environment:
      BLUE_SCORE_DIR: /home/<user>/Metis/blue/scoring-engine
    volumes:
      - /home/<user>/Metis/blue/scoring-engine:/home/<user>/Metis/blue/scoring-engine:ro
```

對不上的話這條資料會整場收不到，**且不會報錯**（`blue_score_receiver.py` 對不存在的目錄只記警告，不會讓服務掛掉）——沒比對過就假設是對的最容易漏掉。

b 座位（內部網段）刻意不計分——Metis 那邊已在 PR #138 確認是設計如此（排行榜/進度指示器整套只針對 `blue-a-*` 外網靶機，`b` 只用於橫向移動場景），不是漏接。

## 開放給其他 VM 存取

`docker-compose.yml` 的 `"8001:8000"` port mapping 已經綁到 collector host 上的所有網卡，不只 `localhost`——只要 host 防火牆/安全群組放行這個 port，同網段的來源 VM 就連得到。真的要對外開放前，還缺（見 [issue #1](../../issues/1)）：

1. **設共用 bearer token**：`docker compose up` 之前先 export `INGEST_TOKEN`（`docker-compose.yml` 會直接傳進去）。沒設的話 `/ingest/*` 不驗證任何請求（僅適合本機/開發環境）——任何連得到這個 port 的人都能寫假事件。設了之後，每個 `POST /ingest/*` 都要帶 `Authorization: Bearer <token>`，沒帶會回 `401`。
2. **只對來源 VM 開 port**，不要對 `0.0.0.0/0` 開。
3. **從 VM 送 log**：Metis 真實 log 格式現在已知了，這個 collector 直接讀（見上方[紅／藍隊真實資料來源](#紅藍隊真實資料來源)），這條路徑不再需要通用的 tail-and-POST 轉送腳本，只有 Metis 沒辦法直接讓 collector 讀到檔案的資料源才需要另外寫一支。

**目前不打算採用**：[issue #2](../../issues/2) 提議把這套 HTTP-push 模式換成 cyber 的 Alloy/Loki tail-and-ship pipeline。那套機制更成熟，但也連帶引出「這個收集器的 Postgres／`/analysis` 那半要不要繼續存在」這個更大的問題，細節見該 issue。目前決定：維持現有的 ingestion 路徑（bearer-token HTTP push），因為改動較小，而且這個 repo 的關聯/MTTD 邏輯沒有明顯的 Loki 對應做法。等到原始 log 量或多方消費需求（例如某個儀表板工具也想要同一份 log）大到值得投資共用 Loki 後端時再重新評估。

## Smoke test

```powershell
pwsh scripts/smoke-test.ps1
```

把整套服務啟動起來，POST [`examples/red-event.json`](examples/red-event.json) 跟 [`examples/blue-event.json`](examples/blue-event.json)，並斷言整條管線真的在 `/analysis` 上產生一筆關聯成功的 `hit`——不只是 ingest 回 200 而已。

## Release

Image 版本要符合語意化版本（semver）。要發布新版本：

1. 更新 [`pyproject.toml`](pyproject.toml) 的 `version`：
   ```toml
   [project]
   version = "0.2.0"  # 例如 0.1.0 → 0.2.0
   ```

2. Commit 並打一個對應版本的 git tag：
   ```bash
   git add pyproject.toml
   git commit -m "版本提升至 0.2.0"
   git tag v0.2.0      # tag 一定要用 'v' 開頭
   git push origin main --tags
   ```

3. CI 會：
   - 驗證 tag 版本（`v0.2.0`）跟 `pyproject.toml`（`0.2.0`）一致
   - Build 並推送 image，兩個 tag：
     - `ghcr.io/graylee0128/red-blue-log-collector:v0.2.0`（固定版本）
     - `ghcr.io/graylee0128/red-blue-log-collector:latest`（開發/方便用）
   - 版本對不上就失敗，並印出清楚的錯誤訊息

### 版本不一致

如果 CI 因為版本不一致失敗，代表 tag 已經推上去但 image 沒 build。修好再重試：

```bash
# 如果 tag 推上去了但版本錯了：
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
# 修好 pyproject.toml 再重來一次
```

### 使用這個 image

- **開發環境**：用 `:latest`（永遠跟著 main 分支）
- **正式環境**：用固定的版本 tag（例如 `:v0.2.0`）。這個 repo 自己的
  [`docker-compose.yml`](docker-compose.yml) 目前還是本機 build（`build: .`），不是拉發布過的 image——如果要改成部署發布版 image，把下面這行 `image:` 換上去。

```yaml
services:
  collector:
    image: ghcr.io/graylee0128/red-blue-log-collector:v0.2.0
```

## 介面契約

完整的欄位別名對照表、正規化後的事件格式、關聯比對邏輯，見 [`docs/INTERFACE_CONTRACT.md`](docs/INTERFACE_CONTRACT.md)——這份要拿去給紅／藍隊看，不是給他們看原始碼。

## Adapter 是唯一該改的地方

Metis（或未來其他來源）的介面格式如果變了，**不要重寫整個收集器**，只改：

```text
src/rbcollector/adapters/red.py
src/rbcollector/adapters/blue.py
```

儲存層／API 契約維持不變。

推薦的最小生產者契約：

```json
{
  "timestamp": "2026-08-17T11:00:00+08:00",
  "source_ip": "10.0.0.10",
  "destination": "10.0.0.20",
  "action_result": "ok",
  "event_type": "red.action",
  "message": "...",
  "correlation_id": "optional-but-highly-recommended"
}
```

## 為什麼原始事件要另外存一份

Adapter 遇到紅／藍隊發布真實 schema 時會跟著改。把生產者原始 payload 留在 `raw_events` 裡，代表早期錯的對應關係之後可以重新處理，不會弄丟原始證據。
