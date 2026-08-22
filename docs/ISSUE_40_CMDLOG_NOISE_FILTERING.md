# Issue #40: cmdlog 打字殘留修好後的補丁優化

## 背景

Metis `cmdlog.sh` 原本有個問題：打錯字按退格後，被刪掉的部分仍會留在紀錄中（原始位元組流未正確重放），導致指令被切碎成片段（如 `y`/`pyh`/`yp`）。

Metis 官方在分支 `fix/cmdlog-backspace` 中修復了此問題，改成逐位元組重放並維護真正的游標位置。

## 當前的臨時補丁

### 1. `seat_log_receiver.py` 的 `is_noise()` 函數（第 120-142 行）

過濾明顯的打字測試雜訊：
- 純數字（如 `123456`）
- 單一字元重複 ≥3 次（如 `aaaa`）  
- 重複字元搭空白（如 `a a a`）

**注意**：目前在 ingest 層完全關閉了噪聲過濾（見第 155-158 行註釋），過濾工作交給顯示層（前端 `collapseBursts()`）。

### 2. 前端 `collapseBursts()` 函數（`ui/purple-console/index.html`）

同來源在 5 秒內連續出現多筆事件時，只保留最後一筆，用於合併被切碎的指令片段。

### 3. `analysis.py` 的 `_is_response_action()` 函數（第 177-179 行）

用關鍵字比對識別藍隊事後應對：
```python
_RESPONSE_TOKENS = (
    "chmod", "chown", "iptables", "ufw", "firewall-cmd", "nft ",
    "drop", "deny", "block",
    "rm -f", "delete from", "sudoers",
)
```

在指令被切碎時容易誤判/漏判——關鍵字可能剛好卡在片段交界處。

## 測試計劃

在 Metis `fix/cmdlog-backspace` 分支部署後：

1. **觀察一輪真實資料**
   - 驗證一般打字+退格/左右移動的殘缺片段是否消失
   - 檢查雜訊比例是否降低

2. **重新驗證關鍵字比對**
   - `detections.py` 的 11 條偵測規則命中率有沒有提升
   - `_is_response_action()` 的准確度是否改善

3. **決策**
   - 確認雜訊明顯改善後，簡化 `is_noise()` 和 `collapseBursts()` 的過濾邏輯
   - 或根據實際數據進一步調整關鍵字列表

## Metis 已知限制

即使在 `fix/cmdlog-backspace` 分支中，以下情況仍未完全修復：
- Home/End/向前刪除（Del 鍵）的逃脫序列（因終端機/模式而異）
- 方向鍵叫回歷史指令時會變空行

## 相關代碼位置

| 組件 | 文件 | 行數 | 說明 |
|------|------|------|------|
| 雜訊過濾函數 | `src/rbcollector/seat_log_receiver.py` | 120-142 | `is_noise()` |
| 應對動作判定 | `src/rbcollector/analysis.py` | 170-179 | `_RESPONSE_TOKENS`, `_is_response_action()` |
| 偵測規則 | `src/rbcollector/detections.py` | 71-114 | 11 條 MITRE ATT&CK 規則 |
| 前端過濾 | `ui/purple-console/index.html` | - | `collapseBursts()` 函數 |

## 環境變量參考

無特殊環境變量用於控制噪聲過濾——過濾邏輯目前硬編碼在代碼中。

## 測試命令

```bash
# 運行相關測試
pytest -v tests/test_analysis.py tests/test_detections.py

# 啟動本地開發環境
docker compose up -d --build
curl http://localhost:8001/docs
```
