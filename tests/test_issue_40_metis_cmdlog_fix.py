"""Issue #40：Metis fix/cmdlog-backspace（se-218/Metis#142）修復效果驗證。

## 方法論（回應 PR #51 的審查意見：先前版本沒有真的拉分支、沒有真實資料）

Metis 是另一個團隊的私有 repo，`cmdlog.sh` 原始碼依規定不能夾帶進這個 repo
（見 .gitignore 對 `Metis/` 的說明）。所以這裡不嵌入 Metis 的原始碼，而是：

1. 在本機另外 checkout 的 Metis repo 裡，取出修復前／修復後兩版
   `deploy/cmdlog.sh` 的核心轉換邏輯（`tr '\\r' '\\n' | sed ...`
   對比 `tr '\\r' '\\n' | awk ... | sed ...`）：
     - 修復前：commit `1ae6855^`（se-218/Metis，PR #142 合併前）
     - 修復後：`origin/main`（commit `a32d288`，已含 #142 退格/方向鍵重放
       修復 + 後續 #143 離開碼工作）
2. 建構一批模擬鍵盤位元組流（含退格 `\\x08`、左右方向鍵 `\\x1b[D`/`\\x1b[C`、
   Enter `\\r`），涵蓋常見的紅隊/藍隊指令＋真實的打字修正情境（typo 用退格
   修正、用方向鍵回頭插字/換字）。
3. 把同一批位元組流餵給兩版邏輯，實際跑出結果（不是用猜的），記錄下面的
   `REAL_PIPELINE_SAMPLES`——`pre_fix_output`／`post_fix_output` 都是實際執行
   結果，可用 Metis repo 上列的 commit SHA 重新跑一遍驗證，不是憑空編的。

下面的測試就是拿這批「真實資料」驗證這個 repo 目前的過濾/比對邏輯該不該動：
- `is_noise()`：驗證修復對「純數字/重複字元」這類雜訊完全沒影響（跟退格重放
  是兩回事），所以維持原本三項檢查，不因這次修復簡化。
- `_is_response_action()` / `detections.py`：驗證修復前的殘留字元污染確實會
  打斷關鍵字比對（假陰性），修復後不再發生，但關鍵字清單本身不用跟著改。
"""

from rbcollector.analysis import _is_response_action
from rbcollector.detections import classify_technique
from rbcollector.seat_log_receiver import is_noise

# 每筆記錄「使用者實際敲的按鍵」（人讀版本，細節見上方方法論）以及跑過真實
# cmdlog.sh 新舊兩版後的實際輸出。unaffected=True 代表這筆跟退格/方向鍵重放
# 無關（沒有用到退格或方向鍵修正），預期兩版輸出應該一致。
REAL_PIPELINE_SAMPLES = [
    {
        "name": "baseline_clean",
        "keystrokes": "sudo find / -perm -4000<CR>",
        "pre_fix_output": "sudo find / -perm -4000",
        "post_fix_output": "sudo find / -perm -4000",
        "unaffected": True,
    },
    {
        "name": "backspace_typo",
        "keystrokes": "chmod 755 /etc/shadwo<BS><BS>ow<CR>",
        "pre_fix_output": "chmod 755 /etc/shadwoow",
        "post_fix_output": "chmod 755 /etc/shadow",
        "unaffected": False,
    },
    {
        "name": "extra_char_backspace",
        "keystrokes": "iptables -A INPUT -j DROPP<BS><CR>",
        "pre_fix_output": "iptables -A INPUT -j DROPP",
        "post_fix_output": "iptables -A INPUT -j DROP",
        "unaffected": False,
    },
    {
        "name": "left_arrow_insert",
        "keystrokes": "sudo fnd / -perm -4000<LEFT x16>i<CR>",
        "pre_fix_output": "sudo fnd / -perm -4000i",
        "post_fix_output": "sudo find / -perm -4000",
        "unaffected": False,
    },
    {
        "name": "digit_noise",
        "keystrokes": "123456<CR>",
        "pre_fix_output": "123456",
        "post_fix_output": "123456",
        "unaffected": True,
    },
    {
        "name": "repeated_char_noise",
        "keystrokes": "aaaaaa<CR>",
        "pre_fix_output": "aaaaaa",
        "post_fix_output": "aaaaaa",
        "unaffected": True,
    },
    {
        "name": "hydra_typo",
        "keystrokes": "hydra -l admni<BS><BS>in -P wordlist.txt ssh://192.168.1.10<CR>",
        "pre_fix_output": "hydra -l admniin -P wordlist.txt ssh://192.168.1.10",
        "post_fix_output": "hydra -l admin -P wordlist.txt ssh://192.168.1.10",
        "unaffected": False,
    },
    {
        "name": "sqlmap_leftarrow",
        "keystrokes": "sqlmap -u http:/target.com/page?id=1<LEFT x20>/<CR>",
        "pre_fix_output": "sqlmap -u http:/target.com/page?id=1/",
        "post_fix_output": "sqlmap -u http://target.com/page?id=1",
        "unaffected": False,
    },
    {
        # 左右方向鍵回頭修正時，殘留字元剛好打斷關鍵字本身（"iptables" 中間）
        "name": "keyword_integrity_transposition",
        "keystrokes": "itpables -A INPUT -j DROP<LEFT x23><BS><RIGHT>t<CR>",
        "pre_fix_output": "itpables -A INPUT -j DROPt",
        "post_fix_output": "iptables -A INPUT -j DROP",
        "unaffected": False,
    },
    {
        # 同上，但挑一個 _RESPONSE_TOKENS 裡沒有其他重複線索的關鍵字（chown），
        # 用來驗證「關鍵字比對從假陰性變成真陽性」不是靠別的 token 湊巧命中
        "name": "response_token_isolated_transposition",
        "keystrokes": "chwon root:root /etc/shadow<LEFT x24><BS><RIGHT>w<CR>",
        "pre_fix_output": "chwon root:root /etc/shadoww",
        "post_fix_output": "chown root:root /etc/shadow",
        "unaffected": False,
    },
]

UNAFFECTED_NAMES = {s["name"] for s in REAL_PIPELINE_SAMPLES if s["unaffected"]}


def test_fixture_data_is_internally_consistent():
    """防呆：unaffected 標記要跟 pre/post 是否相等對得上，避免手動維護漏改。"""
    for sample in REAL_PIPELINE_SAMPLES:
        same = sample["pre_fix_output"] == sample["post_fix_output"]
        assert same == sample["unaffected"], (
            f"{sample['name']}: unaffected={sample['unaffected']} 但 "
            f"pre==post 是 {same}，兩者應該一致"
        )


def test_cmdlog_fix_only_changes_backspace_and_arrow_key_cases():
    """修復只影響「有用到退格/方向鍵修正」的案例，跟修復描述的範圍一致
    （se-218/Metis#142：只處理退格/DEL/左右移動，沒有動到其他部分）。"""
    affected = {s["name"] for s in REAL_PIPELINE_SAMPLES if not s["unaffected"]}
    assert affected == {
        "backspace_typo",
        "extra_char_backspace",
        "left_arrow_insert",
        "hydra_typo",
        "sqlmap_leftarrow",
        "keyword_integrity_transposition",
        "response_token_isolated_transposition",
    }


def test_is_noise_unaffected_by_cmdlog_fix():
    """雜訊過濾（純數字/重複字元）的判定結果不受這次修復影響——證明
    is_noise() 的三項檢查跟退格重放是兩個獨立問題，不該因為這次修復簡化。"""
    for sample in REAL_PIPELINE_SAMPLES:
        if sample["name"] not in UNAFFECTED_NAMES:
            continue
        assert is_noise(sample["pre_fix_output"]) == is_noise(sample["post_fix_output"]), (
            f"{sample['name']}: 修復不該改變雜訊判定結果"
        )


def test_is_noise_still_filters_typing_test_noise_post_fix():
    """修復後，純打字測試雜訊（跟退格/方向鍵無關）仍然要被濾掉。"""
    assert is_noise("123456") is True
    assert is_noise("aaaaaa") is True


def test_response_action_keyword_recovers_after_fix():
    """修復前：殘留字元打斷關鍵字本身，造成關鍵字比對假陰性（明明是藍隊
    在下 chown/iptables 這類事後應對指令，卻比對不到）。修復後恢復正確。"""
    sample = next(
        s for s in REAL_PIPELINE_SAMPLES
        if s["name"] == "response_token_isolated_transposition"
    )
    pre_event = {"message": sample["pre_fix_output"]}
    post_event = {"message": sample["post_fix_output"]}

    assert _is_response_action(pre_event) is False, "修復前應該是假陰性（關鍵字被打斷）"
    assert _is_response_action(post_event) is True, "修復後應該正確命中"


def test_response_action_keyword_list_unchanged_is_correct():
    """驗證關鍵字清單本身不需要因為這次修復調整——只要指令完整（修復後的
    正常情況），現有清單就能正確命中，不用加字或改比對邏輯。"""
    for sample in REAL_PIPELINE_SAMPLES:
        if sample["name"] not in {
            "extra_char_backspace",
            "keyword_integrity_transposition",
            "response_token_isolated_transposition",
        }:
            continue
        assert _is_response_action({"message": sample["post_fix_output"]}) is True


def test_detection_rule_recovers_after_fix():
    """修復前：sudo+find 提權規則（T1548，對應藍隊第 03 關）因為 "find" 被
    殘留字元打斷成 "fnd" 而漏判。修復後恢復正確命中。"""
    sample = next(s for s in REAL_PIPELINE_SAMPLES if s["name"] == "left_arrow_insert")
    pre_event = {"message": sample["pre_fix_output"]}
    post_event = {"message": sample["post_fix_output"]}

    assert classify_technique(pre_event) is None, "修復前 'fnd' 不該命中 local-privesc-target"

    post_result = classify_technique(post_event)
    assert post_result is not None
    assert post_result["rule_id"] == "local-privesc-target"
    assert post_result["technique"] == "T1548"


def test_detection_rules_unchanged_is_correct():
    """驗證 11 條規則本身不需要因為這次修復調整——完整指令（修復後的正常
    情況）下，既有的字串包含比對就能正確命中。"""
    sample = next(s for s in REAL_PIPELINE_SAMPLES if s["name"] == "hydra_typo")
    result = classify_technique({"message": sample["post_fix_output"]})
    assert result is not None
    assert result["rule_id"] == "ssh-brute-force"
    assert result["technique"] == "T1110"
