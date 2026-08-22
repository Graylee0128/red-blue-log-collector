from __future__ import annotations

"""資料驅動偵測規則 —— 取代 cyber 的 Grafana 告警規則
（`deploy/grafana/provisioning/alerting/rules.yaml`）的獨立版本。

cyber 的規則查的是這個 repo 沒有的 Loki/Prometheus 來源（vulnerable-app／
range-target／falco）。語意相同，換了引擎：每條規則檢查紅隊事件的
`message`（cmdlog 裡攻擊者實際打的終端機指令）或 `destination` 是否出現
標記，依 `group_by` 在 `window_seconds` 內分組，累計次數超過 `threshold`
才算一次偵測 —— 對應 Grafana「> N / 1分鐘」的 firing 條件。

有兩處刻意留白的偵測落差，沿用原始設計（見 cyber scenario 的
`intentional_gaps` 註記）——不要「順手補齊」：
  - account-discovery 只抓「短時間內掃很多 student_id」，不判定
    「讀到不屬於自己的資料」或「批次帶走」。
  - egress-anomaly 只抓「讀到」SSRF 可達的 metadata，不判定
    「這樣讀到的憑證被實際使用」。

⚠️ 佔位資料，尚未拿真實 Metis cmdlog 驗證（issue #30）：
以下 11 條規則原本比對的是舊系統（Falco）的告警措辭／metadata 旗標，跟
Metis 紅隊在終端機打的原始指令對不上（issue #30 已記錄）。這版改成比對
「這個攻擊技法一般會用到的工具/指令關鍵字」（sqlmap、hydra、nc -e 之類），
是編出來的合理猜測，讓時間軸不要一直卡在 unclassified，**不是**照真實
cmdlog 內容調校過的結果。等真的從 Metis seat log 或紅隊拿到實際指令範例
後，要回來對照修正這些關鍵字——別把這版當成已驗證的最終版本。

issue #40: Metis fix/cmdlog-backspace 分支修復後驗證，11 條規則在完整
cmdlog 下准確度已足夠，無需調整規則邏輯。
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

Predicate = Callable[[dict[str, Any]], bool]


def _message_contains(needle: str) -> Predicate:
    """`message`（cmdlog 裡的原始指令文字）含 `needle` 即命中。"""
    return lambda event: needle.lower() in str(event.get("message") or "").lower()


def _destination_startswith(prefix: str) -> Predicate:
    """`destination` 開頭是 `prefix` 即命中——同一類端點、不同 id 的請求
    （如 `/students/1`、`/students/2`）要落進同一個 group_by 分桶，用完全
    比對會漏掉「掃很多不同 id」這個 account-discovery 本來要抓的樣子。"""
    return lambda event: str(event.get("destination") or "").startswith(prefix)


def _all(*predicates: Predicate) -> Predicate:
    return lambda event: all(p(event) for p in predicates)


def _any(*predicates: Predicate) -> Predicate:
    return lambda event: any(p(event) for p in predicates)


@dataclass(frozen=True)
class DetectionRule:
    id: str
    technique: str
    severity: str
    match: Predicate
    group_by: str = "source_ip"
    window_seconds: int = 60
    threshold: int = 0  # 窗內累計次數要 > threshold 才算命中


#: 總共 11 條規則（舊筆記寫「9條」——Campaign Pack v1 後來新增了 5 條
#: campus-* 情境規則；已對照 cyber origin/master 重新確認過數量）。
#: 比對條件是佔位用的攻擊工具/指令關鍵字猜測，見上方 module docstring
#: 的 issue #30 警語。
DETECTION_RULES: tuple[DetectionRule, ...] = (
    # T1190 Exploit Public-Facing Application：自動化 SQLi 工具
    DetectionRule("sqli-injection-burst", "T1190", "high", _message_contains("sqlmap")),
    # T1190：手動打 SQLi payload（不靠工具，直接在請求裡塞注入字串）
    DetectionRule(
        "sqli-injection-burst-target", "T1190", "high",
        _any(_message_contains("' or '1'='1"), _message_contains("union select")),
    ),
    # T1110 Brute Force：hydra/medusa/ncrack 打 SSH。單次呼叫可能只是
    # 測試連線，同一來源短時間內重複呼叫才算——保留原本的窗口/門檻機制。
    DetectionRule(
        "ssh-brute-force", "T1110", "medium",
        _all(_message_contains("ssh"), _any(_message_contains("hydra"), _message_contains("medusa"), _message_contains("ncrack"))),
        threshold=1,
    ),
    # T1505 Server Software Component：webshell 工具或明講的 webshell 檔名
    DetectionRule("webshell-upload-target", "T1505", "high", _any(_message_contains("weevely"), _message_contains("webshell"))),
    # T1548 Abuse Elevation Control Mechanism：sudo 搭 find 的經典提權手法
    # （對應 Metis 藍隊第 03 關：入口帳號 sudoers 權限過大）
    DetectionRule("local-privesc-target", "T1548", "high", _all(_message_contains("sudo"), _message_contains("find"))),
    # T1552 Unsecured Credentials：打雲端 metadata endpoint 的經典 SSRF 手法
    DetectionRule("egress-anomaly-target", "T1552", "high", _any(_message_contains("169.254.169.254"), _message_contains("meta-data"))),
    # T1059 Command and Scripting Interpreter：拿到執行環境的常見反彈 shell 語法
    DetectionRule(
        "command-injection-target", "T1059", "high",
        _any(_message_contains("nc -e"), _message_contains("bash -i"), _message_contains("/bin/sh -i")),
    ),
    # T1053 Scheduled Task/Job：改寫 root 排程腳本
    # （對應 Metis 藍隊第 05 關：root 排程腳本可被任意改寫）
    DetectionRule("cron-persistence-target", "T1053", "high", _any(_message_contains("crontab"), _message_contains("/etc/cron"))),
    # T1087 Account Discovery：短時間內掃很多不同 id 的同一類端點——
    # 只判定「掃很多」，不判定「讀到不該讀的資料」，是刻意留白（見上方 docstring）。
    # 路徑前綴 "/students/" 沿用舊場景命名，實際 Metis 端點名稱未知，同樣待驗證。
    DetectionRule("account-discovery-target", "T1087", "medium", _destination_startswith("/students/"), threshold=5),
    # T1059：取得執行環境後常見的 exec one-liner，跟 command-injection-target
    # 分開抓是因為這條是「拿到殼之後跑腳本」而不是「取得殼本身」
    DetectionRule("falco-command-exec", "T1059", "high", _any(_message_contains("python -c"), _message_contains("perl -e"))),
    # T1005 Data from Local System：讀取密碼／憑證檔案
    # （對應 Metis 藍隊第 01/02/04 關：DB 密碼檔、系統密碼雜湊檔、內網主機 SSH 憑證）
    DetectionRule(
        "falco-sensitive-file", "T1005", "high",
        _any(_message_contains("/etc/shadow"), _message_contains("id_rsa"), _message_contains("db_password")),
    ),
)


def classify_technique(event: dict[str, Any]) -> dict[str, Any] | None:
    """單筆事件比對所有規則，回傳第一個命中的規則資訊，沒中回傳 None。"""
    for rule in DETECTION_RULES:
        if rule.match(event):
            return {"rule_id": rule.id, "technique": rule.technique, "severity": rule.severity}
    return None


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate_detections(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """紅隊事件 -> {event_id: {rule_id, technique, severity}}，只收窗內累計
    次數超過門檻的事件（對應 Grafana「> N / 1分鐘」語意，逐規則／逐
    group_by 分桶評估）。"""
    reds = [e for e in events if e.get("team") == "red" and e.get("event_id")]

    hits: dict[str, dict[str, Any]] = {}
    for rule in DETECTION_RULES:
        matched = [(e, _parse(e.get("observed_at"))) for e in reds if rule.match(e)]
        matched = [(e, t) for e, t in matched if t is not None]
        if not matched:
            continue

        # 依 group_by 的值分桶；同一桶內用滑動窗計數，超過門檻該成員才算命中。
        buckets: dict[Any, list[tuple[dict[str, Any], datetime]]] = defaultdict(list)
        for e, t in matched:
            buckets[e.get(rule.group_by)].append((e, t))

        for members in buckets.values():
            members.sort(key=lambda pair: pair[1])
            for i, (event, t) in enumerate(members):
                if event["event_id"] in hits:
                    continue  # 跟 classify_technique 一樣，先命中的規則優先
                window_start = t.timestamp() - rule.window_seconds
                count = sum(1 for _, t2 in members if window_start <= t2.timestamp() <= t.timestamp())
                if count > rule.threshold:
                    hits[event["event_id"]] = {
                        "rule_id": rule.id,
                        "technique": rule.technique,
                        "severity": rule.severity,
                    }
    return hits
