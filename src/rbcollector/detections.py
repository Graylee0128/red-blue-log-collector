from __future__ import annotations

"""資料驅動偵測規則 —— 取代 cyber 的 Grafana 告警規則
（`deploy/grafana/provisioning/alerting/rules.yaml`）的獨立版本。

cyber 的規則查的是這個 repo 沒有的 Loki/Prometheus 來源（vulnerable-app／
range-target／falco）。語意相同，換了引擎：每條規則檢查紅隊事件的
`metadata`（原始 ingest payload，見 `NormalizedEvent.metadata`）或
`message` 是否出現標記，依 `group_by` 在 `window_seconds` 內分組，
累計次數超過 `threshold` 才算一次偵測 —— 對應 Grafana「> N / 1分鐘」
的 firing 條件。

有兩處刻意留白的偵測落差，沿用原始設計（見 cyber scenario 的
`intentional_gaps` 註記）——不要「順手補齊」：
  - account-discovery 只抓「短時間內掃很多 student_id」，不判定
    「讀到不屬於自己的資料」或「批次帶走」。
  - egress-anomaly 只抓「讀到」SSRF 可達的 metadata，不判定
    「這樣讀到的憑證被實際使用」。
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

Predicate = Callable[[dict[str, Any]], bool]


def _metadata_true(field_name: str) -> Predicate:
    """`metadata[field_name]` 為真即命中（對應 cyber 的 `field=true` 篩選）。"""
    return lambda event: bool((event.get("metadata") or {}).get(field_name))


def _message_contains(needle: str) -> Predicate:
    """`message` 含 `needle` 即命中（對應 cyber Falco 的 `|= "text"` 篩選）。"""
    return lambda event: needle.lower() in str(event.get("message") or "").lower()


def _metadata_equals(field_name: str, value: str) -> Predicate:
    return lambda event: (event.get("metadata") or {}).get(field_name) == value


def _all(*predicates: Predicate) -> Predicate:
    return lambda event: all(p(event) for p in predicates)


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
DETECTION_RULES: tuple[DetectionRule, ...] = (
    DetectionRule("sqli-injection-burst", "T1190", "high", _metadata_true("sqli_suspected")),
    DetectionRule("sqli-injection-burst-target", "T1190", "high", _metadata_true("sqli_suspected")),
    # cyber 原本查的是 `ssh_failed_logins_total` 這個 Prometheus counter，
    # 這個 repo 沒有對應來源，退化成統計送進來、讀起來像 SSH 登入失敗的紅隊事件。
    DetectionRule("ssh-brute-force", "T1110", "medium", _all(_message_contains("ssh"), _message_contains("fail")), threshold=10),
    DetectionRule("webshell-upload-target", "T1505", "high", _message_contains("webshell exec detected")),
    DetectionRule("local-privesc-target", "T1548", "high", _message_contains("sudo find abuse")),
    DetectionRule("egress-anomaly-target", "T1552", "high", _metadata_true("ssrf_suspected")),
    DetectionRule("command-injection-target", "T1059", "high", _metadata_true("cmd_injection_suspected")),
    DetectionRule("cron-persistence-target", "T1053", "high", _message_contains("cron persistence write")),
    DetectionRule("account-discovery-target", "T1087", "medium", _metadata_equals("destination", "/students/token"), threshold=5),
    DetectionRule("falco-command-exec", "T1059", "high", _message_contains("exec detected")),
    DetectionRule("falco-sensitive-file", "T1005", "high", _message_contains("sensitive file access")),
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
