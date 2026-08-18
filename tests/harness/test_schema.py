"""NormalizedEvent schema 斷言 —— 純函數。

重寫自 cyber 的 `tests/harness/test_schema.py`，改驗
`harness.schema.assert_normalized_event`——驗的是 rbcollector 的
NormalizedEvent 契約，不是 cyber 的 Core Event 契約。"""

import pytest

from harness.schema import SchemaViolation, assert_normalized_event

VALID = {
    "event_id": "evt-01j000000000000000000000",
    "team": "red",
    "observed_at": "2026-08-08T14:30:00+08:00",
    "source_ip": "10.0.0.10",
    "destination": "10.0.0.20",
    "action_result": "ok",
    "event_type": "red.action",
    "source": "red-team-api",
    "actor": None,
    "message": "nmap -sV 10.0.0.20",
    "correlation_id": "example-1",
    "metadata": {},
}


def without(field: str) -> dict:
    return {k: v for k, v in VALID.items() if k != field}


class TestAcceptsTheContract:
    def test_the_example_from_the_interface_contract_passes(self):
        assert_normalized_event(VALID)

    def test_blue_team_passes(self):
        assert_normalized_event({**VALID, "team": "blue"})

    def test_optional_fields_may_be_absent(self):
        minimal = {k: VALID[k] for k in ("event_id", "team", "observed_at", "event_type", "source")}
        assert_normalized_event(minimal)


class TestRequiredFields:
    @pytest.mark.parametrize("field", ["event_id", "team", "observed_at", "event_type", "source"])
    def test_every_required_field_is_required(self, field):
        with pytest.raises(SchemaViolation, match=field):
            assert_normalized_event(without(field))


class TestForbiddenFields:
    """擋 cyber Core Event 字彙悄悄長回來——見 docs/COPY_FROM_CYBER.md
    的「砍掉的耦合」清單。"""

    @pytest.mark.parametrize("field", ["exercise_id", "scenario_id", "lifecycle", "visibility", "action_id", "evidence_ref"])
    def test_cyber_specific_fields_are_rejected(self, field):
        with pytest.raises(SchemaViolation, match=field):
            assert_normalized_event({**VALID, field: "anything"})

    @pytest.mark.parametrize("word", ["loki", "logql", "promql", "grafana", "Grafana"])
    def test_backend_vocabulary_is_rejected_anywhere_in_the_event(self, word):
        with pytest.raises(SchemaViolation, match="(?i)" + word):
            assert_normalized_event({**VALID, "message": f"seen via {word}"})


class TestTeam:
    def test_unknown_team_is_rejected(self):
        with pytest.raises(SchemaViolation, match="team"):
            assert_normalized_event({**VALID, "team": "green"})


class TestTimestamps:
    def test_naive_observed_at_is_rejected(self):
        with pytest.raises(SchemaViolation, match="timezone"):
            assert_normalized_event({**VALID, "observed_at": "2026-08-08T14:30:00"})

    def test_unparsable_observed_at_is_rejected(self):
        with pytest.raises(SchemaViolation, match="observed_at"):
            assert_normalized_event({**VALID, "observed_at": "yesterday"})
