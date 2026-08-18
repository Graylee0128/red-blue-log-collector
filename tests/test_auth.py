import os

import pytest
from fastapi import HTTPException

from rbcollector.auth import _extract_bearer, require_purple_clearance, token_is_valid


def test_no_configured_token_disables_auth():
    assert token_is_valid(None, None) is True
    assert token_is_valid("anything", None) is True


def test_missing_token_rejected_when_configured():
    assert token_is_valid(None, "secret") is False


def test_wrong_token_rejected():
    assert token_is_valid("wrong", "secret") is False


def test_correct_token_accepted():
    assert token_is_valid("secret", "secret") is True


def test_extract_bearer_requires_prefix():
    assert _extract_bearer(None) is None
    assert _extract_bearer("secret") is None
    assert _extract_bearer("Bearer secret") == "secret"
    assert _extract_bearer("Bearer   padded  ") == "padded"


def test_purple_clearance_public_caller_needs_no_token(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret")
    require_purple_clearance("public", None)  # must not raise


def test_purple_clearance_rejects_missing_token(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret")
    with pytest.raises(HTTPException) as exc:
        require_purple_clearance("purple", None)
    assert exc.value.status_code == 401


def test_purple_clearance_rejects_wrong_token(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret")
    with pytest.raises(HTTPException):
        require_purple_clearance("purple", "Bearer wrong")


def test_purple_clearance_accepts_correct_token(monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret")
    require_purple_clearance("purple", "Bearer secret")  # must not raise


def test_purple_clearance_open_when_no_token_configured(monkeypatch):
    monkeypatch.delenv("INGEST_TOKEN", raising=False)
    require_purple_clearance("purple", None)  # local/dev default: must not raise
