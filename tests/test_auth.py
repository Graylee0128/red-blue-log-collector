from rbcollector.auth import _extract_bearer, token_is_valid


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
