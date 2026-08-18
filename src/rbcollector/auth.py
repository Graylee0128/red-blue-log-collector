from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException


def _extract_bearer(header_value: str | None) -> str | None:
    if not header_value or not header_value.startswith("Bearer "):
        return None
    return header_value[len("Bearer "):].strip()


def token_is_valid(provided: str | None, configured: str | None) -> bool:
    """No configured token means auth is disabled (local/dev default)."""
    if not configured:
        return True
    return provided is not None and hmac.compare_digest(provided, configured)


def require_ingest_token(authorization: str | None = Header(default=None)) -> None:
    configured = os.environ.get("INGEST_TOKEN") or None
    if not token_is_valid(_extract_bearer(authorization), configured):
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")
