"""Opaque identifier generation."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone


def new_id(prefix: str) -> str:
    """Return a sortable-enough opaque identifier without external services."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix.upper()}-{stamp}-{secrets.token_hex(5).upper()}"
