from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from typing import Any

from cyberkimi.core import canonical_json, utc_now
from cyberkimi.errors import AuthorizationError
from cyberkimi.policy.models import ExecutionGrantClaims


class GrantCodec:
    def __init__(self, signing_key: bytes) -> None:
        self.signing_key = signing_key

    def issue(self, claims: ExecutionGrantClaims) -> str:
        header = _encode(canonical_json({"alg": "HS256", "typ": "CK-GRANT", "v": 1}).encode())
        payload = _encode(canonical_json(claims).encode())
        signature = hmac.new(
            self.signing_key, f"{header}.{payload}".encode(), hashlib.sha256
        ).digest()
        return f"{header}.{payload}.{_encode(signature)}"

    def verify(self, token: str, *, now: datetime | None = None) -> ExecutionGrantClaims:
        try:
            header, payload, signature = token.split(".")
            actual = _decode(signature)
        except Exception as exc:
            raise AuthorizationError("malformed execution grant") from exc
        expected = hmac.new(
            self.signing_key, f"{header}.{payload}".encode(), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(actual, expected):
            raise AuthorizationError("execution grant signature mismatch")
        try:
            header_json: dict[str, Any] = json.loads(_decode(header))
            claims = ExecutionGrantClaims.model_validate_json(_decode(payload))
        except Exception as exc:
            raise AuthorizationError("invalid execution grant payload") from exc
        if header_json != {"alg": "HS256", "typ": "CK-GRANT", "v": 1}:
            raise AuthorizationError("unsupported execution grant header")
        check_time = now or utc_now()
        if claims.expires_at <= check_time or claims.issued_at > check_time:
            raise AuthorizationError("execution grant is expired or not yet valid")
        return claims


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not value or "=" in value:
        raise ValueError("invalid base64url")
    raw = base64.b64decode((value + "=" * (-len(value) % 4)).encode(), altchars=b"-_", validate=True)
    if _encode(raw) != value:
        raise ValueError("non-canonical base64url")
    return raw
