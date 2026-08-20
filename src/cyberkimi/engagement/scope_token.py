from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from typing import Any

from pydantic import Field

from cyberkimi.core import RiskTier, StrictModel, canonical_json, new_id, utc_now
from cyberkimi.errors import ScopeTokenError


class ScopeTokenClaims(StrictModel):
    token_id: str = Field(default_factory=lambda: new_id("SCOPE"))
    engagement_id: str
    engagement_revision: int = Field(ge=1)
    assets: dict[str, str]
    maximum_risk_tier: RiskTier
    engagement_flags: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    nonce: str


class ScopeTokenCodec:
    def __init__(self, signing_key: bytes) -> None:
        self._signing_key = signing_key

    def issue(self, claims: ScopeTokenClaims) -> str:
        header = {"alg": "HS256", "typ": "CK-SCOPE", "v": 1}
        header_part = _b64url(canonical_json(header).encode())
        payload_part = _b64url(canonical_json(claims).encode())
        signature = self._sign(f"{header_part}.{payload_part}".encode())
        return f"{header_part}.{payload_part}.{_b64url(signature)}"

    def verify(self, token: str, *, now: datetime | None = None) -> ScopeTokenClaims:
        try:
            header_part, payload_part, signature_part = token.split(".")
        except ValueError as exc:
            raise ScopeTokenError("scope token must have three segments") from exc
        signed = f"{header_part}.{payload_part}".encode()
        expected = self._sign(signed)
        try:
            actual = _b64url_decode(signature_part)
        except Exception as exc:
            raise ScopeTokenError("invalid scope token signature encoding") from exc
        if not hmac.compare_digest(expected, actual):
            raise ScopeTokenError("scope token signature mismatch")
        try:
            header = json.loads(_b64url_decode(header_part))
            payload: dict[str, Any] = json.loads(_b64url_decode(payload_part))
        except Exception as exc:
            raise ScopeTokenError("invalid scope token JSON") from exc
        if header != {"alg": "HS256", "typ": "CK-SCOPE", "v": 1}:
            raise ScopeTokenError("unsupported scope token header")
        claims = ScopeTokenClaims.model_validate(payload)
        check_time = now or utc_now()
        if claims.expires_at <= check_time:
            raise ScopeTokenError("scope token expired")
        if claims.issued_at > check_time:
            raise ScopeTokenError("scope token issued in the future")
        return claims

    def token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _sign(self, data: bytes) -> bytes:
        return hmac.new(self._signing_key, data, hashlib.sha256).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
