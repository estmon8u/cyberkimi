from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .domain import DataClassification


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    ),
    (
        "assignment_secret",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*"
            r"(['\"]?)([^\s,'\";]{8,})\2"
        ),
    ),
    (
        "github_token",
        re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    ),
)

PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("us_phone", re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}(?!\d)")),
)


@dataclass(frozen=True)
class VaultCandidate:
    kind: str
    fingerprint: str
    value: str


@dataclass(frozen=True)
class ModelContent:
    classification: DataClassification
    text: str
    transformed: bool
    redaction_count: int
    vault_candidates: tuple[VaultCandidate, ...]


def _placeholder(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"<REDACTED:{kind}:{digest}>"


def redact_sensitive(text: str, *, include_pii: bool = True) -> ModelContent:
    candidates: list[VaultCandidate] = []
    redaction_count = 0
    transformed = text

    for kind, pattern in SECRET_PATTERNS:
        def replace_secret(match: re.Match[str], *, kind: str = kind) -> str:
            nonlocal redaction_count
            value = match.group(0)
            fingerprint = hashlib.sha256(value.encode()).hexdigest()
            candidates.append(VaultCandidate(kind=kind, fingerprint=fingerprint, value=value))
            redaction_count += 1
            return _placeholder(kind, value)

        transformed = pattern.sub(replace_secret, transformed)

    if include_pii:
        for kind, pattern in PII_PATTERNS:
            def replace_pii(match: re.Match[str], *, kind: str = kind) -> str:
                nonlocal redaction_count
                value = match.group(0)
                redaction_count += 1
                return _placeholder(kind, value)

            transformed = pattern.sub(replace_pii, transformed)

    return ModelContent(
        classification=DataClassification.CONFIDENTIAL,
        text=transformed,
        transformed=transformed != text,
        redaction_count=redaction_count,
        vault_candidates=tuple(candidates),
    )


def restricted_summary(text: str, *, maximum_lines: int = 40) -> str:
    """Create a deterministic fact-only summary without transmitting raw restricted text."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    indicators: list[dict[str, Any]] = []
    for index, line in enumerate(lines[:500], start=1):
        lowered = line.lower()
        categories = [
            category
            for category, markers in {
                "authorization": ("authorize", "permission", "ownership", "access control"),
                "authentication": ("login", "authenticate", "credential", "session"),
                "secret_material": ("password", "token", "api key", "private key"),
                "network": ("http", "socket", "port", "host"),
                "error": ("error", "exception", "failed", "denied"),
            }.items()
            if any(marker in lowered for marker in markers)
        ]
        if categories:
            indicators.append(
                {
                    "line_index": index,
                    "categories": categories,
                    "length": len(line),
                    "sha256": hashlib.sha256(line.encode()).hexdigest(),
                }
            )
        if len(indicators) >= maximum_lines:
            break
    return (
        "RESTRICTED_CONTENT_SUMMARY\n"
        f"byte_count={len(text.encode())}\n"
        f"line_count={len(lines)}\n"
        f"content_sha256={hashlib.sha256(text.encode()).hexdigest()}\n"
        f"security_indicators={indicators!r}"
    )


def prepare_for_model(classification: DataClassification, text: str) -> ModelContent:
    if classification in {DataClassification.PUBLIC, DataClassification.INTERNAL}:
        return ModelContent(
            classification=classification,
            text=text,
            transformed=False,
            redaction_count=0,
            vault_candidates=(),
        )
    if classification == DataClassification.CONFIDENTIAL:
        redacted = redact_sensitive(text, include_pii=True)
        return ModelContent(
            classification=classification,
            text=redacted.text,
            transformed=redacted.transformed,
            redaction_count=redacted.redaction_count,
            vault_candidates=redacted.vault_candidates,
        )
    redacted = redact_sensitive(restricted_summary(text), include_pii=True)
    return ModelContent(
        classification=classification,
        text=redacted.text,
        transformed=True,
        redaction_count=redacted.redaction_count,
        vault_candidates=redacted.vault_candidates,
    )
