from __future__ import annotations

import copy
import re
from typing import Any

from cyberkimi.core import DataClassification
from cyberkimi.evidence.models import ModelEvidence


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key", re.compile(r"(?i)['\"]?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{12,})")),
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_secrets(text: str) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for secret_type, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if value and len(value) >= 8:
                found.append((secret_type, value))
    unique: dict[tuple[str, str], None] = {}
    for item in found:
        unique[item] = None
    return tuple(unique)


def redact_text(text: str, *, redact_pii: bool) -> tuple[str, int]:
    redactions = 0
    output = text
    for secret_type, pattern in _SECRET_PATTERNS:
        def replacement(match: re.Match[str]) -> str:
            nonlocal redactions
            redactions += 1
            prefix = match.group(0)
            if match.lastindex:
                value = match.group(1)
                return prefix.replace(value, f"<REDACTED:{secret_type}>")
            return f"<REDACTED:{secret_type}>"
        output = pattern.sub(replacement, output)
    if redact_pii:
        output, email_count = _EMAIL.subn("<REDACTED:email>", output)
        output, ip_count = _IPV4.subn("<REDACTED:ip>", output)
        redactions += email_count + ip_count
    return output, redactions


def prepare_for_model(payload: dict[str, Any], classification: DataClassification) -> ModelEvidence:
    if classification == DataClassification.RESTRICTED:
        return ModelEvidence(
            classification=classification,
            content={
                "kind": "restricted_security_summary",
                "keys": sorted(payload),
                "item_count": _count_items(payload),
                "security_labels": _security_labels(payload),
            },
            redactions=0,
            restricted_summary=True,
        )
    redactions = 0
    result = copy.deepcopy(payload)
    redact_pii = classification == DataClassification.CONFIDENTIAL

    def transform(value: Any) -> Any:
        nonlocal redactions
        if isinstance(value, str):
            cleaned, count = redact_text(value, redact_pii=redact_pii)
            redactions += count
            return cleaned
        if isinstance(value, list):
            return [transform(item) for item in value]
        if isinstance(value, tuple):
            return [transform(item) for item in value]
        if isinstance(value, dict):
            return {str(key): transform(item) for key, item in value.items()}
        return value

    result = transform(result)
    return ModelEvidence(
        classification=classification,
        content=result,
        redactions=redactions,
        restricted_summary=False,
    )


def _count_items(value: Any) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_count_items(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return len(value) + sum(_count_items(item) for item in value)
    return 1


def _security_labels(payload: dict[str, Any]) -> list[str]:
    text = str(payload).lower()
    labels = [
        label
        for label in ("secret", "dependency", "authorization", "configuration", "runtime", "log")
        if label in text
    ]
    return labels or ["security_evidence"]
