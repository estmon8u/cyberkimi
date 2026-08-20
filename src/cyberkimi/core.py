from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Default contract for data crossing a CyberKimi trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True)


class MutableModel(BaseModel):
    """Strict model for runtime state that is intentionally mutable."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=True)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value) if all(isinstance(item, str) for item in value) else list(value)
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def fingerprint(value: Any) -> str:
    return f"sha256:{sha256_text(canonical_json(value))}"


def new_id(prefix: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_-]", "", prefix).upper()
    return f"{clean}-{secrets.token_hex(8).upper()}"


def ensure_relative_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path must be relative and may not contain '..'")
    return candidate


class RiskTier(StrEnum):
    R0_REASONING = "R0_REASONING"
    R1_READ_ONLY = "R1_READ_ONLY"
    R2_OBSERVATION = "R2_OBSERVATION"
    R3_ACTIVE_VALIDATION = "R3_ACTIVE_VALIDATION"
    R4_EXTENDED_OPERATIONS = "R4_EXTENDED_OPERATIONS"

    @property
    def rank(self) -> int:
        return {
            RiskTier.R0_REASONING: 0,
            RiskTier.R1_READ_ONLY: 1,
            RiskTier.R2_OBSERVATION: 2,
            RiskTier.R3_ACTIVE_VALIDATION: 3,
            RiskTier.R4_EXTENDED_OPERATIONS: 4,
        }[self]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank < other.rank


class AssetType(StrEnum):
    REPOSITORY = "repository"
    BUILD_ARTIFACT = "build_artifact"
    LOG_SOURCE = "log_source"
    PACKET_CAPTURE = "packet_capture"
    LAB = "lab"
    SERVICE = "service"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class AccessMode(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ACTIVE_VALIDATION = "active_validation"


class TrustProfile(StrEnum):
    RESTRICTED = "RESTRICTED"
    ELEVATED = "ELEVATED"
    COMPREHENSIVE = "COMPREHENSIVE"


class TaskMode(StrEnum):
    REVIEW = "review"
    HUNT = "hunt"
    LAB = "lab"


class DecisionKind(StrEnum):
    PERMIT = "permit"
    REQUIRE_APPROVAL = "require_approval"
    ADJUST_CONFIGURATION = "adjust_configuration"
    DECOMPOSE = "decompose"
    DENY = "deny"


class TaskStatus(StrEnum):
    READY = "ready"
    NEEDS_SCOPE = "needs_scope"
    NEEDS_AUTHORIZATION = "needs_authorization"
    NEEDS_EVIDENCE = "needs_evidence"
    SANDBOX_ONLY = "sandbox_only"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    EXTENDED_OPERATION = "extended_operation"
    PROVIDER_BOUNDARY = "provider_boundary"
    PROVIDER_BOUNDARY_EXHAUSTED = "provider_boundary_exhausted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingState(StrEnum):
    SIGNAL = "SIGNAL"
    HYPOTHESIS = "HYPOTHESIS"
    SUPPORTED = "SUPPORTED"
    REPRODUCED = "REPRODUCED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"


class VerificationVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class NonResponseCategory(StrEnum):
    HTTP_ERROR = "HTTP_ERROR"
    RATE_LIMIT = "RATE_LIMIT"
    TOOL_SCHEMA_ERROR = "TOOL_SCHEMA_ERROR"
    TOOL_CALL_ID_ERROR = "TOOL_CALL_ID_ERROR"
    CONTEXT_FORMAT_ERROR = "CONTEXT_FORMAT_ERROR"
    MODEL_REFUSAL = "MODEL_REFUSAL"
    PROVIDER_POLICY = "PROVIDER_POLICY"
    TERMINOLOGY_AMBIGUITY = "TERMINOLOGY_AMBIGUITY"
    CONTEXT_TOO_BROAD = "CONTEXT_TOO_BROAD"
    TIMEOUT = "TIMEOUT"
    MISSING_AUTH_CONTEXT = "MISSING_AUTH_CONTEXT"
    AMBIGUOUS_TARGET = "AMBIGUOUS_TARGET"
    ACTIVE_ACTION_REQUIRES_ENV = "ACTIVE_ACTION_REQUIRES_ENV"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    UNKNOWN = "UNKNOWN"
