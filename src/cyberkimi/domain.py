from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Mode(StrEnum):
    REVIEW = "review"
    HUNT = "hunt"
    LAB = "lab"


class RiskTier(IntEnum):
    R0_REASONING = 0
    R1_READ_ONLY = 1
    R2_OBSERVATION = 2
    R3_BOUNDED_VALIDATION = 3
    R4_EXTENDED = 4


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class TrustProfile(StrEnum):
    RESTRICTED = "restricted"
    ELEVATED = "elevated"
    COMPREHENSIVE = "comprehensive"


class TaskState(StrEnum):
    READY = "ready"
    NEEDS_SCOPE = "needs_scope"
    NEEDS_AUTHORIZATION = "needs_authorization"
    NEEDS_EVIDENCE = "needs_evidence"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    PROVIDER_BOUNDARY = "provider_boundary"
    PROVIDER_BOUNDARY_EXHAUSTED = "provider_boundary_exhausted"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingState(StrEnum):
    SIGNAL = "signal"
    HYPOTHESIS = "hypothesis"
    SUPPORTED = "supported"
    REPRODUCED = "reproduced"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    DISPUTED = "disputed"
    UNRESOLVED = "unresolved"


class BudgetLimits(StrictModel):
    max_parallel_tasks: int = Field(ge=1, le=32)
    max_model_turns_per_task: int = Field(ge=1, le=128)
    max_tool_calls_per_task: int = Field(ge=1, le=500)
    max_tool_runtime_seconds: int = Field(ge=1, le=7200)
    max_artifact_bytes: int = Field(ge=1, le=5_000_000_000)
    max_retry_attempts: int = Field(ge=0, le=50)


DEFAULT_BUDGET = BudgetLimits(
    max_parallel_tasks=4,
    max_model_turns_per_task=16,
    max_tool_calls_per_task=60,
    max_tool_runtime_seconds=300,
    max_artifact_bytes=100_000_000,
    max_retry_attempts=3,
)

EXTENDED_BUDGET = BudgetLimits(
    max_parallel_tasks=16,
    max_model_turns_per_task=64,
    max_tool_calls_per_task=240,
    max_tool_runtime_seconds=3600,
    max_artifact_bytes=1_000_000_000,
    max_retry_attempts=20,
)

COMPREHENSIVE_BUDGET = BudgetLimits(
    max_parallel_tasks=32,
    max_model_turns_per_task=128,
    max_tool_calls_per_task=500,
    max_tool_runtime_seconds=7200,
    max_artifact_bytes=5_000_000_000,
    max_retry_attempts=50,
)


class EngagementRevision(StrictModel):
    engagement_id: str = Field(min_length=3)
    revision: int = Field(ge=1)
    owner: str = Field(min_length=1)
    purpose: Literal["defensive_security_assessment"] = "defensive_security_assessment"
    authorization_basis: str = Field(min_length=1)
    authorization_status: str = Field(min_length=1)
    approver: str = Field(min_length=1)
    created_at: datetime
    expires_at: datetime
    maximum_risk_tier: RiskTier = RiskTier.R1_READ_ONLY
    capability_flags: frozenset[str] = frozenset()
    prohibited_effects: frozenset[str] = frozenset(
        {
            "persistence",
            "destructive",
            "credential.extraction",
            "stealth",
            "external.propagation",
            "third_party.targeting",
        }
    )
    budget: BudgetLimits = DEFAULT_BUDGET
    self_attested_approvals: bool = False

    @model_validator(mode="after")
    def validate_time_window(self) -> "EngagementRevision":
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("engagement timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self

    def active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return self.created_at <= current < self.expires_at

    @property
    def versioned_id(self) -> str:
        return f"{self.engagement_id}@{self.revision}"


class AssetRevision(StrictModel):
    asset_alias: str = Field(pattern=r"^[a-z][a-z0-9_-]*:[A-Za-z0-9._-]+$")
    revision: int = Field(ge=1)
    engagement_id: str = Field(min_length=3)
    asset_type: Literal["repository", "logs", "lab"]
    canonical_location: str = Field(min_length=1)
    trust_domain: str = Field(min_length=1)
    content_revision: str = Field(min_length=1)
    allowed_effects: frozenset[str]
    data_classification: DataClassification = DataClassification.INTERNAL
    network_identifiers: tuple[str, ...] = ()
    authorization_evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    signature: str = Field(min_length=16)

    @property
    def versioned_id(self) -> str:
        return f"{self.asset_alias}@{self.revision}"


class ToolProfile(StrictModel):
    name: str = Field(min_length=1)
    risk_tier: RiskTier
    effects: frozenset[str]
    network: bool = False
    filesystem: Literal["read_only", "read_write"] = "read_only"
    timeout_seconds: int = Field(ge=1, le=7200)
    trust_profile: TrustProfile = TrustProfile.RESTRICTED
    requires_engagement_flag: str | None = None
    additional_operations: tuple[str, ...] = ()


class ToolManifest(StrictModel):
    internal_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]+@[0-9]+\.[0-9]+\.[0-9]+$")
    kimi_alias: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    category: str
    accepted_asset_types: frozenset[Literal["repository", "logs", "lab"]]
    base_profile: ToolProfile
    authorized_profiles: tuple[ToolProfile, ...] = ()
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]

    @model_validator(mode="after")
    def unique_profiles(self) -> "ToolManifest":
        names = [self.base_profile.name, *(p.name for p in self.authorized_profiles)]
        if len(names) != len(set(names)):
            raise ValueError("deployment profile names must be unique")
        return self


class ProposedAction(StrictModel):
    action_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    engagement_id: str = Field(min_length=3)
    action_template: str = Field(min_length=1)
    target_asset_id: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = Field(min_length=1)
    requested_effects: frozenset[str]
    requested_timeout_seconds: int = Field(ge=1, le=7200)


class NumericRange(StrictModel):
    minimum: float | None = None
    maximum: float | None = None

    @model_validator(mode="after")
    def ordered(self) -> "NumericRange":
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum cannot exceed maximum")
        return self

    def contains(self, value: float) -> bool:
        return (self.minimum is None or value >= self.minimum) and (
            self.maximum is None or value <= self.maximum
        )


class ActionApproval(StrictModel):
    approval_id: str
    engagement_id: str
    action_template: str
    target_asset_revision: str
    tool_internal_id: str
    allowed_effects: frozenset[str]
    numeric_ranges: dict[str, NumericRange] = Field(default_factory=dict)
    allowed_values: dict[str, frozenset[str]] = Field(default_factory=dict)
    actor: str
    issued_at: datetime
    expires_at: datetime
    auto_granted: bool = False

    def permits_arguments(self, arguments: dict[str, Any]) -> bool:
        for key, constraint in self.numeric_ranges.items():
            value = arguments.get(key)
            if not isinstance(value, (int, float)) or not constraint.contains(float(value)):
                return False
        for key, values in self.allowed_values.items():
            value = arguments.get(key)
            if not isinstance(value, str) or value not in values:
                return False
        return True


class ExecutionGrant(StrictModel):
    grant_id: str
    nonce: str
    engagement_revision: str
    asset_revision: str
    action_id: str
    tool_internal_id: str
    deployment_profile: str
    effective_effects: frozenset[str]
    effective_timeout_seconds: int
    issued_at: datetime
    expires_at: datetime
    signature: str


class PolicyDecision(StrictModel):
    permitted: bool
    reason_code: str
    evaluation_pass: int
    selected_profile: str | None = None
    requires_approval: bool = False
    grant: ExecutionGrant | None = None
    adjustments: tuple[dict[str, Any], ...] = ()


class EvidenceRecord(StrictModel):
    evidence_id: str
    task_id: str
    asset_revision: str
    evidence_type: str
    evidence_class: str
    payload: dict[str, Any]
    artifact_sha256: str | None = None
    source_session_id: str | None = None
    created_at: datetime


class VerificationResult(StrictModel):
    verdict: Literal["confirmed", "rejected", "unresolved"]
    claim_supported: bool
    impact_supported: bool
    missing_evidence: tuple[str, ...] = ()
    alternative_explanations: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)


@field_validator("created_at", "issued_at", "expires_at", mode="before", check_fields=False)
def _parse_datetime(value: Any) -> Any:
    return value
