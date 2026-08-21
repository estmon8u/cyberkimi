"""Strict contracts shared by every CyberKimi trust boundary."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

JsonObject = dict[str, Any]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_assignment=True)


class AssuranceLevel(StrEnum):
    A0_UNVERIFIED = "A0_UNVERIFIED"
    A1_LOCAL_OWNER = "A1_LOCAL_OWNER"
    A2_ORG_APPROVED = "A2_ORG_APPROVED"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class RiskTier(IntEnum):
    R0_REASONING_ONLY = 0
    R1_LOCAL_READ_ONLY = 1
    R2_LOCAL_OBSERVATION = 2
    R3_BOUNDED_LAB_VALIDATION = 3

    def label(self) -> str:
        return self.name


class TaskMode(StrEnum):
    REVIEW = "review"
    HUNT = "hunt"
    LAB = "lab"


class AssetKind(StrEnum):
    REPOSITORY = "repository"
    SOURCE_SNAPSHOT = "source_snapshot"
    FILE = "file"
    DIRECTORY = "directory"
    LOG_BUNDLE = "log_bundle"
    PCAP = "pcap"
    SARIF = "sarif"
    SIGMA = "sigma"
    DOCKER_COMPOSE_LAB = "docker_compose_lab"


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    VALIDATED = "validated"
    SIGNED = "signed"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class DecisionCode(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    NEEDS_SCOPE_AMENDMENT = "NEEDS_SCOPE_AMENDMENT"
    NEEDS_DATA_POLICY_CHANGE = "NEEDS_DATA_POLICY_CHANGE"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RETRYABLE_TECHNICAL_ERROR = "RETRYABLE_TECHNICAL_ERROR"


class FindingState(StrEnum):
    SIGNAL = "signal"
    HYPOTHESIS = "hypothesis"
    SUPPORTED = "supported"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class ToolRunStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TOOL_UNAVAILABLE = "tool_unavailable"
    DENIED = "denied"
    TIMED_OUT = "timed_out"


class ProviderOutcome(StrEnum):
    STRUCTURED_SUCCESS = "structured_success"
    TRANSPORT_ERROR = "transport_error"
    SCHEMA_ERROR = "schema_error"
    PROVIDER_BOUNDARY = "provider_boundary"


class Budgets(StrictModel):
    max_parallel_subtasks: Annotated[int, Field(ge=1, le=16)] = 4
    max_subtask_depth: Annotated[int, Field(ge=0, le=4)] = 2
    max_subtasks_per_task: Annotated[int, Field(ge=1, le=64)] = 12
    max_model_turns_per_subtask: Annotated[int, Field(ge=1, le=32)] = 12
    max_tool_calls_per_subtask: Annotated[int, Field(ge=1, le=200)] = 40
    max_failed_tool_calls_per_subtask: Annotated[int, Field(ge=0, le=32)] = 6
    max_total_tool_runtime_seconds: Annotated[int, Field(ge=1, le=7200)] = 900
    max_single_tool_runtime_seconds: Annotated[int, Field(ge=1, le=600)] = 120
    max_artifact_bytes: Annotated[int, Field(ge=1024, le=2_000_000_000)] = 250_000_000
    max_context_recompositions: Annotated[int, Field(ge=0, le=2)] = 1
    max_schema_retries_per_call: Annotated[int, Field(ge=0, le=2)] = 1
    max_provider_policy_retries: Literal[0] = 0


class DataPolicy(StrictModel):
    classification: DataClassification = DataClassification.INTERNAL
    external_model_allowed: bool = False
    allowed_model_providers: tuple[str, ...] = ()
    provider_no_training_required: bool = False
    provider_no_training: bool = False
    redact_secrets_before_model: bool = True
    redact_pii_before_model: bool = True
    retain_raw_evidence_locally: bool = True
    persist_model_transcripts: bool = False

    def permits_provider(self, provider: str) -> bool:
        if self.classification is DataClassification.RESTRICTED:
            return False
        if not self.external_model_allowed or provider not in self.allowed_model_providers:
            return False
        if self.classification is DataClassification.CONFIDENTIAL:
            return self.provider_no_training_required and self.provider_no_training
        return True


class EndpointBinding(StrictModel):
    endpoint_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    scheme: Literal["http", "https"]
    host: str | None = Field(default=None, max_length=253)
    service: str | None = Field(default=None, max_length=100)
    port: int = Field(ge=1, le=65535)
    path_prefix: str = Field(default="/", pattern=r"^/")
    pinned_ips: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_host_or_service(self) -> "EndpointBinding":
        if bool(self.host) == bool(self.service):
            raise ValueError("exactly one of host or service is required")
        return self


class AssetBinding(StrictModel):
    git_commit: str | None = Field(default=None, max_length=128)
    dirty_tree_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    content_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    compose_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class Asset(StrictModel):
    asset_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*:[A-Za-z0-9_.-]+@[1-9][0-9]*$")
    kind: AssetKind
    locator_type: Literal["local_path", "compose_project"]
    canonical_locator: str = Field(min_length=1, max_length=4096)
    binding: AssetBinding
    allowed_effects: frozenset[str]
    data_classification: DataClassification
    endpoint_allowlist: tuple[EndpointBinding, ...] = ()
    status: Literal["active", "revoked"] = "active"


class Authorization(StrictModel):
    assurance_level: AssuranceLevel
    status: Literal["active", "revoked", "expired"]
    approver_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


class NetworkPolicy(StrictModel):
    default: Literal["DENY_ALL"] = "DENY_ALL"
    allowed_endpoint_ids: frozenset[str] = frozenset()


class Engagement(StrictModel):
    schema_version: Literal["cyberkimi.engagement/v1"] = "cyberkimi.engagement/v1"
    engagement_id: str = Field(pattern=r"^ENG-[A-Za-z0-9_.-]+$")
    revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=200)
    owner_id: str = Field(min_length=1, max_length=200)
    purpose: Literal["defensive_security_assessment"] = "defensive_security_assessment"
    created_at: datetime
    expires_at: datetime
    authorization: Authorization
    data_policy: DataPolicy
    risk_ceiling: RiskTier
    assets: tuple[Asset, ...]
    network_policy: NetworkPolicy = NetworkPolicy()
    prohibited_effects: frozenset[str] = frozenset(
        {
            "network.public",
            "persistence",
            "destructive",
            "credential.extract",
            "credential.return_plaintext",
            "stealth",
            "external_propagation",
            "third_party_targeting",
            "source.modify_original",
        }
    )
    budgets: Budgets = Budgets()
    status: EngagementStatus = EngagementStatus.ACTIVE

    @model_validator(mode="after")
    def validate_time_and_assets(self) -> "Engagement":
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        ids = [asset.asset_id for asset in self.assets]
        if len(ids) != len(set(ids)):
            raise ValueError("asset IDs must be unique within a revision")
        return self

    def asset(self, asset_id: str) -> Asset:
        for item in self.assets:
            if item.asset_id == asset_id:
                return item
        raise KeyError(asset_id)

    def active_at(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(timezone.utc)
        return (
            self.status is EngagementStatus.ACTIVE
            and self.authorization.status == "active"
            and self.created_at <= moment < self.expires_at
        )


class TaskSpec(StrictModel):
    task_id: str
    engagement_id: str
    engagement_revision: int = Field(ge=1)
    asset_id: str
    mode: TaskMode
    goal: str = Field(min_length=1, max_length=4000)
    allowed_effects: frozenset[str]
    risk_ceiling: RiskTier
    parent_task_id: str | None = None
    depth: int = Field(default=0, ge=0, le=4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: Literal["pending", "running", "completed", "failed", "cancelled"] = "pending"


class ScopeClaims(StrictModel):
    iss: Literal["cyberkimi-scope-service"] = "cyberkimi-scope-service"
    aud: Literal["cyberkimi-control-plane"] = "cyberkimi-control-plane"
    engagement_id: str
    engagement_revision: int
    task_id: str
    asset_digests: dict[str, str]
    allowed_effects: frozenset[str]
    risk_ceiling: RiskTier
    policy_version: str = "policy/v1.0.0"
    iat: int
    exp: int
    nonce: str


class ToolRuntime(StrictModel):
    timeout_seconds_max: int = Field(default=60, ge=1, le=600)
    cpu_cores_max: float = Field(default=1.0, gt=0, le=8)
    memory_mb_max: int = Field(default=512, ge=64, le=8192)
    pids_max: int = Field(default=64, ge=8, le=1024)
    output_bytes_max: int = Field(default=5_000_000, ge=1024, le=100_000_000)


class ToolManifest(StrictModel):
    schema_version: Literal["cyberkimi.tool/v1"] = "cyberkimi.tool/v1"
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    api_name: str = Field(pattern=r"^[A-Za-z0-9_-]+$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    category: str
    description: str
    modes: frozenset[TaskMode]
    minimum_risk: RiskTier
    maximum_effects: frozenset[str]
    accepted_asset_kinds: frozenset[AssetKind]
    default_approval_required: bool = False
    network_mode: Literal["DENY_ALL", "LAB_ALLOWLIST"] = "DENY_ALL"
    source_mount: Literal["NONE", "READ_ONLY"] = "READ_ONLY"
    scratch_mount: Literal["NONE", "READ_WRITE"] = "NONE"
    runtime: ToolRuntime = ToolRuntime()
    arguments_schema: JsonObject
    output_schema_id: str
    adapter: str

    @property
    def template_id(self) -> str:
        return f"{self.name}@{self.version}"


class DeploymentProfile(StrictModel):
    profile_id: str
    tool_template_id: str
    timeout_seconds: int = Field(ge=1, le=600)
    memory_mb: int = Field(ge=64, le=8192)
    output_bytes: int = Field(ge=1024, le=100_000_000)
    network_mode: Literal["DENY_ALL", "LAB_ALLOWLIST"]
    source_mount: Literal["NONE", "READ_ONLY"]
    effects: frozenset[str]
    risk_floor: RiskTier


class BudgetReservation(StrictModel):
    reservation_id: str
    tool_calls: int = Field(default=1, ge=1)
    runtime_seconds: int = Field(ge=1)
    artifact_bytes: int = Field(default=0, ge=0)


class ProposedAction(StrictModel):
    action_id: str
    task_id: str
    subtask_id: str | None = None
    tool_template_id: str
    tool_manifest_digest: str
    asset_id: str
    asset_binding_digest: str
    arguments: JsonObject
    requested_effects: frozenset[str]
    risk_tier: RiskTier
    budget: BudgetReservation
    scope_token_digest: str
    operator_profile: str


class ApprovalRecord(StrictModel):
    approval_id: str
    action_digest: str
    actor_id: str
    decision: Literal["approved", "denied"]
    issued_at: datetime
    expires_at: datetime
    single_use: bool = True
    authentication_level: Literal["local_session", "organization"] = "local_session"
    comment: str = ""
    consumed_at: datetime | None = None


class ExecutionGrant(StrictModel):
    grant_id: str
    action_digest: str
    tool_manifest_digest: str
    asset_binding_digest: str
    operator_profile: str
    budget_reservation_id: str
    approval_id: str | None = None
    iat: int
    exp: int
    single_use: bool = True
    nonce: str


class PolicyDecision(StrictModel):
    code: DecisionCode
    reason: str
    action_digest: str
    effective_risk: RiskTier
    effective_effects: frozenset[str]
    requires_approval: bool = False
    policy_version: str = "policy/v1.0.0"


class ToolResult(StrictModel):
    status: ToolRunStatus
    tool_template_id: str
    started_at: datetime
    completed_at: datetime
    exit_code: int | None = None
    structured: JsonObject = Field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False
    error_code: str | None = None


class ArtifactRecord(StrictModel):
    artifact_id: str
    digest: str
    media_type: str
    size_bytes: int
    local_path: str
    created_at: datetime
    tool_run_id: str | None = None


class EvidenceEnvelope(StrictModel):
    evidence_id: str
    engagement_id: str
    engagement_revision: int
    task_id: str
    asset_id: str
    asset_binding_digest: str
    tool_template_id: str
    tool_manifest_digest: str
    tool_run_id: str
    artifact_digest: str
    evidence_type: str
    summary: str
    excerpt: str
    secret_refs: tuple[str, ...] = ()
    content_hash: str
    created_at: datetime
    provenance: JsonObject


class VerificationVerdict(StrictModel):
    verifier_id: str
    verdict: Literal["confirm", "reject", "unresolved"]
    rationale: str
    checked_evidence_ids: tuple[str, ...]
    missing_requirements: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(StrictModel):
    finding_id: str
    engagement_id: str
    engagement_revision: int
    task_id: str
    asset_id: str
    finding_type: str
    claim: str
    state: FindingState
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    evidence_policy_id: str
    evidence_ids: tuple[str, ...]
    verifier_verdict: VerificationVerdict | None = None
    remediation: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RetryClassification(StrEnum):
    TRANSPORT = "transport"
    RATE_LIMIT = "rate_limit"
    MALFORMED_SCHEMA = "malformed_schema"
    MISSING_TOOL_HISTORY = "missing_tool_history"
    CONTEXT_TOO_LARGE = "context_too_large"
    PROVIDER_POLICY = "provider_policy"
    PERMANENT = "permanent"


class ModelCallRecord(StrictModel):
    provider: str
    model: str
    role: Literal["director", "worker", "verifier", "reporter"]
    reasoning_effort: Literal["low", "high", "max"]
    task_id: str
    subtask_id: str | None = None
    prompt_version: str
    schema_version: str
    prompt_fingerprint: str
    response_fingerprint: str
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    tool_count_exposed: int = Field(ge=0, le=8)
    latency_ms: int = Field(ge=0)
    result: ProviderOutcome
    session_id: str


class HealthReport(StrictModel):
    state_directory: str
    database_ok: bool
    signing_key_ok: bool
    vault_key_ok: bool
    audit_chain_ok: bool
    optional_tools: dict[str, bool]
