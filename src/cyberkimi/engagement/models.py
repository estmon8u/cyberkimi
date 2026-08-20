from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from cyberkimi.core import (
    AccessMode,
    AssetType,
    DataClassification,
    RiskTier,
    StrictModel,
    TrustProfile,
)


EffectName = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")]
AssetAlias = Annotated[
    str,
    Field(
        min_length=3,
        max_length=256,
        pattern=r"^(repo|build|logs|pcap|lab|service):[A-Za-z0-9][A-Za-z0-9_.-]*$",
    ),
]


class EngagementInfo(StrictModel):
    id: Annotated[str, Field(min_length=3, max_length=128, pattern=r"^ENG-[A-Za-z0-9_.-]+$")]
    name: Annotated[str, Field(min_length=1, max_length=256)]
    owner: Annotated[str, Field(min_length=1, max_length=256)]
    purpose: Literal["defensive_security_assessment", "incident_response", "security_research"]
    created_at: datetime
    expires_at: datetime
    flags: frozenset[str] = frozenset()
    revision: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_dates(self) -> "EngagementInfo":
        if self.expires_at <= self.created_at:
            raise ValueError("engagement.expires_at must be after created_at")
        return self


class AuthorizationSpec(StrictModel):
    basis: Literal[
        "local_owner_attestation",
        "written_authorization",
        "contractual_authorization",
        "training_environment",
    ]
    status: Literal["self_attested", "verified", "pending"]
    approver: Annotated[str, Field(min_length=1, max_length=256)]
    evidence: tuple[str, ...] = ()
    auto_approve_within_scope: bool = False
    allow_harness_asset_progression: bool = False

    @model_validator(mode="after")
    def validate_auto_approval(self) -> "AuthorizationSpec":
        if self.auto_approve_within_scope and self.status not in {"self_attested", "verified"}:
            raise ValueError("auto approval requires self_attested or verified authorization")
        return self


class NetworkDeclaration(StrictModel):
    network_id: str | None = None
    permitted: bool = False
    allowed_hosts: tuple[str, ...] = ()
    allowed_cidrs: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("network ports must be between 1 and 65535")
        return ports


class AssetDeclaration(StrictModel):
    id: AssetAlias
    type: AssetType
    location: str
    access: AccessMode = AccessMode.READ_ONLY
    data_classification: DataClassification = DataClassification.INTERNAL
    trust_domain: str = "local"
    allowed_effects: frozenset[EffectName] = frozenset()
    network: NetworkDeclaration = NetworkDeclaration()
    content_digest: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("location")
    @classmethod
    def nonempty_location(cls, location: str) -> str:
        if not location.strip():
            raise ValueError("asset location cannot be empty")
        return location


class RepositoryDeclaration(StrictModel):
    id: AssetAlias
    path: str
    access: AccessMode = AccessMode.READ_ONLY
    data_classification: DataClassification = DataClassification.INTERNAL
    allowed_effects: frozenset[EffectName] = frozenset(
        {"file.read", "file.search", "scanner.execute", "artifact.read", "evidence.write"}
    )
    trust_domain: str = "local"
    content_digest: str | None = None

    def to_asset(self) -> AssetDeclaration:
        return AssetDeclaration(
            id=self.id,
            type=AssetType.REPOSITORY,
            location=self.path,
            access=self.access,
            data_classification=self.data_classification,
            trust_domain=self.trust_domain,
            allowed_effects=self.allowed_effects,
            content_digest=self.content_digest,
        )


class RuntimeEnvironmentDeclaration(StrictModel):
    id: AssetAlias
    type: Literal["docker_compose", "docker", "local_vm", "training_target"]
    location: str | None = None
    compose_file: str | None = None
    network: str | None = None
    access: AccessMode = AccessMode.ACTIVE_VALIDATION
    data_classification: DataClassification = DataClassification.INTERNAL
    allowed_effects: frozenset[EffectName] = frozenset(
        {
            "process.local",
            "container.read",
            "network.observed",
            "evidence.write",
        }
    )
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    trust_domain: str = "engagement_lab"

    def to_asset(self) -> AssetDeclaration:
        location = self.location or self.compose_file or self.id
        return AssetDeclaration(
            id=self.id,
            type=AssetType.LAB,
            location=location,
            access=self.access,
            data_classification=self.data_classification,
            trust_domain=self.trust_domain,
            allowed_effects=self.allowed_effects,
            network=NetworkDeclaration(
                network_id=self.network,
                permitted=True,
                allowed_hosts=self.allowed_hosts,
                allowed_ports=self.allowed_ports,
            ),
            metadata={"runtime_type": self.type, "compose_file": self.compose_file},
        )


class LogSourceDeclaration(StrictModel):
    id: AssetAlias
    path: str
    format: Literal["auto", "json", "jsonl", "csv", "text"] = "auto"
    data_classification: DataClassification = DataClassification.INTERNAL
    allowed_effects: frozenset[EffectName] = frozenset(
        {"file.read", "artifact.read", "parser.execute", "evidence.write"}
    )

    def to_asset(self) -> AssetDeclaration:
        return AssetDeclaration(
            id=self.id,
            type=AssetType.LOG_SOURCE,
            location=self.path,
            access=AccessMode.READ_ONLY,
            data_classification=self.data_classification,
            allowed_effects=self.allowed_effects,
            metadata={"format": self.format},
        )


class ScopeSpec(StrictModel):
    assets: tuple[AssetDeclaration, ...] = ()
    repositories: tuple[RepositoryDeclaration, ...] = ()
    runtime_environments: tuple[RuntimeEnvironmentDeclaration, ...] = ()
    log_sources: tuple[LogSourceDeclaration, ...] = ()
    public_internet_permitted: bool = False

    def normalized_assets(self) -> tuple[AssetDeclaration, ...]:
        combined = [*self.assets]
        combined.extend(repo.to_asset() for repo in self.repositories)
        combined.extend(runtime.to_asset() for runtime in self.runtime_environments)
        combined.extend(logs.to_asset() for logs in self.log_sources)
        aliases = [asset.id for asset in combined]
        if len(aliases) != len(set(aliases)):
            raise ValueError("asset aliases must be unique within an engagement")
        return tuple(combined)


class BudgetLimits(StrictModel):
    max_parallel_tasks: int = Field(ge=1, le=32)
    max_model_turns_per_task: int = Field(ge=1, le=128)
    max_tool_calls_per_task: int = Field(ge=1, le=500)
    max_tool_runtime_seconds: int = Field(ge=1, le=7200)
    max_artifact_bytes: int = Field(ge=1, le=5_000_000_000)
    max_retry_attempts: int = Field(ge=0, le=50)
    max_subtasks_per_task: int = Field(default=32, ge=1, le=256)
    max_engagement_tool_calls: int = Field(default=10_000, ge=1, le=100_000)
    max_engagement_artifact_bytes: int = Field(
        default=20_000_000_000, ge=1, le=100_000_000_000
    )


DEFAULT_BUDGET = BudgetLimits(
    max_parallel_tasks=4,
    max_model_turns_per_task=16,
    max_tool_calls_per_task=60,
    max_tool_runtime_seconds=300,
    max_artifact_bytes=100_000_000,
    max_retry_attempts=3,
    max_subtasks_per_task=16,
    max_engagement_tool_calls=2_000,
    max_engagement_artifact_bytes=2_000_000_000,
)
EXTENDED_BUDGET = BudgetLimits(
    max_parallel_tasks=16,
    max_model_turns_per_task=64,
    max_tool_calls_per_task=240,
    max_tool_runtime_seconds=3600,
    max_artifact_bytes=1_000_000_000,
    max_retry_attempts=20,
    max_subtasks_per_task=64,
    max_engagement_tool_calls=20_000,
    max_engagement_artifact_bytes=20_000_000_000,
)
COMPREHENSIVE_BUDGET = BudgetLimits(
    max_parallel_tasks=32,
    max_model_turns_per_task=128,
    max_tool_calls_per_task=500,
    max_tool_runtime_seconds=7200,
    max_artifact_bytes=5_000_000_000,
    max_retry_attempts=50,
    max_subtasks_per_task=128,
    max_engagement_tool_calls=50_000,
    max_engagement_artifact_bytes=50_000_000_000,
)


class BudgetProfile(StrictModel):
    name: Literal["default", "extended", "comprehensive"]
    requires_engagement_flag: str | None = None
    limits: BudgetLimits


class BudgetConfiguration(StrictModel):
    selected: Literal["default", "extended", "comprehensive"] = "default"
    default: BudgetLimits = DEFAULT_BUDGET
    extended: BudgetLimits = EXTENDED_BUDGET
    comprehensive: BudgetLimits = COMPREHENSIVE_BUDGET

    def selected_profile(self) -> BudgetProfile:
        if self.selected == "default":
            return BudgetProfile(name="default", limits=self.default)
        if self.selected == "extended":
            return BudgetProfile(
                name="extended",
                requires_engagement_flag="extended_operations",
                limits=self.extended,
            )
        return BudgetProfile(
            name="comprehensive",
            requires_engagement_flag="comprehensive_assessment",
            limits=self.comprehensive,
        )


class DataHandlingSpec(StrictModel):
    redact_secrets_before_model: bool = True
    retain_raw_evidence_locally: bool = True
    send_raw_secrets_to_model: bool = False
    redact_pii_for_confidential: bool = True

    @model_validator(mode="after")
    def prohibit_raw_secret_transmission(self) -> "DataHandlingSpec":
        if self.send_raw_secrets_to_model:
            raise ValueError("CyberKimi v0.1 never sends raw secrets to a model")
        return self


class EngagementManifest(StrictModel):
    engagement: EngagementInfo
    authorization: AuthorizationSpec
    scope: ScopeSpec
    allowed_capabilities: dict[str, bool | Literal["approval_required"]] = Field(
        default_factory=dict
    )
    prohibited_capabilities: dict[str, bool] = Field(default_factory=dict)
    budgets: BudgetConfiguration = BudgetConfiguration()
    data_handling: DataHandlingSpec = DataHandlingSpec()
    maximum_risk_tier: RiskTier = RiskTier.R3_ACTIVE_VALIDATION
    allowed_trust_profiles: frozenset[TrustProfile] = frozenset({TrustProfile.RESTRICTED})

    @model_validator(mode="after")
    def validate_manifest(self) -> "EngagementManifest":
        self.scope.normalized_assets()
        profile = self.budgets.selected_profile()
        if profile.requires_engagement_flag and profile.requires_engagement_flag not in self.engagement.flags:
            raise ValueError(
                f"budget profile {profile.name!r} requires engagement flag "
                f"{profile.requires_engagement_flag!r}"
            )
        if self.maximum_risk_tier == RiskTier.R4_EXTENDED_OPERATIONS and (
            "extended_operations" not in self.engagement.flags
            and "comprehensive_assessment" not in self.engagement.flags
        ):
            raise ValueError("R4 requires extended_operations or comprehensive_assessment")
        if TrustProfile.ELEVATED in self.allowed_trust_profiles and "elevated_tools" not in self.engagement.flags:
            raise ValueError("ELEVATED trust profile requires elevated_tools")
        if (
            TrustProfile.COMPREHENSIVE in self.allowed_trust_profiles
            and "comprehensive_assessment" not in self.engagement.flags
        ):
            raise ValueError("COMPREHENSIVE trust profile requires comprehensive_assessment")
        return self

    @property
    def id(self) -> str:
        return self.engagement.id

    @property
    def revision(self) -> int:
        return self.engagement.revision

    def has_flag(self, flag: str) -> bool:
        return flag in self.engagement.flags

    def authorization_allows_auto_approval(self) -> bool:
        return self.authorization.auto_approve_within_scope and self.authorization.status in {
            "self_attested",
            "verified",
        }
