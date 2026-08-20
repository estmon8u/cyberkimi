from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from cyberkimi.core import utc_now


class Base(DeclarativeBase):
    pass


class EngagementRow(Base):
    __tablename__ = "engagements"
    __table_args__ = (UniqueConstraint("engagement_id", "revision"),)

    row_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    manifest_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest_hash: Mapped[str] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AssetRevisionRow(Base):
    __tablename__ = "asset_revisions"
    __table_args__ = (UniqueConstraint("asset_alias", "revision"),)

    row_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_alias: Mapped[str] = mapped_column(String(256), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    versioned_id: Mapped[str] = mapped_column(String(300), unique=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(64))
    canonical_location: Mapped[str] = mapped_column(Text)
    access_mode: Mapped[str] = mapped_column(String(64))
    data_classification: Mapped[str] = mapped_column(String(32))
    trust_domain: Mapped[str] = mapped_column(String(128), default="local")
    network_policy_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    allowed_effects_json: Mapped[list[str]] = mapped_column(JSON)
    content_digest: Mapped[str | None] = mapped_column(String(100), nullable=True)
    parent_versioned_id: Mapped[str | None] = mapped_column(String(300), nullable=True)
    authorization_evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    signature: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AssetAliasRow(Base):
    __tablename__ = "asset_aliases"

    asset_alias: Mapped[str] = mapped_column(String(256), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    current_versioned_id: Mapped[str] = mapped_column(
        ForeignKey("asset_revisions.versioned_id"), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ScopeTokenRow(Base):
    __tablename__ = "scope_tokens"

    token_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    engagement_revision: Mapped[int] = mapped_column(Integer)
    token_hash: Mapped[str] = mapped_column(String(80), unique=True)
    claims_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TaskRow(Base):
    __tablename__ = "task_specs"

    task_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    mode: Mapped[str] = mapped_column(String(32))
    objective: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(64), index=True)
    spec_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    parent_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class HypothesisRow(Base):
    __tablename__ = "hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    claim: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(64))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ProposedActionRow(Base):
    __tablename__ = "proposed_actions"

    action_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    template_id: Mapped[str] = mapped_column(String(256))
    target_asset_alias: Mapped[str] = mapped_column(String(256))
    arguments_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    action_fingerprint: Mapped[str] = mapped_column(String(80), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PolicyDecisionRow(Base):
    __tablename__ = "policy_decisions"

    decision_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(128), index=True)
    pass_number: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(64), index=True)
    reason_code: Mapped[str] = mapped_column(String(128))
    configuration_before_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    configuration_after_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApprovalRow(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    action_template: Mapped[str] = mapped_column(String(256), index=True)
    asset_versioned_id: Mapped[str] = mapped_column(String(300), index=True)
    tool_version: Mapped[str] = mapped_column(String(64))
    effect_classes_json: Mapped[list[str]] = mapped_column(JSON)
    parameter_ranges_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    actor: Mapped[str] = mapped_column(String(256))
    auto_granted: Mapped[bool] = mapped_column(Boolean, default=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    signature: Mapped[str] = mapped_column(String(256))


class ExecutionGrantRow(Base):
    __tablename__ = "execution_grants"

    grant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(128), index=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_versioned_id: Mapped[str] = mapped_column(String(300))
    tool_id: Mapped[str] = mapped_column(String(256))
    tool_version: Mapped[str] = mapped_column(String(64))
    profile_name: Mapped[str] = mapped_column(String(128))
    action_fingerprint: Mapped[str] = mapped_column(String(80))
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    token: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class BudgetUsageRow(Base):
    __tablename__ = "budget_usage"
    __table_args__ = (UniqueConstraint("engagement_id", "task_id", "budget_name"),)

    row_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    budget_name: Mapped[str] = mapped_column(String(64))
    model_turns: Mapped[int] = mapped_column(Integer, default=0)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    tool_runtime_seconds: Mapped[int] = mapped_column(Integer, default=0)
    artifact_bytes: Mapped[int] = mapped_column(Integer, default=0)
    retry_attempts: Mapped[int] = mapped_column(Integer, default=0)
    subtask_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ToolRunRow(Base):
    __tablename__ = "tool_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(128), index=True)
    grant_id: Mapped[str] = mapped_column(String(128), index=True)
    tool_id: Mapped[str] = mapped_column(String(256))
    profile_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(64))
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer)
    stdout_artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stderr_artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ArtifactRow(Base):
    __tablename__ = "artifacts"

    artifact_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    media_type: Mapped[str] = mapped_column(String(128))
    byte_count: Mapped[int] = mapped_column(Integer)
    relative_path: Mapped[str] = mapped_column(Text)
    source_run_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvidenceRow(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    asset_versioned_id: Mapped[str] = mapped_column(String(300), index=True)
    evidence_type: Mapped[str] = mapped_column(String(128), index=True)
    evidence_class: Mapped[str] = mapped_column(String(128), index=True)
    summary: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    finding_type: Mapped[str] = mapped_column(String(128), index=True)
    asset_versioned_id: Mapped[str] = mapped_column(String(300), index=True)
    title: Mapped[str] = mapped_column(Text)
    claim: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32))
    fingerprint: Mapped[str] = mapped_column(String(80), index=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class FindingEvidenceRow(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (UniqueConstraint("finding_id", "evidence_id"),)

    row_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    evidence_id: Mapped[str] = mapped_column(String(128), index=True)
    relationship: Mapped[str] = mapped_column(String(32), default="supporting")


class VerificationRow(Base):
    __tablename__ = "verifications"

    verification_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    verdict: Mapped[str] = mapped_column(String(32))
    verifier_type: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class NonResponseEventRow(Base):
    __tablename__ = "non_response_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    stage: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(64), index=True)
    subtype: Mapped[str | None] = mapped_column(String(128), nullable=True)
    retryable: Mapped[bool] = mapped_column(Boolean)
    retry_count: Mapped[int] = mapped_column(Integer)
    strategies_json: Mapped[list[str]] = mapped_column(JSON)
    prompt_fingerprint: Mapped[str] = mapped_column(String(80))
    response_fingerprint: Mapped[str] = mapped_column(String(80))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RetryAttemptRow(Base):
    __tablename__ = "retry_attempts"

    attempt_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), index=True)
    pass_number: Mapped[int] = mapped_column(Integer)
    strategy: Mapped[str] = mapped_column(String(128))
    semantic_fingerprint: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    action_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(256))
    before_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    after_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ModelCallRow(Base):
    __tablename__ = "model_calls"

    call_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    model: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(64))
    reasoning_effort: Mapped[str] = mapped_column(String(16))
    task_id: Mapped[str] = mapped_column(String(128), index=True)
    sub_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    prompt_hash: Mapped[str] = mapped_column(String(80))
    response_hash: Mapped[str] = mapped_column(String(80))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    tool_count_exposed: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str] = mapped_column(String(64))
    strategies_json: Mapped[list[str]] = mapped_column(JSON)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class VaultItemRow(Base):
    __tablename__ = "credential_vault"

    vault_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_relative_path: Mapped[str] = mapped_column(Text)
    secret_type: Mapped[str] = mapped_column(String(128))
    source_artifact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class EvaluationCaseRow(Base):
    __tablename__ = "evaluation_cases"

    case_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    suite: Mapped[str] = mapped_column(String(128), index=True)
    label_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    case_json: Mapped[dict[str, Any]] = mapped_column(JSON)


class EvaluationRunRow(Base):
    __tablename__ = "evaluation_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    benchmark_name: Mapped[str] = mapped_column(String(128))
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    sample_count: Mapped[int] = mapped_column(Integer)
    passed: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
