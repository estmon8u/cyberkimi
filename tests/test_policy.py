from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyberkimi.authorization import ScopeSigner
from cyberkimi.domain import (
    AssetRevision,
    DataClassification,
    EngagementRevision,
    ProposedAction,
    RiskTier,
    ToolManifest,
    ToolProfile,
    TrustProfile,
)
from cyberkimi.policy import AuthorizationContext, PolicyDenied, PolicyEngine
from cyberkimi.store import Database


def build_context(tmp_path, *, self_attested: bool = False):
    database = Database(tmp_path / "state.db")
    database.initialize()
    signer = ScopeSigner(b"s" * 32)
    now = datetime.now(timezone.utc)
    engagement = EngagementRevision(
        engagement_id="ENG-POLICY",
        revision=1,
        owner="owner",
        approver="owner",
        authorization_basis="local_owner_attestation",
        authorization_status="self_attested",
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        maximum_risk_tier=RiskTier.R3_BOUNDED_VALIDATION,
        capability_flags=frozenset({"extended_operations"}),
        self_attested_approvals=self_attested,
    )
    unsigned = {
        "asset_alias": "repo:service",
        "revision": 1,
        "engagement_id": engagement.engagement_id,
        "asset_type": "repository",
        "canonical_location": str(tmp_path),
        "trust_domain": "local",
        "content_revision": "working-tree",
        "allowed_effects": ["file.read", "file.write", "process.local", "network.observed"],
        "data_classification": DataClassification.INTERNAL.value,
        "network_identifiers": [],
        "authorization_evidence_digest": "b" * 64,
    }
    asset = AssetRevision.model_validate({**unsigned, "signature": signer.sign(unsigned)})
    tool = ToolManifest(
        internal_id="repository.trace_symbols@1.0.0",
        kimi_alias="repository_trace_symbols_v1",
        category="source_analysis",
        accepted_asset_types=frozenset({"repository"}),
        base_profile=ToolProfile(
            name="restricted",
            risk_tier=RiskTier.R1_READ_ONLY,
            effects=frozenset({"file.read", "process.local"}),
            timeout_seconds=60,
            trust_profile=TrustProfile.RESTRICTED,
        ),
        authorized_profiles=(
            ToolProfile(
                name="extended_lab",
                requires_engagement_flag="extended_operations",
                risk_tier=RiskTier.R3_BOUNDED_VALIDATION,
                effects=frozenset(
                    {"file.read", "file.write", "process.local", "network.observed"}
                ),
                network=True,
                filesystem="read_write",
                timeout_seconds=600,
                trust_profile=TrustProfile.ELEVATED,
            ),
        ),
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        output_schema={"type": "object"},
    )
    return database, signer, now, engagement, asset, tool


def test_success_is_atomic_and_grant_is_single_use(tmp_path) -> None:
    database, signer, now, engagement, asset, tool = build_context(tmp_path)
    engine = PolicyEngine(database, signer)
    action = ProposedAction(
        action_id="ACT-1",
        task_id="TASK-1",
        engagement_id=engagement.engagement_id,
        action_template=tool.internal_id,
        target_asset_id=asset.asset_alias,
        purpose="trace authorization symbols",
        requested_effects=frozenset({"file.read", "process.local"}),
        requested_timeout_seconds=30,
    )
    decision = engine.authorize(
        action,
        engagement,
        asset,
        tool,
        AuthorizationContext(root_task_id="TASK-1", actor="owner", now=now),
    )
    assert decision.permitted
    assert decision.grant is not None
    assert database.fetch_one("SELECT COUNT(*) AS count FROM execution_grants")["count"] == 1
    assert database.fetch_one("SELECT tool_calls FROM budget_usage")["tool_calls"] == 1

    engine.consume_grant(decision.grant, now=now)
    with pytest.raises(PolicyDenied) as failure:
        engine.consume_grant(decision.grant, now=now)
    assert failure.value.reason_code == "REPLAYED_GRANT"


def test_denial_rolls_back_budget_and_grant(tmp_path) -> None:
    database, signer, now, engagement, asset, tool = build_context(tmp_path)
    engine = PolicyEngine(database, signer)
    action = ProposedAction(
        action_id="ACT-DENIED",
        task_id="TASK-1",
        engagement_id=engagement.engagement_id,
        action_template=tool.internal_id,
        target_asset_id=asset.asset_alias,
        purpose="request prohibited effect",
        requested_effects=frozenset({"destructive"}),
        requested_timeout_seconds=30,
    )
    decision = engine.authorize(
        action,
        engagement,
        asset,
        tool,
        AuthorizationContext(root_task_id="TASK-1", actor="owner", now=now),
    )
    assert not decision.permitted
    assert decision.reason_code == "PROHIBITED_EFFECT"
    assert database.fetch_one("SELECT COUNT(*) AS count FROM execution_grants")["count"] == 0
    assert database.fetch_one("SELECT COUNT(*) AS count FROM budget_usage")["count"] == 0
    assert database.fetch_one("SELECT COUNT(*) AS count FROM audit_events")["count"] == 1


def test_authorized_profile_selection_requires_approval(tmp_path) -> None:
    database, signer, now, engagement, asset, tool = build_context(tmp_path)
    engine = PolicyEngine(database, signer)
    action = ProposedAction(
        action_id="ACT-R3",
        task_id="TASK-1",
        engagement_id=engagement.engagement_id,
        action_template=tool.internal_id,
        target_asset_id=asset.asset_alias,
        purpose="bounded validation in declared lab",
        requested_effects=frozenset(
            {"file.read", "file.write", "process.local", "network.observed"}
        ),
        requested_timeout_seconds=300,
    )
    decision = engine.authorize(
        action,
        engagement,
        asset,
        tool,
        AuthorizationContext(root_task_id="TASK-1", actor="owner", now=now),
    )
    assert not decision.permitted
    assert decision.requires_approval
    assert decision.reason_code == "HUMAN_APPROVAL_REQUIRED"


def test_self_attested_r3_auto_grant_is_audited(tmp_path) -> None:
    database, signer, now, engagement, asset, tool = build_context(tmp_path, self_attested=True)
    engine = PolicyEngine(database, signer)
    action = ProposedAction(
        action_id="ACT-R3-AUTO",
        task_id="TASK-1",
        engagement_id=engagement.engagement_id,
        action_template=tool.internal_id,
        target_asset_id=asset.asset_alias,
        purpose="bounded validation in declared lab",
        requested_effects=frozenset(
            {"file.read", "file.write", "process.local", "network.observed"}
        ),
        requested_timeout_seconds=300,
    )
    decision = engine.authorize(
        action,
        engagement,
        asset,
        tool,
        AuthorizationContext(root_task_id="TASK-1", actor="owner", now=now),
    )
    assert decision.permitted
    assert decision.selected_profile == "extended_lab"
    assert database.fetch_one("SELECT COUNT(*) AS count FROM approvals")["count"] == 1
    event_types = {
        row["event_type"] for row in database.fetch_all("SELECT event_type FROM audit_events")
    }
    assert {"approval.auto_granted", "authorization.permitted"}.issubset(event_types)
