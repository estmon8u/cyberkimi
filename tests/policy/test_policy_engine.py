from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select

from cyberkimi.core import DecisionKind, RiskTier, TaskMode
from cyberkimi.engagement.manifest import provision_repository_manifest
from cyberkimi.engagement.service import EngagementService
from cyberkimi.errors import AuthorizationError, BudgetExceeded
from cyberkimi.persistence.models import BudgetUsageRow, ExecutionGrantRow, PolicyDecisionRow
from cyberkimi.policy import AuthorizationRequest, PolicyEngine
from cyberkimi.tasking import BudgetCost, ProposedAction, TaskSpec
from cyberkimi.tools import CapabilityProfile, RuntimeLimits, ToolRegistry


def registry() -> ToolRegistry:
    return ToolRegistry.from_directory(Path(__file__).parents[2] / "tool_manifests")


def setup_repo(database, signing_key: bytes, tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    manifest = provision_repository_manifest(
        target=root,
        owner="Esteban",
        engagement_id="ENG-POLICY",
    )
    engagements = EngagementService(database, signing_key)
    compiled = engagements.register(manifest)
    engine = PolicyEngine(database, engagements, registry(), signing_key)
    return manifest, compiled, engine


def test_r1_authorization_is_atomic_and_grant_is_single_use(database, signing_key, tmp_path):
    manifest, compiled, engine = setup_repo(database, signing_key, tmp_path)
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Find authorization enforcement points",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read", "file.search"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="repository.search",
        target_asset_id="repo:repo",
        arguments={"query": "authorize", "max_results": 20},
        purpose="Locate enforcement points",
    )

    outcome = engine.authorize_adaptive(
        AuthorizationRequest(
            scope_token=compiled.token,
            task=task,
            action=action,
            actor="Esteban",
        )
    )

    assert outcome.decision.decision == DecisionKind.PERMIT
    assert outcome.grant is not None
    assert outcome.grant_token is not None
    consumed = engine.consume_grant(outcome.grant_token, expected_action=action)
    assert consumed.action_id == action.action_id
    with pytest.raises(AuthorizationError, match="already been consumed"):
        engine.consume_grant(outcome.grant_token, expected_action=action)


def test_unauthorized_extended_profile_is_audited_then_falls_back(database, signing_key, tmp_path):
    manifest, compiled, engine = setup_repo(database, signing_key, tmp_path)
    base = engine.tools.require("repository.search")
    extended = CapabilityProfile(
        name="extended",
        risk_tier=RiskTier.R1_READ_ONLY,
        effects=frozenset({"file.read", "file.search"}),
        runtime=RuntimeLimits(timeout_seconds=120),
        requires_engagement_flag="extended_operations",
    )
    engine.tools = ToolRegistry([base.model_copy(update={"authorized_profiles": (extended,)})])
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Search source",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read", "file.search"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="repository.search",
        target_asset_id="repo:repo",
        arguments={"query": "auth"},
        purpose="Search",
        requested_profile="extended",
    )

    outcome = engine.authorize_adaptive(
        AuthorizationRequest(scope_token=compiled.token, task=task, action=action, actor="Esteban")
    )

    assert outcome.decision.pass_number == 2
    assert outcome.decision.decision == DecisionKind.PERMIT
    with database.read_session() as session:
        decisions = session.scalars(
            select(PolicyDecisionRow).where(PolicyDecisionRow.action_id == action.action_id)
        ).all()
    assert [row.decision for row in decisions] == [
        DecisionKind.ADJUST_CONFIGURATION.value,
        DecisionKind.PERMIT.value,
    ]


def test_budget_failure_rolls_back_grant_and_usage(database, signing_key, tmp_path):
    manifest, compiled, engine = setup_repo(database, signing_key, tmp_path)
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Search source",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read", "file.search"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="repository.search",
        target_asset_id="repo:repo",
        arguments={"query": "auth"},
        purpose="Search",
        estimated_cost=BudgetCost(tool_calls=61),
    )

    with pytest.raises(BudgetExceeded):
        engine.authorize_adaptive(
            AuthorizationRequest(scope_token=compiled.token, task=task, action=action, actor="Esteban")
        )

    with database.read_session() as session:
        grants = session.scalar(select(func.count()).select_from(ExecutionGrantRow))
        usage = session.scalar(select(func.count()).select_from(BudgetUsageRow))
    assert grants == 0
    assert usage == 0


def test_tool_arguments_are_strictly_validated(database, signing_key, tmp_path):
    manifest, compiled, engine = setup_repo(database, signing_key, tmp_path)
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Search source",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read", "file.search"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="repository.search",
        target_asset_id="repo:repo",
        arguments={"query": "auth", "unexpected": True},
        purpose="Search",
    )

    with pytest.raises(Exception, match="additional properties|schema validation"):
        engine.authorize_adaptive(
            AuthorizationRequest(scope_token=compiled.token, task=task, action=action, actor="Esteban")
        )
