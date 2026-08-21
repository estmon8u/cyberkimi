from __future__ import annotations

from datetime import timedelta

import pytest

from cyberkimi.assets import asset_binding_digest
from cyberkimi.authorization import action_digest
from cyberkimi.canonical import sha256_digest
from cyberkimi.errors import ApprovalRequired, AuthorizationError, GrantError
from cyberkimi.ids import new_id
from cyberkimi.models import BudgetReservation, ProposedAction, RiskTier
from cyberkimi.operator import Operator


def _action(runtime, task_scope, repository_read):
    task, _token, scope_digest = task_scope
    engagement = runtime["engagement"]
    asset = engagement.asset(task.asset_id)
    tool, profile = repository_read
    return ProposedAction(
        action_id=new_id("ACT"),
        task_id=task.task_id,
        tool_template_id=tool.template_id,
        tool_manifest_digest=sha256_digest(tool),
        asset_id=asset.asset_id,
        asset_binding_digest=asset_binding_digest(asset),
        arguments={"path": "app.py", "max_bytes": 1000},
        requested_effects=frozenset({"repository.read"}),
        risk_tier=RiskTier.R1_LOCAL_READ_ONLY,
        budget=BudgetReservation(
            reservation_id=new_id("BUD"), runtime_seconds=10, artifact_bytes=1000
        ),
        scope_token_digest=scope_digest,
        operator_profile=profile.profile_id,
    )


def test_modified_scope_token_is_rejected(runtime, task_scope) -> None:
    task, token, digest = task_scope
    with pytest.raises(AuthorizationError):
        runtime["scopes"].verify(token + "x", task, digest)


def test_revoked_scope_token_is_rejected(runtime, task_scope) -> None:
    task, token, digest = task_scope
    runtime["database"].revoke_scope_token(digest)
    with pytest.raises(AuthorizationError):
        runtime["scopes"].verify(token, task, digest)


def test_single_use_grant_cannot_be_replayed(runtime, task_scope, repository_read) -> None:
    task, token, digest = task_scope
    runtime["scopes"].verify(token, task, digest)
    action = _action(runtime, task_scope, repository_read)
    engagement = runtime["engagement"]
    asset = engagement.asset(task.asset_id)
    tool, profile = repository_read
    _decision, grant = runtime["coordinator"].authorize(
        engagement, task, tool, profile, action
    )
    operator = Operator(
        runtime["database"], runtime["audit"], runtime["grants"], runtime["adapters"]
    )
    run_id, result = operator.execute(
        engagement,
        asset,
        tool,
        profile,
        action,
        action_digest(engagement, task, action, tool),
        grant,
    )
    assert run_id.startswith("RUN-")
    assert result.status.value == "success"
    with pytest.raises(GrantError):
        operator.execute(
            engagement,
            asset,
            tool,
            profile,
            action,
            action_digest(engagement, task, action, tool),
            grant,
        )


def test_r3_requires_exact_approval(runtime, task_scope, repository_read) -> None:
    task, _token, _digest = task_scope
    action = _action(runtime, task_scope, repository_read).model_copy(
        update={"risk_tier": RiskTier.R3_BOUNDED_LAB_VALIDATION}
    )
    tool, profile = repository_read
    profile = profile.model_copy(update={"risk_floor": RiskTier.R3_BOUNDED_LAB_VALIDATION})
    engagement = runtime["engagement"].model_copy(
        update={"risk_ceiling": RiskTier.R3_BOUNDED_LAB_VALIDATION}
    )
    task = task.model_copy(update={"risk_ceiling": RiskTier.R3_BOUNDED_LAB_VALIDATION})
    with pytest.raises(ApprovalRequired):
        runtime["coordinator"].authorize(engagement, task, tool, profile, action)
    digest = action_digest(engagement, task, action, tool)
    runtime["approvals"].record(
        engagement.engagement_id,
        digest,
        "user:test",
        "approved",
        expires_in=timedelta(minutes=1),
    )
    decision, _grant = runtime["coordinator"].authorize(
        engagement, task, tool, profile, action
    )
    assert decision.code.value == "PERMIT"
