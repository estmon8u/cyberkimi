from __future__ import annotations

from cyberkimi.assets import asset_binding_digest
from cyberkimi.canonical import sha256_digest
from cyberkimi.ids import new_id
from cyberkimi.models import BudgetReservation, ProposedAction, RiskTier
from cyberkimi.policy import PolicyContext


def test_effect_intersection_never_widens(runtime, task_scope, repository_read) -> None:
    task, _token, scope_digest = task_scope
    engagement = runtime["engagement"]
    asset = engagement.asset(task.asset_id)
    tool, profile = repository_read
    candidate_sets = [
        frozenset({"repository.read"}),
        frozenset({"repository.read", "network.public"}),
        frozenset({"artifact.write"}),
    ]
    for effects in candidate_sets:
        action = ProposedAction(
            action_id=new_id("ACT"),
            task_id=task.task_id,
            tool_template_id=tool.template_id,
            tool_manifest_digest=sha256_digest(tool),
            asset_id=asset.asset_id,
            asset_binding_digest=asset_binding_digest(asset),
            arguments={"path": "app.py"},
            requested_effects=effects,
            risk_tier=RiskTier.R1_LOCAL_READ_ONLY,
            budget=BudgetReservation(reservation_id=new_id("BUD"), runtime_seconds=5),
            scope_token_digest=scope_digest,
            operator_profile=profile.profile_id,
        )
        before = action.model_dump(mode="json")
        decision = runtime["policy"].evaluate(
            PolicyContext(engagement, task, tool, profile, action, False)
        )
        assert action.model_dump(mode="json") == before
        if decision.code.value == "PERMIT":
            assert decision.effective_effects.issubset(tool.maximum_effects)
            assert decision.effective_effects.issubset(profile.effects)
            assert decision.effective_effects.issubset(task.allowed_effects)
            assert decision.effective_effects.issubset(asset.allowed_effects)
