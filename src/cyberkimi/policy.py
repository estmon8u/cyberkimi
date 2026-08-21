"""Pure fail-closed policy evaluation and atomic authorization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from jsonschema import Draft202012Validator
from sqlalchemy import insert

from cyberkimi.audit import AuditStore
from cyberkimi.authorization import ApprovalService, GrantService, action_digest
from cyberkimi.errors import ApprovalRequired, BudgetExceeded
from cyberkimi.models import (
    DecisionCode,
    DeploymentProfile,
    Engagement,
    PolicyDecision,
    ProposedAction,
    RiskTier,
    TaskSpec,
    ToolManifest,
)
from cyberkimi.persistence import Database, budget_reservations

GLOBAL_EFFECT_CEILING: Final[frozenset[str]] = frozenset(
    {
        "repository.read",
        "repository.search",
        "repository.diff_read",
        "process.local_readonly",
        "artifact.read",
        "artifact.write",
        "lab.observe",
        "lab.request_allowlisted",
        "lab.reset",
        "credential.inject_handle",
        "source.patch_scratch",
        "source.test_scratch",
    }
)


@dataclass(frozen=True)
class PolicyContext:
    engagement: Engagement
    task: TaskSpec
    tool: ToolManifest
    profile: DeploymentProfile
    action: ProposedAction
    approval_present: bool


class PolicyEngine:
    version = "policy/v1.0.0"

    def validate_profile(self, manifest: ToolManifest, profile: DeploymentProfile) -> None:
        if profile.tool_template_id != manifest.template_id:
            raise ValueError("deployment profile tool mismatch")
        if profile.timeout_seconds > manifest.runtime.timeout_seconds_max:
            raise ValueError("deployment profile widens timeout")
        if profile.memory_mb > manifest.runtime.memory_mb_max:
            raise ValueError("deployment profile widens memory")
        if profile.output_bytes > manifest.runtime.output_bytes_max:
            raise ValueError("deployment profile widens output limit")
        if not profile.effects.issubset(manifest.maximum_effects):
            raise ValueError("deployment profile adds effects")
        if profile.risk_floor < manifest.minimum_risk:
            raise ValueError("deployment profile lowers minimum risk")
        if manifest.network_mode == "DENY_ALL" and profile.network_mode != "DENY_ALL":
            raise ValueError("deployment profile widens network")
        if manifest.source_mount in {"NONE", "READ_ONLY"} and profile.source_mount not in {
            "NONE",
            manifest.source_mount,
        }:
            raise ValueError("deployment profile widens source mount")

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        engagement = context.engagement
        task = context.task
        tool = context.tool
        profile = context.profile
        action = context.action
        digest = action_digest(engagement, task, action, tool)
        effective_risk = max(action.risk_tier, tool.minimum_risk, profile.risk_floor)
        effective_effects = action.requested_effects

        def decision(code: DecisionCode, reason: str, *, approval: bool = False) -> PolicyDecision:
            return PolicyDecision(
                code=code,
                reason=reason,
                action_digest=digest,
                effective_risk=effective_risk,
                effective_effects=effective_effects,
                requires_approval=approval,
                policy_version=self.version,
            )

        try:
            self.validate_profile(tool, profile)
        except ValueError as exc:
            return decision(DecisionCode.DENY, str(exc))
        if not engagement.active_at():
            return decision(DecisionCode.DENY, "engagement revision is not active")
        if task.engagement_id != engagement.engagement_id or task.engagement_revision != engagement.revision:
            return decision(DecisionCode.DENY, "task engagement revision mismatch")
        if task.asset_id != action.asset_id:
            return decision(DecisionCode.DENY, "action asset differs from task asset")
        try:
            asset = engagement.asset(action.asset_id)
        except KeyError:
            return decision(DecisionCode.DENY, "action asset is not in the engagement")
        if asset.status != "active":
            return decision(DecisionCode.DENY, "asset is not active")
        if asset.kind not in tool.accepted_asset_kinds:
            return decision(DecisionCode.DENY, "tool does not accept the immutable asset kind")
        if task.mode not in tool.modes:
            return decision(DecisionCode.DENY, "tool is not eligible for the task mode")
        if action.tool_template_id != tool.template_id:
            return decision(DecisionCode.DENY, "action tool version mismatch")
        if action.risk_tier < tool.minimum_risk:
            return decision(DecisionCode.DENY, "action attempts to lower tool risk")
        if effective_risk > engagement.risk_ceiling or effective_risk > task.risk_ceiling:
            return decision(DecisionCode.NEEDS_SCOPE_AMENDMENT, "risk exceeds immutable ceiling")
        if not effective_effects:
            return decision(DecisionCode.DENY, "executable action must request explicit effects")
        if not effective_effects.issubset(GLOBAL_EFFECT_CEILING):
            return decision(DecisionCode.DENY, "effect exceeds global hard ceiling")
        if not effective_effects.issubset(tool.maximum_effects):
            return decision(DecisionCode.DENY, "effect exceeds tool manifest")
        if not effective_effects.issubset(profile.effects):
            return decision(DecisionCode.DENY, "effect exceeds deployment profile")
        if not effective_effects.issubset(task.allowed_effects):
            return decision(DecisionCode.NEEDS_SCOPE_AMENDMENT, "effect exceeds task scope")
        if not effective_effects.issubset(asset.allowed_effects):
            return decision(DecisionCode.NEEDS_SCOPE_AMENDMENT, "effect exceeds asset binding")
        if effective_effects.intersection(engagement.prohibited_effects):
            return decision(DecisionCode.DENY, "effect is explicitly prohibited")
        if action.budget.runtime_seconds > engagement.budgets.max_single_tool_runtime_seconds:
            return decision(DecisionCode.BUDGET_EXCEEDED, "single-tool runtime exceeds budget")
        if tool.network_mode == "DENY_ALL" and profile.network_mode != "DENY_ALL":
            return decision(DecisionCode.DENY, "network policy was widened")
        if profile.network_mode == "LAB_ALLOWLIST" and not engagement.network_policy.allowed_endpoint_ids:
            return decision(DecisionCode.DENY, "lab network profile has no registered endpoints")
        errors = sorted(Draft202012Validator(tool.arguments_schema).iter_errors(action.arguments), key=str)
        if errors:
            return decision(DecisionCode.DENY, f"tool arguments invalid: {errors[0].message}")
        requires_approval = (
            effective_risk >= RiskTier.R3_BOUNDED_LAB_VALIDATION
            or tool.default_approval_required
        )
        if requires_approval and not context.approval_present:
            return decision(
                DecisionCode.NEEDS_APPROVAL,
                "exact action approval required",
                approval=True,
            )
        return decision(DecisionCode.PERMIT, "all immutable policy intersections permit action")


class AuthorizationCoordinator:
    """Reserve budgets, bind approval, audit, and mint a grant in one transaction."""

    def __init__(
        self,
        database: Database,
        audit: AuditStore,
        policy: PolicyEngine,
        approvals: ApprovalService,
        grants: GrantService,
    ):
        self.database = database
        self.audit = audit
        self.policy = policy
        self.approvals = approvals
        self.grants = grants

    def authorize(
        self,
        engagement: Engagement,
        task: TaskSpec,
        tool: ToolManifest,
        profile: DeploymentProfile,
        action: ProposedAction,
    ) -> tuple[PolicyDecision, str]:
        digest = action_digest(engagement, task, action, tool)
        approval_id: str | None = None
        approval_present = False
        try:
            approval = self.approvals.require_valid(digest)
            approval_id = approval.approval_id
            approval_present = True
        except ApprovalRequired:
            pass
        context = PolicyContext(
            engagement=engagement,
            task=task,
            tool=tool,
            profile=profile,
            action=action,
            approval_present=approval_present,
        )
        decision = self.policy.evaluate(context)
        if decision.code is not DecisionCode.PERMIT:
            self.audit.append(
                engagement.engagement_id,
                "policy.decision",
                decision.model_dump(mode="json"),
            )
            if decision.code is DecisionCode.NEEDS_APPROVAL:
                raise ApprovalRequired(decision.reason)
            if decision.code is DecisionCode.BUDGET_EXCEEDED:
                raise BudgetExceeded(decision.reason)
            raise PermissionError(decision.reason)

        with self.database.transaction() as connection:
            used_calls, used_runtime, used_bytes = self.database.task_usage(task.task_id, connection)
            next_calls = used_calls + action.budget.tool_calls
            next_runtime = used_runtime + action.budget.runtime_seconds
            next_bytes = used_bytes + action.budget.artifact_bytes
            if next_calls > engagement.budgets.max_tool_calls_per_subtask:
                raise BudgetExceeded("tool-call budget exceeded")
            if next_runtime > engagement.budgets.max_total_tool_runtime_seconds:
                raise BudgetExceeded("total runtime budget exceeded")
            if next_bytes > engagement.budgets.max_artifact_bytes:
                raise BudgetExceeded("artifact budget exceeded")
            if decision.requires_approval:
                approval = self.approvals.require_valid(digest, connection=connection, consume=True)
                approval_id = approval.approval_id
            connection.execute(
                insert(budget_reservations).values(
                    reservation_id=action.budget.reservation_id,
                    task_id=task.task_id,
                    action_digest=digest,
                    tool_calls=action.budget.tool_calls,
                    runtime_seconds=action.budget.runtime_seconds,
                    artifact_bytes=action.budget.artifact_bytes,
                    state="reserved",
                    created_at=self.database.now(),
                )
            )
            self.audit.append(
                engagement.engagement_id,
                "policy.decision",
                decision.model_dump(mode="json"),
                connection=connection,
            )
            grant_token, _grant = self.grants.mint(
                engagement.engagement_id,
                action,
                digest,
                approval_id=approval_id,
                connection=connection,
            )
        return decision, grant_token
