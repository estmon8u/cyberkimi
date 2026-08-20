from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from jsonschema import Draft202012Validator
from sqlalchemy import func, select

from cyberkimi.core import DecisionKind, RiskTier, canonical_json, fingerprint, new_id, utc_now
from cyberkimi.engagement.service import EngagementService
from cyberkimi.errors import AuthorizationError, BudgetExceeded, ValidationFailure
from cyberkimi.persistence.database import Database
from cyberkimi.persistence.models import (
    ApprovalRow,
    AuditEventRow,
    BudgetUsageRow,
    ExecutionGrantRow,
    PolicyDecisionRow,
    ProposedActionRow,
)
from cyberkimi.policy.grants import GrantCodec
from cyberkimi.policy.models import (
    AuthorizationOutcome,
    AuthorizationRequest,
    ExecutionGrantClaims,
    PolicyDecision,
)
from cyberkimi.tasking.models import ProposedAction
from cyberkimi.tools.models import CapabilityProfile, ToolManifest
from cyberkimi.tools.registry import ToolRegistry


class PolicyEngine:
    """Atomic, fail-closed authorization coordinator."""

    def __init__(
        self,
        database: Database,
        engagements: EngagementService,
        tools: ToolRegistry,
        signing_key: bytes,
    ) -> None:
        self.database = database
        self.engagements = engagements
        self.tools = tools
        self.signing_key = signing_key
        self.grants = GrantCodec(signing_key)

    def authorize_adaptive(self, request: AuthorizationRequest) -> AuthorizationOutcome:
        first = self.authorize(request, pass_number=1)
        if first.decision.decision != DecisionKind.ADJUST_CONFIGURATION:
            return first
        adjusted = request.action.model_copy(update={"requested_profile": None})
        return self.authorize(
            request.model_copy(update={"action": adjusted}),
            pass_number=2,
            configuration_before=first.decision.configuration_after,
        )

    def authorize(
        self,
        request: AuthorizationRequest,
        *,
        pass_number: int = 1,
        configuration_before: dict[str, Any] | None = None,
    ) -> AuthorizationOutcome:
        claims = self.engagements.verify_scope_token(request.scope_token)
        manifest = self.engagements.get_manifest(claims.engagement_id, claims.engagement_revision)
        self._validate_request_binding(request, claims.engagement_id)
        asset = self.engagements.resolve_asset(claims.engagement_id, request.action.target_asset_id)
        expected_version = claims.assets.get(asset.asset_alias)
        if expected_version != asset.versioned_id:
            return self._non_grant(
                request,
                pass_number,
                DecisionKind.DENY,
                "ASSET_REVISION_NOT_IN_SCOPE_TOKEN",
                "The action does not bind to the asset revision signed into this scope token.",
            )
        tool = self.tools.require(request.action.action_template)
        tool.validate_arguments(request.action.arguments)
        if all(item.value != asset.asset_type for item in tool.accepted_assets):
            return self._non_grant(
                request,
                pass_number,
                DecisionKind.DENY,
                "ASSET_TYPE_NOT_ACCEPTED",
                f"{tool.name} does not accept asset type {asset.asset_type}.",
            )
        try:
            profile = tool.profile(
                request.action.requested_profile,
                engagement_flags=manifest.engagement.flags,
            )
        except ValidationFailure as exc:
            if request.action.requested_profile:
                return self._non_grant(
                    request,
                    pass_number,
                    DecisionKind.ADJUST_CONFIGURATION,
                    "PROFILE_NOT_AUTHORIZED",
                    str(exc),
                    before=configuration_before
                    or {"requested_profile": request.action.requested_profile},
                    after={"requested_profile": tool.base_profile.name},
                )
            raise
        reason = self._validate_profile(request, manifest, asset, profile)
        if reason is not None:
            kind, code, message = reason
            return self._non_grant(request, pass_number, kind, code, message)

        with self.database.transaction(immediate=True) as session:
            self._ensure_budget(session, request, manifest, profile)
            approval_id: str | None = None
            if profile.requires_approval or profile.risk_tier.rank >= RiskTier.R3_ACTIVE_VALIDATION.rank:
                approval = self._find_approval(
                    session,
                    request=request,
                    tool=tool,
                    profile=profile,
                    asset_versioned_id=asset.versioned_id,
                )
                if approval is None:
                    if not manifest.authorization_allows_auto_approval():
                        decision = self._decision(
                            pass_number,
                            DecisionKind.REQUIRE_APPROVAL,
                            "HUMAN_APPROVAL_REQUIRED",
                            "This action class and parameter range requires approval.",
                        )
                        self._persist_decision(session, request, decision)
                        return AuthorizationOutcome(decision=decision, profile=profile)
                    approval = self._auto_approve(
                        session,
                        request=request,
                        tool=tool,
                        profile=profile,
                        asset_versioned_id=asset.versioned_id,
                    )
                approval_id = approval.approval_id

            now = utc_now()
            grant = ExecutionGrantClaims(
                grant_id=new_id("GRANT"),
                action_id=request.action.action_id,
                engagement_id=manifest.id,
                task_id=request.task.task_id,
                asset_versioned_id=asset.versioned_id,
                tool_id=tool.internal_id,
                tool_version=tool.version,
                profile_name=profile.name,
                risk_tier=profile.risk_tier,
                trust_profile=profile.trust_profile,
                effects=profile.effects,
                arguments_hash=fingerprint(request.action.arguments),
                nonce=secrets.token_urlsafe(24),
                issued_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            token = self.grants.issue(grant)
            decision = self._decision(
                pass_number,
                DecisionKind.PERMIT,
                "AUTHORIZED",
                "Action is within the signed engagement, selected profile, approval, and budget.",
                after={"profile": profile.name, "asset": asset.versioned_id},
            )
            session.add(
                ProposedActionRow(
                    action_id=request.action.action_id,
                    task_id=request.task.task_id,
                    template_id=tool.name,
                    target_asset_alias=asset.asset_alias,
                    arguments_json=request.action.arguments,
                    action_fingerprint=fingerprint(request.action),
                )
            )
            session.add(
                ExecutionGrantRow(
                    grant_id=grant.grant_id,
                    action_id=grant.action_id,
                    engagement_id=grant.engagement_id,
                    asset_versioned_id=grant.asset_versioned_id,
                    tool_id=grant.tool_id,
                    tool_version=grant.tool_version,
                    profile_name=grant.profile_name,
                    action_fingerprint=fingerprint(request.action),
                    nonce=grant.nonce,
                    token=token,
                    expires_at=grant.expires_at,
                )
            )
            self._reserve_budget(session, request, manifest, profile)
            self._persist_decision(session, request, decision)
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=manifest.id,
                    task_id=request.task.task_id,
                    action_id=request.action.action_id,
                    event_type=(
                        "policy.r4_granted"
                        if profile.risk_tier == RiskTier.R4_EXTENDED_OPERATIONS
                        else "policy.grant_created"
                    ),
                    actor=request.actor,
                    before_json={},
                    after_json={
                        "grant_id": grant.grant_id,
                        "profile": profile.name,
                        "risk_tier": profile.risk_tier.value,
                    },
                    details_json={"approval_id": approval_id, "pass_number": pass_number},
                )
            )
            return AuthorizationOutcome(
                decision=decision,
                grant_token=token,
                grant=grant,
                profile=profile,
                approval_id=approval_id,
            )

    def consume_grant(self, token: str, *, expected_action: ProposedAction) -> ExecutionGrantClaims:
        claims = self.grants.verify(token)
        if claims.action_id != expected_action.action_id:
            raise AuthorizationError("execution grant action mismatch")
        if claims.arguments_hash != fingerprint(expected_action.arguments):
            raise AuthorizationError("execution grant argument binding mismatch")
        with self.database.transaction(immediate=True) as session:
            row = session.get(ExecutionGrantRow, claims.grant_id)
            if row is None or not hmac.compare_digest(row.token, token):
                raise AuthorizationError("execution grant is unknown")
            if row.consumed_at is not None:
                raise AuthorizationError("execution grant nonce has already been consumed")
            expires_at = _utc(row.expires_at)
            if expires_at <= utc_now():
                raise AuthorizationError("execution grant expired")
            row.consumed_at = utc_now()
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=claims.engagement_id,
                    task_id=claims.task_id,
                    action_id=claims.action_id,
                    event_type="policy.grant_consumed",
                    actor="tool_operator",
                    before_json={"consumed": False},
                    after_json={"consumed": True},
                    details_json={"grant_id": claims.grant_id},
                )
            )
        return claims

    def _validate_request_binding(self, request: AuthorizationRequest, engagement_id: str) -> None:
        if request.task.engagement_id != engagement_id:
            raise AuthorizationError("task is not bound to the scope-token engagement")
        if request.action.task_id != request.task.task_id:
            raise AuthorizationError("action is not bound to the supplied task")
        if request.action.target_asset_id not in request.task.assets:
            raise AuthorizationError("action target is not declared on the task")

    def _validate_profile(self, request: AuthorizationRequest, manifest: Any, asset: Any, profile: CapabilityProfile) -> tuple[DecisionKind, str, str] | None:
        if profile.risk_tier.rank > manifest.maximum_risk_tier.rank:
            return DecisionKind.DENY, "RISK_CEILING_EXCEEDED", "Profile risk exceeds the signed engagement ceiling."
        if profile.risk_tier.rank > request.task.risk_tier.rank:
            return DecisionKind.DENY, "TASK_RISK_EXCEEDED", "Profile risk exceeds the task risk ceiling."
        if not profile.effects.issubset(asset.allowed_effects):
            return DecisionKind.DENY, "ASSET_EFFECTS_EXCEEDED", "Profile effects exceed the immutable asset revision."
        if not profile.effects.issubset(request.task.allowed_effects):
            return DecisionKind.DENY, "TASK_EFFECTS_EXCEEDED", "Profile effects exceed the typed task contract."
        if profile.effects & request.task.prohibited_effects:
            return DecisionKind.DENY, "PROHIBITED_EFFECT", "Profile requests an explicitly prohibited task effect."
        if profile.network and not bool(asset.network_policy.get("permitted", False)):
            return DecisionKind.DENY, "NETWORK_NOT_DECLARED", "Network access is not declared for the target asset."
        if profile.risk_tier == RiskTier.R4_EXTENDED_OPERATIONS:
            flags = manifest.engagement.flags
            if not ({"extended_operations", "comprehensive_assessment"} & set(flags)):
                return DecisionKind.DENY, "R4_FLAG_REQUIRED", "R4 requires an extended-operations authorization flag."
            if not request.kill_switch_armed:
                return DecisionKind.DENY, "KILL_SWITCH_REQUIRED", "R4 requires an armed engagement kill switch."
        return None

    def _ensure_budget(self, session: Any, request: AuthorizationRequest, manifest: Any, profile: CapabilityProfile) -> None:
        budget = manifest.budgets.selected_profile()
        usage = session.scalar(
            select(BudgetUsageRow).where(
                BudgetUsageRow.engagement_id == manifest.id,
                BudgetUsageRow.task_id == request.task.task_id,
                BudgetUsageRow.budget_name == budget.name,
            )
        )
        current_calls = 0 if usage is None else usage.tool_calls
        current_runtime = 0 if usage is None else usage.tool_runtime_seconds
        current_bytes = 0 if usage is None else usage.artifact_bytes
        cost = request.action.estimated_cost
        if current_calls + cost.tool_calls > budget.limits.max_tool_calls_per_task:
            raise BudgetExceeded("task tool-call budget exhausted; decompose within the root hard ceiling")
        if current_runtime + cost.runtime_seconds > budget.limits.max_tool_runtime_seconds:
            raise BudgetExceeded("task runtime budget exhausted; decompose within the root hard ceiling")
        if current_bytes + cost.artifact_bytes > budget.limits.max_artifact_bytes:
            raise BudgetExceeded("task artifact budget exhausted; decompose within the root hard ceiling")
        if profile.risk_tier == RiskTier.R4_EXTENDED_OPERATIONS:
            limit = {"default": 5, "extended": 100, "comprehensive": 1000}[budget.name]
            count = session.scalar(
                select(func.count()).select_from(AuditEventRow).where(
                    AuditEventRow.engagement_id == manifest.id,
                    AuditEventRow.event_type == "policy.r4_granted",
                )
            ) or 0
            if count >= limit:
                raise BudgetExceeded("engagement R4 action rate limit exhausted")

    def _reserve_budget(self, session: Any, request: AuthorizationRequest, manifest: Any, profile: CapabilityProfile) -> None:
        budget = manifest.budgets.selected_profile()
        usage = session.scalar(
            select(BudgetUsageRow).where(
                BudgetUsageRow.engagement_id == manifest.id,
                BudgetUsageRow.task_id == request.task.task_id,
                BudgetUsageRow.budget_name == budget.name,
            )
        )
        if usage is None:
            usage = BudgetUsageRow(
                engagement_id=manifest.id,
                task_id=request.task.task_id,
                budget_name=budget.name,
            )
            session.add(usage)
            session.flush()
        cost = request.action.estimated_cost
        usage.model_turns += cost.model_turns
        usage.tool_calls += cost.tool_calls
        usage.tool_runtime_seconds += cost.runtime_seconds
        usage.artifact_bytes += cost.artifact_bytes
        usage.retry_attempts += cost.retries
        usage.updated_at = utc_now()

    def _find_approval(self, session: Any, *, request: AuthorizationRequest, tool: ToolManifest, profile: CapabilityProfile, asset_versioned_id: str) -> ApprovalRow | None:
        now = utc_now()
        rows = session.scalars(
            select(ApprovalRow).where(
                ApprovalRow.engagement_id == request.task.engagement_id,
                ApprovalRow.action_template == tool.name,
                ApprovalRow.asset_versioned_id == asset_versioned_id,
                ApprovalRow.tool_version == tool.version,
                ApprovalRow.revoked.is_(False),
                ApprovalRow.expires_at > now,
            )
        ).all()
        for row in rows:
            if not set(profile.effects).issubset(set(row.effect_classes_json)):
                continue
            if not self._approval_signature_valid(row):
                continue
            schema = {
                "type": "object",
                "properties": row.parameter_ranges_json,
                "required": sorted(row.parameter_ranges_json),
                "additionalProperties": False,
            }
            if not list(Draft202012Validator(schema).iter_errors(request.action.arguments)):
                return row
        return None

    def _auto_approve(self, session: Any, *, request: AuthorizationRequest, tool: ToolManifest, profile: CapabilityProfile, asset_versioned_id: str) -> ApprovalRow:
        now = utc_now()
        payload = {
            "approval_id": new_id("APPROVAL"),
            "engagement_id": request.task.engagement_id,
            "action_template": tool.name,
            "asset_versioned_id": asset_versioned_id,
            "tool_version": tool.version,
            "effect_classes": sorted(profile.effects),
            "parameter_ranges": _ranges(request.action.arguments),
            "actor": request.actor,
            "auto_granted": True,
            "issued_at": now,
            "expires_at": now + timedelta(minutes=15),
        }
        row = ApprovalRow(
            approval_id=payload["approval_id"],
            engagement_id=payload["engagement_id"],
            action_template=payload["action_template"],
            asset_versioned_id=payload["asset_versioned_id"],
            tool_version=payload["tool_version"],
            effect_classes_json=payload["effect_classes"],
            parameter_ranges_json=payload["parameter_ranges"],
            actor=payload["actor"],
            auto_granted=True,
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            signature=self._sign(payload),
        )
        session.add(row)
        session.flush()
        return row

    def _approval_signature_valid(self, row: ApprovalRow) -> bool:
        payload = {
            "approval_id": row.approval_id,
            "engagement_id": row.engagement_id,
            "action_template": row.action_template,
            "asset_versioned_id": row.asset_versioned_id,
            "tool_version": row.tool_version,
            "effect_classes": row.effect_classes_json,
            "parameter_ranges": row.parameter_ranges_json,
            "actor": row.actor,
            "auto_granted": row.auto_granted,
            "issued_at": _utc(row.issued_at),
            "expires_at": _utc(row.expires_at),
        }
        return hmac.compare_digest(row.signature, self._sign(payload))

    def _non_grant(self, request: AuthorizationRequest, pass_number: int, kind: DecisionKind, code: str, message: str, *, before: dict[str, Any] | None = None, after: dict[str, Any] | None = None) -> AuthorizationOutcome:
        decision = self._decision(pass_number, kind, code, message, before=before, after=after)
        with self.database.transaction(immediate=True) as session:
            self._persist_decision(session, request, decision)
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=request.task.engagement_id,
                    task_id=request.task.task_id,
                    action_id=request.action.action_id,
                    event_type="policy.non_grant_decision",
                    actor=request.actor,
                    before_json=decision.configuration_before,
                    after_json=decision.configuration_after,
                    details_json={"decision": kind.value, "reason_code": code, "pass_number": pass_number},
                )
            )
        return AuthorizationOutcome(decision=decision)

    def _decision(self, pass_number: int, kind: DecisionKind, code: str, message: str, *, before: dict[str, Any] | None = None, after: dict[str, Any] | None = None) -> PolicyDecision:
        return PolicyDecision(
            decision_id=new_id("DECISION"),
            pass_number=pass_number,
            decision=kind,
            reason_code=code,
            message=message,
            configuration_before=before or {},
            configuration_after=after or {},
        )

    def _persist_decision(self, session: Any, request: AuthorizationRequest, decision: PolicyDecision) -> None:
        session.add(
            PolicyDecisionRow(
                decision_id=decision.decision_id,
                action_id=request.action.action_id,
                pass_number=decision.pass_number,
                decision=decision.decision.value,
                reason_code=decision.reason_code,
                configuration_before_json=decision.configuration_before,
                configuration_after_json=decision.configuration_after,
                details_json={"message": decision.message},
            )
        )

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self.signing_key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()


def _ranges(arguments: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in arguments.items():
        if isinstance(value, bool):
            result[name] = {"type": "boolean", "const": value}
        elif isinstance(value, int) and any(key in name.lower() for key in ("timeout", "limit", "count", "max")):
            result[name] = {"type": "integer", "minimum": 0, "maximum": value}
        elif isinstance(value, int):
            result[name] = {"type": "integer", "const": value}
        elif isinstance(value, str):
            result[name] = {"type": "string", "const": value}
        elif isinstance(value, list):
            result[name] = {"type": "array", "const": value}
        elif isinstance(value, dict):
            result[name] = {"type": "object", "const": value}
        elif value is None:
            result[name] = {"type": "null"}
        else:
            result[name] = {"const": value}
    return result


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
