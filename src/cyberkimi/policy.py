from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .authorization import AuthorizationError, ScopeSigner
from .domain import (
    ActionApproval,
    AssetRevision,
    EngagementRevision,
    ExecutionGrant,
    PolicyDecision,
    ProposedAction,
    RiskTier,
    ToolManifest,
    ToolProfile,
)
from .store import Database, canonical_json


class PolicyDenied(AuthorizationError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class AuthorizationContext:
    root_task_id: str
    actor: str
    now: datetime
    preferred_profile: str | None = None


class PolicyEngine:
    """Deterministic policy boundary.

    Every successful authorization is one atomic SQLite transaction containing
    profile resolution, approval handling, budget reservation, grant creation,
    and append-only audit persistence. Adaptive changes are represented as
    explicit before/after records, never as mutations of signed revisions.
    """

    def __init__(
        self,
        database: Database,
        signer: ScopeSigner,
        *,
        grant_ttl_seconds: int = 120,
        r4_limit_per_hour: int = 10,
    ) -> None:
        self.database = database
        self.signer = signer
        self.grant_ttl_seconds = grant_ttl_seconds
        self.r4_limit_per_hour = r4_limit_per_hour

    def authorize(
        self,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        context: AuthorizationContext,
    ) -> PolicyDecision:
        evaluation_pass = 1
        adjustments: list[dict[str, Any]] = []
        try:
            with self.database.transaction() as connection:
                self._validate_static(action, engagement, asset, tool, context)
                profile, profile_adjustments = self._resolve_profile(
                    action, engagement, asset, tool, context.preferred_profile
                )
                adjustments.extend(profile_adjustments)

                approval = self._resolve_approval(
                    connection, action, engagement, asset, tool, profile, context
                )
                self._reserve_budget(connection, action, engagement, context, profile)
                if profile.risk_tier == RiskTier.R4_EXTENDED:
                    self._reserve_r4_window(connection, engagement, context.now)

                grant = self._create_grant(action, engagement, asset, tool, profile, context)
                connection.execute(
                    "INSERT INTO execution_grants "
                    "(grant_id, nonce, engagement_id, action_id, grant_json, consumed_at, "
                    "expires_at, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                    (
                        grant.grant_id,
                        grant.nonce,
                        engagement.engagement_id,
                        action.action_id,
                        canonical_json(grant.model_dump(mode="json")),
                        grant.expires_at.isoformat(),
                        context.now.isoformat(),
                    ),
                )
                self._append_audit(
                    connection,
                    engagement.engagement_id,
                    "authorization.permitted",
                    {
                        "evaluation_pass": evaluation_pass,
                        "action": action.model_dump(mode="json"),
                        "engagement_revision": engagement.versioned_id,
                        "asset_revision": asset.versioned_id,
                        "tool_internal_id": tool.internal_id,
                        "selected_profile": profile.model_dump(mode="json"),
                        "approval_id": approval.approval_id if approval else None,
                        "adjustments": adjustments,
                        "grant_id": grant.grant_id,
                    },
                    context.now,
                )
                return PolicyDecision(
                    permitted=True,
                    reason_code="PERMITTED",
                    evaluation_pass=evaluation_pass,
                    selected_profile=profile.name,
                    grant=grant,
                    adjustments=tuple(adjustments),
                )
        except PolicyDenied as exc:
            self._record_denial(action, engagement, asset, tool, context, exc)
            return PolicyDecision(
                permitted=False,
                reason_code=exc.reason_code,
                evaluation_pass=evaluation_pass,
                requires_approval=exc.reason_code == "HUMAN_APPROVAL_REQUIRED",
                adjustments=tuple(adjustments),
            )

    def consume_grant(self, grant: ExecutionGrant, *, now: datetime | None = None) -> None:
        current = now or datetime.now(timezone.utc)
        unsigned = grant.model_dump(mode="json", exclude={"signature"})
        if not self.signer.verify(unsigned, grant.signature):
            raise PolicyDenied("INVALID_GRANT", "execution grant signature is invalid")
        if current >= grant.expires_at:
            raise PolicyDenied("EXPIRED_GRANT", "execution grant has expired")
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT consumed_at, grant_json FROM execution_grants WHERE grant_id = ? AND nonce = ?",
                (grant.grant_id, grant.nonce),
            ).fetchone()
            if row is None:
                raise PolicyDenied("UNKNOWN_GRANT", "execution grant is not registered")
            if row["consumed_at"] is not None:
                raise PolicyDenied("REPLAYED_GRANT", "execution grant has already been consumed")
            if json.loads(row["grant_json"]) != grant.model_dump(mode="json"):
                raise PolicyDenied("GRANT_MISMATCH", "execution grant does not match stored grant")
            connection.execute(
                "UPDATE execution_grants SET consumed_at = ? WHERE grant_id = ?",
                (current.isoformat(), grant.grant_id),
            )
            self._append_audit(
                connection,
                grant.engagement_revision.split("@", 1)[0],
                "execution_grant.consumed",
                {"grant_id": grant.grant_id, "nonce": grant.nonce},
                current,
            )

    def _validate_static(
        self,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        context: AuthorizationContext,
    ) -> None:
        if not engagement.active(context.now):
            raise PolicyDenied("ENGAGEMENT_INACTIVE", "engagement is not active")
        if action.engagement_id != engagement.engagement_id:
            raise PolicyDenied("ENGAGEMENT_MISMATCH", "action engagement does not match")
        if asset.engagement_id != engagement.engagement_id:
            raise PolicyDenied("ASSET_ENGAGEMENT_MISMATCH", "asset belongs to another engagement")
        if action.target_asset_id not in {asset.asset_alias, asset.versioned_id}:
            raise PolicyDenied("ASSET_MISMATCH", "action target does not resolve to supplied asset")
        if action.action_template not in {tool.internal_id, tool.kimi_alias}:
            raise PolicyDenied("TOOL_MISMATCH", "action template does not identify supplied tool")
        if asset.asset_type not in tool.accepted_asset_types:
            raise PolicyDenied("ASSET_TYPE_UNSUPPORTED", "tool does not accept this asset type")
        forbidden = action.requested_effects & engagement.prohibited_effects
        if forbidden:
            raise PolicyDenied(
                "PROHIBITED_EFFECT",
                f"action requested prohibited effects: {sorted(forbidden)}",
            )

    def _resolve_profile(
        self,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        preferred_profile: str | None,
    ) -> tuple[ToolProfile, list[dict[str, Any]]]:
        authorized = []
        for profile in (tool.base_profile, *tool.authorized_profiles):
            if (
                profile.requires_engagement_flag is not None
                and profile.requires_engagement_flag not in engagement.capability_flags
            ):
                continue
            if profile.risk_tier > engagement.maximum_risk_tier:
                continue
            if not action.requested_effects.issubset(profile.effects):
                continue
            if not profile.effects.issubset(asset.allowed_effects):
                continue
            if action.requested_timeout_seconds > profile.timeout_seconds:
                continue
            authorized.append(profile)
        if preferred_profile:
            preferred = next((p for p in authorized if p.name == preferred_profile), None)
            if preferred is None:
                raise PolicyDenied(
                    "PROFILE_NOT_AUTHORIZED", "preferred deployment profile cannot satisfy action"
                )
            return preferred, []
        if not authorized:
            raise PolicyDenied(
                "NO_AUTHORIZED_PROFILE", "no engagement-authorized profile can satisfy action"
            )
        selected = min(authorized, key=lambda item: (int(item.risk_tier), item.timeout_seconds))
        adjustments: list[dict[str, Any]] = []
        if selected.name != tool.base_profile.name:
            adjustments.append(
                {
                    "kind": "deployment_profile_selection",
                    "before": tool.base_profile.name,
                    "after": selected.name,
                    "reason": "base profile cannot satisfy action inside authorized scope",
                }
            )
        return selected, adjustments

    def _resolve_approval(
        self,
        connection: Any,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        profile: ToolProfile,
        context: AuthorizationContext,
    ) -> ActionApproval | None:
        if profile.risk_tier < RiskTier.R3_BOUNDED_VALIDATION:
            return None
        rows = connection.execute(
            "SELECT document_json FROM approvals WHERE engagement_id = ? "
            "AND action_template = ? AND target_asset_revision = ? "
            "AND tool_internal_id = ? AND expires_at > ? ORDER BY created_at DESC",
            (
                engagement.engagement_id,
                action.action_template,
                asset.versioned_id,
                tool.internal_id,
                context.now.isoformat(),
            ),
        ).fetchall()
        for row in rows:
            approval = ActionApproval.model_validate(json.loads(row["document_json"]))
            if action.requested_effects.issubset(approval.allowed_effects) and approval.permits_arguments(
                action.arguments
            ):
                return approval
        if not engagement.self_attested_approvals:
            raise PolicyDenied("HUMAN_APPROVAL_REQUIRED", "matching action-class approval required")
        approval = ActionApproval(
            approval_id=f"APR-{uuid.uuid4().hex}",
            engagement_id=engagement.engagement_id,
            action_template=action.action_template,
            target_asset_revision=asset.versioned_id,
            tool_internal_id=tool.internal_id,
            allowed_effects=action.requested_effects,
            actor=context.actor,
            issued_at=context.now,
            expires_at=min(context.now + timedelta(minutes=15), engagement.expires_at),
            auto_granted=True,
        )
        connection.execute(
            "INSERT INTO approvals "
            "(approval_id, engagement_id, action_template, target_asset_revision, "
            "tool_internal_id, document_json, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                approval.approval_id,
                approval.engagement_id,
                approval.action_template,
                approval.target_asset_revision,
                approval.tool_internal_id,
                canonical_json(approval.model_dump(mode="json")),
                approval.expires_at.isoformat(),
                context.now.isoformat(),
            ),
        )
        self._append_audit(
            connection,
            engagement.engagement_id,
            "approval.auto_granted",
            approval.model_dump(mode="json"),
            context.now,
        )
        return approval

    def _reserve_budget(
        self,
        connection: Any,
        action: ProposedAction,
        engagement: EngagementRevision,
        context: AuthorizationContext,
        profile: ToolProfile,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM budget_usage WHERE root_task_id = ?",
            (context.root_task_id,),
        ).fetchone()
        current_calls = 0 if row is None else int(row["tool_calls"])
        current_runtime = 0 if row is None else int(row["runtime_seconds"])
        if current_calls + 1 > engagement.budget.max_tool_calls_per_task:
            raise PolicyDenied("TOOL_CALL_BUDGET_EXHAUSTED", "root task tool-call ceiling reached")
        reserved_runtime = min(action.requested_timeout_seconds, profile.timeout_seconds)
        hard_runtime = engagement.budget.max_tool_runtime_seconds * max(
            1, engagement.budget.max_tool_calls_per_task
        )
        if current_runtime + reserved_runtime > hard_runtime:
            raise PolicyDenied("RUNTIME_BUDGET_EXHAUSTED", "root task runtime ceiling reached")
        timestamp = context.now.isoformat()
        if row is None:
            connection.execute(
                "INSERT INTO budget_usage "
                "(root_task_id, engagement_id, tool_calls, runtime_seconds, artifact_bytes, "
                "model_turns, updated_at) VALUES (?, ?, 1, ?, 0, 0, ?)",
                (context.root_task_id, engagement.engagement_id, reserved_runtime, timestamp),
            )
        else:
            connection.execute(
                "UPDATE budget_usage SET tool_calls = tool_calls + 1, "
                "runtime_seconds = runtime_seconds + ?, updated_at = ? WHERE root_task_id = ?",
                (reserved_runtime, timestamp, context.root_task_id),
            )

    def _reserve_r4_window(
        self, connection: Any, engagement: EngagementRevision, now: datetime
    ) -> None:
        cutoff = now - timedelta(hours=1)
        connection.execute(
            "DELETE FROM r4_execution_windows WHERE engagement_id = ? AND executed_at < ?",
            (engagement.engagement_id, cutoff.isoformat()),
        )
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM r4_execution_windows WHERE engagement_id = ?",
            (engagement.engagement_id,),
        ).fetchone()["count"]
        if int(count) >= self.r4_limit_per_hour:
            raise PolicyDenied("R4_RATE_LIMITED", "engagement R4 rate limit reached")
        connection.execute(
            "INSERT INTO r4_execution_windows (engagement_id, executed_at) VALUES (?, ?)",
            (engagement.engagement_id, now.isoformat()),
        )

    def _create_grant(
        self,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        profile: ToolProfile,
        context: AuthorizationContext,
    ) -> ExecutionGrant:
        unsigned = {
            "grant_id": f"GRT-{uuid.uuid4().hex}",
            "nonce": secrets.token_urlsafe(24),
            "engagement_revision": engagement.versioned_id,
            "asset_revision": asset.versioned_id,
            "action_id": action.action_id,
            "tool_internal_id": tool.internal_id,
            "deployment_profile": profile.name,
            "effective_effects": sorted(action.requested_effects),
            "effective_timeout_seconds": min(
                action.requested_timeout_seconds, profile.timeout_seconds
            ),
            "issued_at": context.now.isoformat(),
            "expires_at": min(
                context.now + timedelta(seconds=self.grant_ttl_seconds), engagement.expires_at
            ).isoformat(),
        }
        signature = self.signer.sign(unsigned)
        return ExecutionGrant.model_validate({**unsigned, "signature": signature})

    def _append_audit(
        self,
        connection: Any,
        engagement_id: str,
        event_type: str,
        payload: dict[str, Any],
        created_at: datetime,
    ) -> None:
        previous = connection.execute(
            "SELECT event_hash FROM audit_events WHERE engagement_id = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (engagement_id,),
        ).fetchone()
        prior_hash = None if previous is None else str(previous["event_hash"])
        event_id = f"AUD-{uuid.uuid4().hex}"
        body = {
            "event_id": event_id,
            "engagement_id": engagement_id,
            "event_type": event_type,
            "payload": payload,
            "prior_event_hash": prior_hash,
            "created_at": created_at.isoformat(),
        }
        event_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        connection.execute(
            "INSERT INTO audit_events "
            "(event_id, engagement_id, event_type, payload_json, prior_event_hash, "
            "event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                engagement_id,
                event_type,
                canonical_json(payload),
                prior_hash,
                event_hash,
                created_at.isoformat(),
            ),
        )

    def _record_denial(
        self,
        action: ProposedAction,
        engagement: EngagementRevision,
        asset: AssetRevision,
        tool: ToolManifest,
        context: AuthorizationContext,
        error: PolicyDenied,
    ) -> None:
        with self.database.transaction() as connection:
            self._append_audit(
                connection,
                engagement.engagement_id,
                "authorization.denied",
                {
                    "action_id": action.action_id,
                    "asset_revision": asset.versioned_id,
                    "tool_internal_id": tool.internal_id,
                    "reason_code": error.reason_code,
                    "message": str(error),
                },
                context.now,
            )
