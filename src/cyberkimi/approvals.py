"""Exact-action approval queue and human-readable previews."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import Field
from sqlalchemy import insert, select, update

from cyberkimi.audit import AuditStore
from cyberkimi.authorization import ApprovalService, action_digest
from cyberkimi.errors import ValidationFailure
from cyberkimi.models import (
    DeploymentProfile,
    Engagement,
    ProposedAction,
    StrictModel,
    TaskSpec,
    ToolManifest,
)
from cyberkimi.persistence import Database, pending_actions


class ActionPreview(StrictModel):
    action_id: str
    task_id: str
    subtask_id: str | None
    tool_template_id: str
    tool_manifest_digest: str
    target_asset_id: str
    asset_binding_digest: str
    normalized_arguments: dict[str, Any]
    requested_effects: tuple[str, ...]
    risk_tier: str
    network_mode: str
    maximum_runtime_seconds: int
    maximum_output_bytes: int
    credential_handles: tuple[str, ...] = ()
    rollback_or_reset: str = "not applicable"
    approval_expires_in_seconds: int = Field(default=600, ge=1, le=3600)


class QueuedAction(StrictModel):
    action: ProposedAction
    action_digest: str
    engagement_id: str
    status: Literal["pending", "approved", "denied", "consumed", "cancelled"]
    preview: ActionPreview
    created_at: datetime
    updated_at: datetime


class ApprovalQueue:
    def __init__(
        self,
        database: Database,
        audit: AuditStore,
        approvals_service: ApprovalService,
    ):
        self.database = database
        self.audit = audit
        self.approvals = approvals_service

    def enqueue(
        self,
        engagement: Engagement,
        task: TaskSpec,
        tool: ToolManifest,
        profile: DeploymentProfile,
        action: ProposedAction,
        *,
        rollback_or_reset: str = "not applicable",
    ) -> QueuedAction:
        digest = action_digest(engagement, task, action, tool)
        credentials = tuple(
            sorted(
                str(value)
                for key, value in action.arguments.items()
                if "credential" in key.lower() and isinstance(value, str)
            )
        )
        preview = ActionPreview(
            action_id=action.action_id,
            task_id=task.task_id,
            subtask_id=action.subtask_id,
            tool_template_id=tool.template_id,
            tool_manifest_digest=action.tool_manifest_digest,
            target_asset_id=action.asset_id,
            asset_binding_digest=action.asset_binding_digest,
            normalized_arguments=action.arguments,
            requested_effects=tuple(sorted(action.requested_effects)),
            risk_tier=action.risk_tier.name,
            network_mode=profile.network_mode,
            maximum_runtime_seconds=action.budget.runtime_seconds,
            maximum_output_bytes=profile.output_bytes,
            credential_handles=credentials,
            rollback_or_reset=rollback_or_reset,
        )
        now = datetime.now(timezone.utc)
        queued = QueuedAction(
            action=action,
            action_digest=digest,
            engagement_id=engagement.engagement_id,
            status="pending",
            preview=preview,
            created_at=now,
            updated_at=now,
        )
        with self.database.transaction() as connection:
            existing = connection.execute(
                select(pending_actions.c.action_id).where(
                    pending_actions.c.action_digest == digest
                )
            ).first()
            if existing is None:
                connection.execute(
                    insert(pending_actions).values(
                        action_id=action.action_id,
                        engagement_id=engagement.engagement_id,
                        task_id=task.task_id,
                        action_digest=digest,
                        status="pending",
                        action_json=action.model_dump_json(),
                        preview_json=preview.model_dump_json(),
                        created_at=now,
                        updated_at=now,
                    )
                )
                self.audit.append(
                    engagement.engagement_id,
                    "approval.queued",
                    {
                        "action_id": action.action_id,
                        "task_id": task.task_id,
                        "action_digest": digest,
                        "risk_tier": action.risk_tier.name,
                    },
                    connection=connection,
                )
            else:
                return self.get(str(existing.action_id))
        return queued

    def get(self, action_id: str) -> QueuedAction:
        row = self.database.fetch_one(
            select(pending_actions).where(pending_actions.c.action_id == action_id)
        )
        if row is None:
            raise KeyError(action_id)
        return QueuedAction(
            action=ProposedAction.model_validate_json(str(row["action_json"])),
            action_digest=str(row["action_digest"]),
            engagement_id=str(row["engagement_id"]),
            status=str(row["status"]),  # type: ignore[arg-type]
            preview=ActionPreview.model_validate_json(str(row["preview_json"])),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list(
        self,
        *,
        engagement_id: str | None = None,
        status: str | None = None,
    ) -> list[QueuedAction]:
        statement = select(pending_actions).order_by(pending_actions.c.created_at.asc())
        if engagement_id is not None:
            statement = statement.where(pending_actions.c.engagement_id == engagement_id)
        if status is not None:
            statement = statement.where(pending_actions.c.status == status)
        rows = self.database.fetch_all(statement)
        return [
            QueuedAction(
                action=ProposedAction.model_validate_json(str(row["action_json"])),
                action_digest=str(row["action_digest"]),
                engagement_id=str(row["engagement_id"]),
                status=str(row["status"]),  # type: ignore[arg-type]
                preview=ActionPreview.model_validate_json(str(row["preview_json"])),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    def decide(
        self,
        action_id: str,
        *,
        actor_id: str,
        decision: Literal["approved", "denied"],
        expires_in: timedelta = timedelta(minutes=10),
        comment: str = "",
    ) -> QueuedAction:
        queued = self.get(action_id)
        if queued.status != "pending":
            raise ValidationFailure("only pending actions may be approved or denied")
        self.approvals.record(
            queued.engagement_id,
            queued.action_digest,
            actor_id,
            decision,
            expires_in=expires_in,
            comment=comment,
        )
        now = datetime.now(timezone.utc)
        with self.database.transaction() as connection:
            result = connection.execute(
                update(pending_actions)
                .where(
                    pending_actions.c.action_id == action_id,
                    pending_actions.c.status == "pending",
                )
                .values(status=decision, updated_at=now)
            )
            if result.rowcount != 1:
                raise ValidationFailure("approval queue state changed concurrently")
            self.audit.append(
                queued.engagement_id,
                "approval.queue_decision",
                {
                    "action_id": action_id,
                    "action_digest": queued.action_digest,
                    "decision": decision,
                    "actor_id": actor_id,
                },
                connection=connection,
            )
        return self.get(action_id)

    def mark_consumed(self, action_digest_value: str) -> None:
        now = datetime.now(timezone.utc)
        with self.database.transaction() as connection:
            connection.execute(
                update(pending_actions)
                .where(pending_actions.c.action_digest == action_digest_value)
                .values(status="consumed", updated_at=now)
            )
