"""Operator-plane grant verification and typed tool execution."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import insert, update

from cyberkimi.audit import AuditStore
from cyberkimi.authorization import GrantService
from cyberkimi.canonical import sha256_digest
from cyberkimi.errors import GrantError, ToolUnavailable, ValidationFailure
from cyberkimi.ids import new_id
from cyberkimi.models import (
    Asset,
    DeploymentProfile,
    Engagement,
    ProposedAction,
    ToolManifest,
    ToolResult,
    ToolRunStatus,
)
from cyberkimi.persistence import Database, budget_reservations, tool_runs
from cyberkimi.tools import AdapterRegistry, manifest_digest, validate_tool_arguments


class Operator:
    """Execute one typed action after independently consuming its exact grant."""

    def __init__(
        self,
        database: Database,
        audit: AuditStore,
        grants: GrantService,
        adapters: AdapterRegistry,
    ):
        self.database = database
        self.audit = audit
        self.grants = grants
        self.adapters = adapters

    def execute(
        self,
        engagement: Engagement,
        asset: Asset,
        manifest: ToolManifest,
        profile: DeploymentProfile,
        action: ProposedAction,
        action_digest: str,
        grant_token: str,
    ) -> tuple[str, ToolResult]:
        validate_tool_arguments(manifest, action.arguments)
        if manifest_digest(manifest) != action.tool_manifest_digest:
            raise GrantError("operator tool manifest digest mismatch")
        if asset.asset_id != action.asset_id:
            raise GrantError("operator asset mismatch")
        grant = self.grants.verify_and_consume(
            grant_token,
            action,
            action_digest,
            engagement_id=engagement.engagement_id,
        )
        tool_run_id = new_id("RUN")
        try:
            adapter = self.adapters.get(manifest.adapter)
            result = adapter.execute(manifest, asset, action.arguments, profile)
        except ToolUnavailable as exc:
            now = datetime.now(timezone.utc)
            result = ToolResult(
                status=ToolRunStatus.TOOL_UNAVAILABLE,
                tool_template_id=manifest.template_id,
                started_at=now,
                completed_at=now,
                error_code="TOOL_UNAVAILABLE",
                stderr=str(exc),
            )
        except (ValidationFailure, OSError) as exc:
            now = datetime.now(timezone.utc)
            result = ToolResult(
                status=ToolRunStatus.FAILED,
                tool_template_id=manifest.template_id,
                started_at=now,
                completed_at=now,
                error_code="ADAPTER_FAILURE",
                stderr=str(exc),
            )
        with self.database.transaction() as connection:
            connection.execute(
                insert(tool_runs).values(
                    tool_run_id=tool_run_id,
                    grant_id=grant.grant_id,
                    action_digest=action_digest,
                    tool_template_id=manifest.template_id,
                    status=result.status.value,
                    result_json=result.model_dump_json(),
                    action_json=action.model_dump_json(),
                    asset_json=asset.model_dump_json(),
                    profile_json=profile.model_dump_json(),
                    result_digest=sha256_digest(result),
                    created_at=datetime.now(timezone.utc),
                )
            )
            connection.execute(
                update(budget_reservations)
                .where(budget_reservations.c.reservation_id == action.budget.reservation_id)
                .values(state="consumed")
            )
            self.audit.append(
                engagement.engagement_id,
                "tool.run",
                {
                    "tool_run_id": tool_run_id,
                    "action_digest": action_digest,
                    "tool_template_id": manifest.template_id,
                    "status": result.status.value,
                    "exit_code": result.exit_code,
                },
                connection=connection,
            )
        return tool_run_id, result
