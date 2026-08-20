from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cyberkimi.core import DataClassification, new_id
from cyberkimi.engagement.service import EngagementService
from cyberkimi.evidence import (
    ArtifactStore,
    CredentialVault,
    EvidenceRecord,
    EvidenceStore,
    extract_secrets,
    prepare_for_model,
)
from cyberkimi.errors import ToolExecutionError
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import AuditEventRow, ToolRunRow
from cyberkimi.policy import PolicyEngine
from cyberkimi.tasking import ProposedAction, TaskSpec
from cyberkimi.tools.handlers import HandlerRegistry
from cyberkimi.tools.registry import ToolRegistry


class ToolOperator:
    def __init__(
        self,
        *,
        database: Database,
        engagements: EngagementService,
        policy: PolicyEngine,
        tools: ToolRegistry,
        handlers: HandlerRegistry,
        artifacts: ArtifactStore,
        evidence: EvidenceStore,
        vault: CredentialVault,
    ) -> None:
        self.database = database
        self.engagements = engagements
        self.policy = policy
        self.tools = tools
        self.handlers = handlers
        self.artifacts = artifacts
        self.evidence = evidence
        self.vault = vault

    def execute(self, *, task: TaskSpec, action: ProposedAction, grant_token: str) -> EvidenceRecord:
        started = time.monotonic()
        grant = self.policy.consume_grant(grant_token, expected_action=action)
        asset = self.engagements.resolve_asset(grant.engagement_id, grant.asset_versioned_id)
        manifest = self.engagements.get_manifest(grant.engagement_id)
        tool = self.tools.require(action.action_template)
        profile = tool.profile(grant.profile_name, engagement_flags=manifest.engagement.flags)
        if profile.effects != grant.effects:
            raise ToolExecutionError("execution profile no longer matches the signed grant")
        handler = self.handlers.require(tool.name)
        run_id = new_id("RUN")
        try:
            output = handler(_asset_path(asset.canonical_location), action.arguments)
            if len(output.raw) > profile.runtime.output_bytes:
                raise ToolExecutionError("tool output exceeded the signed profile limit")
            artifact = self.artifacts.persist(
                output.raw,
                media_type=output.media_type,
                source_run_id=run_id,
            )
            vault_refs: list[str] = []
            raw_text = output.raw.decode("utf-8", errors="replace")
            for secret_type, value in extract_secrets(raw_text):
                vault_refs.append(
                    self.vault.store(
                        value,
                        secret_type=secret_type,
                        source_artifact_id=artifact.artifact_id,
                        metadata={"run_id": run_id, "tool": tool.name},
                    )
                )
            classification = DataClassification(asset.data_classification)
            model_evidence = prepare_for_model(output.normalized, classification)
            evidence = EvidenceRecord(
                task_id=task.task_id,
                asset_versioned_id=asset.versioned_id,
                evidence_type=output.evidence_type,
                evidence_class=output.evidence_class,
                summary=output.summary,
                payload=model_evidence.content,
                artifact_id=artifact.artifact_id,
                provenance={
                    "run_id": run_id,
                    "tool": tool.name,
                    "tool_version": tool.version,
                    "profile": profile.name,
                    "grant_id": grant.grant_id,
                    "artifact_sha256": artifact.sha256,
                    "classification": classification.value,
                    "redactions": model_evidence.redactions,
                    "vault_refs": vault_refs,
                },
            )
            self.evidence.record(evidence)
            self._record_run(
                run_id=run_id,
                action=action,
                grant_id=grant.grant_id,
                tool_id=tool.internal_id,
                profile_name=profile.name,
                status="completed",
                duration_ms=int((time.monotonic() - started) * 1000),
                artifact_id=artifact.artifact_id,
                result={"evidence_id": evidence.evidence_id, "summary": output.summary},
                engagement_id=grant.engagement_id,
                task_id=task.task_id,
            )
            return evidence
        except Exception as exc:
            self._record_run(
                run_id=run_id,
                action=action,
                grant_id=grant.grant_id,
                tool_id=tool.internal_id,
                profile_name=profile.name,
                status="failed",
                duration_ms=int((time.monotonic() - started) * 1000),
                artifact_id=None,
                result={"error_type": type(exc).__name__, "message": str(exc)},
                engagement_id=grant.engagement_id,
                task_id=task.task_id,
            )
            raise

    def _record_run(
        self,
        *,
        run_id: str,
        action: ProposedAction,
        grant_id: str,
        tool_id: str,
        profile_name: str,
        status: str,
        duration_ms: int,
        artifact_id: str | None,
        result: dict[str, Any],
        engagement_id: str,
        task_id: str,
    ) -> None:
        with self.database.transaction(immediate=True) as session:
            session.add(
                ToolRunRow(
                    run_id=run_id,
                    action_id=action.action_id,
                    grant_id=grant_id,
                    tool_id=tool_id,
                    profile_name=profile_name,
                    status=status,
                    exit_code=0 if status == "completed" else 1,
                    duration_ms=duration_ms,
                    stdout_artifact_id=artifact_id,
                    stderr_artifact_id=None,
                    result_json=result,
                )
            )
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=engagement_id,
                    task_id=task_id,
                    action_id=action.action_id,
                    event_type=f"tool.{status}",
                    actor="tool_operator",
                    before_json={},
                    after_json={"run_id": run_id, "status": status},
                    details_json={"tool_id": tool_id, "profile": profile_name, **result},
                )
            )


def _asset_path(location: str) -> Path:
    return Path(location).expanduser().resolve()
