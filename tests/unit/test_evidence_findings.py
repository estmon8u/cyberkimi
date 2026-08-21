from __future__ import annotations

from datetime import datetime, timezone

from cyberkimi.assets import asset_binding_digest
from cyberkimi.canonical import sha256_digest
from cyberkimi.findings import BlindVerifier
from cyberkimi.models import FindingState, ToolResult, ToolRunStatus


def test_redaction_vaults_secret(runtime, task_scope, repository_read) -> None:
    task, _token, _digest = task_scope
    engagement = runtime["engagement"]
    asset = engagement.asset(task.asset_id)
    tool, _profile = repository_read
    now = datetime.now(timezone.utc)
    result = ToolResult(
        status=ToolRunStatus.SUCCESS,
        tool_template_id=tool.template_id,
        started_at=now,
        completed_at=now,
        structured={"content": "api_key=abcdefghijk12345"},
    )
    envelope = runtime["evidence"].from_tool_result(
        engagement,
        task.task_id,
        asset.asset_id,
        asset_binding_digest(asset),
        tool,
        "RUN-EVIDENCE",
        result,
        evidence_type="context_read",
        summary="Read source context",
    )
    assert "abcdefghijk12345" not in envelope.excerpt
    assert envelope.secret_refs
    assert runtime["vault"].reveal(engagement.engagement_id, envelope.secret_refs[0]) == "abcdefghijk12345"


def test_finding_requires_blind_verification(runtime, task_scope, repository_read) -> None:
    task, _token, _digest = task_scope
    engagement = runtime["engagement"]
    asset = engagement.asset(task.asset_id)
    tool, _profile = repository_read
    now = datetime.now(timezone.utc)
    evidences = []
    for evidence_type, run_id in (("source_match", "RUN-1"), ("context_read", "RUN-2")):
        result = ToolResult(
            status=ToolRunStatus.SUCCESS,
            tool_template_id=tool.template_id,
            started_at=now,
            completed_at=now,
            structured={"evidence_type": evidence_type},
        )
        evidences.append(
            runtime["evidence"].from_tool_result(
                engagement,
                task.task_id,
                asset.asset_id,
                asset_binding_digest(asset),
                tool.model_copy(update={"name": f"repository.{evidence_type}", "api_name": f"tool_{run_id}"}),
                run_id,
                result,
                evidence_type=evidence_type,
                summary=evidence_type,
            )
        )
    finding = runtime["findings"].create_signal(
        engagement_id=engagement.engagement_id,
        engagement_revision=engagement.revision,
        task_id=task.task_id,
        asset_id=asset.asset_id,
        finding_type="authorization_consistency",
        claim="A route lacks the expected ownership check",
        severity="medium",
        evidence_policy_id="authorization_consistency/v1",
        evidence_ids=tuple(item.evidence_id for item in evidences),
    )
    for state in (FindingState.HYPOTHESIS, FindingState.SUPPORTED, FindingState.CANDIDATE):
        finding = runtime["findings"].transition(finding.finding_id, state, confidence=0.7)
    confirmed = runtime["findings"].verify_candidate(
        finding.finding_id, tuple(evidences), BlindVerifier()
    )
    assert confirmed.state is FindingState.CONFIRMED
    assert confirmed.verifier_verdict is not None
