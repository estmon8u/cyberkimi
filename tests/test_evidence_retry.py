from __future__ import annotations

from datetime import datetime, timezone

from cyberkimi.data_handling import prepare_for_model
from cyberkimi.domain import DataClassification, EvidenceRecord, VerificationResult
from cyberkimi.evidence import EVIDENCE_POLICIES, route_trace_verifier
from cyberkimi.retry import NonResponseCategory, RetryManager, RetryStrategy


def evidence(evidence_type: str, evidence_class: str) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=f"E-{evidence_type}",
        task_id="TASK-1",
        asset_revision="repo:service@1",
        evidence_type=evidence_type,
        evidence_class=evidence_class,
        payload={},
        created_at=datetime.now(timezone.utc),
    )


def test_confidential_content_is_redacted() -> None:
    prepared = prepare_for_model(
        DataClassification.CONFIDENTIAL,
        "password=super-secret-value and owner@example.com",
    )
    assert "super-secret-value" not in prepared.text
    assert "owner@example.com" not in prepared.text
    assert prepared.redaction_count == 2
    assert len(prepared.vault_candidates) == 1


def test_restricted_content_is_replaced_by_fact_summary() -> None:
    raw = "Authorization denied for token=top-secret-token-value at owner@example.com"
    prepared = prepare_for_model(DataClassification.RESTRICTED, raw)
    assert raw not in prepared.text
    assert "top-secret-token-value" not in prepared.text
    assert "RESTRICTED_CONTENT_SUMMARY" in prepared.text
    assert prepared.transformed


def test_authorization_policy_requires_all_typed_evidence() -> None:
    records = [
        evidence("source_location", "source"),
        evidence("route_to_handler", "trace"),
        evidence("missing_enforcement", "source"),
        evidence("counterevidence_search", "search"),
    ]
    verification = VerificationResult(
        verdict="confirmed",
        claim_supported=True,
        impact_supported=True,
        confidence=0.95,
    )
    policy = EVIDENCE_POLICIES["authorization_inconsistency"]
    accepted, missing = policy.evaluate(records, route_trace_verifier(records), verification)
    assert accepted
    assert not missing


def test_provider_boundary_escalation_is_bounded() -> None:
    manager = RetryManager(maximum_attempts=5)
    event = RetryManager.classify(
        status_code=400,
        provider_code="CONTENT_POLICY",
        body="provider policy boundary",
    )
    assert event.category == NonResponseCategory.PROVIDER_POLICY
    outcomes = [manager.next_outcome(event, attempt=index) for index in range(6)]
    assert [outcome.strategy for outcome in outcomes[:5]] == [
        RetryStrategy.TECHNICAL_RETRY,
        RetryStrategy.CONTEXT_NARROWING,
        RetryStrategy.TERMINAL_QUESTION,
        RetryStrategy.SESSION_DECOMPOSITION,
        RetryStrategy.DETERMINISTIC_INVESTIGATION,
    ]
    assert not outcomes[5].retry
    assert outcomes[5].strategy == RetryStrategy.EXHAUSTED
    assert not outcomes[2].include_original_triggering_context
