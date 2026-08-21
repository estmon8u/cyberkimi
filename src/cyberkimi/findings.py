"""Finding lifecycle, typed evidence policies, deduplication, and blind verification."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from cyberkimi.audit import AuditStore
from cyberkimi.canonical import sha256_digest
from cyberkimi.errors import ValidationFailure
from cyberkimi.ids import new_id
from cyberkimi.models import EvidenceEnvelope, Finding, FindingState, VerificationVerdict
from cyberkimi.persistence import Database, findings

_ALLOWED_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.SIGNAL: frozenset({FindingState.HYPOTHESIS, FindingState.REJECTED}),
    FindingState.HYPOTHESIS: frozenset(
        {FindingState.SUPPORTED, FindingState.REJECTED, FindingState.UNRESOLVED}
    ),
    FindingState.SUPPORTED: frozenset(
        {FindingState.CANDIDATE, FindingState.REJECTED, FindingState.UNRESOLVED}
    ),
    FindingState.CANDIDATE: frozenset(
        {FindingState.CONFIRMED, FindingState.REJECTED, FindingState.UNRESOLVED}
    ),
    FindingState.CONFIRMED: frozenset(),
    FindingState.REJECTED: frozenset(),
    FindingState.UNRESOLVED: frozenset({FindingState.SUPPORTED, FindingState.REJECTED}),
}


class EvidencePolicy(Protocol):
    policy_id: str

    def evaluate(
        self,
        finding_type: str,
        evidence_items: tuple[EvidenceEnvelope, ...],
    ) -> tuple[bool, tuple[str, ...]]: ...


class VersionedEvidencePolicy:
    def __init__(
        self,
        policy_id: str,
        required_types: frozenset[str],
        *,
        minimum_items: int = 1,
        require_distinct_tools: int = 1,
    ):
        self.policy_id = policy_id
        self.required_types = required_types
        self.minimum_items = minimum_items
        self.require_distinct_tools = require_distinct_tools

    def evaluate(
        self,
        finding_type: str,
        evidence_items: tuple[EvidenceEnvelope, ...],
    ) -> tuple[bool, tuple[str, ...]]:
        missing: list[str] = []
        observed_types = {item.evidence_type for item in evidence_items}
        for required in sorted(self.required_types - observed_types):
            missing.append(f"missing evidence type: {required}")
        if len(evidence_items) < self.minimum_items:
            missing.append(f"requires at least {self.minimum_items} evidence items")
        distinct_tools = {item.tool_template_id for item in evidence_items}
        if len(distinct_tools) < self.require_distinct_tools:
            missing.append(f"requires evidence from {self.require_distinct_tools} distinct tools")
        if any(not item.provenance or not item.artifact_digest for item in evidence_items):
            missing.append("all evidence must include provenance and a raw artifact digest")
        return not missing, tuple(missing)


DEFAULT_POLICIES: dict[str, VersionedEvidencePolicy] = {
    "authorization_consistency/v1": VersionedEvidencePolicy(
        "authorization_consistency/v1",
        frozenset({"source_match", "context_read"}),
        minimum_items=2,
        require_distinct_tools=2,
    ),
    "dependency_advisory/v1": VersionedEvidencePolicy(
        "dependency_advisory/v1",
        frozenset({"dependency_manifest", "advisory_match"}),
        minimum_items=2,
        require_distinct_tools=2,
    ),
    "secret_exposure/v1": VersionedEvidencePolicy(
        "secret_exposure/v1",
        frozenset({"secret_signal", "context_read"}),
        minimum_items=2,
        require_distinct_tools=2,
    ),
    "configuration/v1": VersionedEvidencePolicy(
        "configuration/v1",
        frozenset({"configuration_signal", "context_read"}),
        minimum_items=2,
        require_distinct_tools=1,
    ),
    "hunt_correlation/v1": VersionedEvidencePolicy(
        "hunt_correlation/v1",
        frozenset({"event_signal", "correlation"}),
        minimum_items=2,
        require_distinct_tools=1,
    ),
    "lab_property/v1": VersionedEvidencePolicy(
        "lab_property/v1",
        frozenset({"lab_observation", "lab_property_result"}),
        minimum_items=2,
        require_distinct_tools=1,
    ),
}


class BlindVerifier:
    """A verifier interface that receives evidence but not Director confidence."""

    def verify(
        self,
        claim: str,
        finding_type: str,
        policy: VersionedEvidencePolicy,
        evidence_items: tuple[EvidenceEnvelope, ...],
    ) -> VerificationVerdict:
        sufficient, missing = policy.evaluate(finding_type, evidence_items)
        if not sufficient:
            verdict = "unresolved"
            rationale = "Typed evidence policy is not satisfied."
        elif any("counterevidence" in item.evidence_type for item in evidence_items):
            verdict = "reject"
            rationale = "Recorded counterevidence contradicts the claim."
        else:
            verdict = "confirm"
            rationale = "Evidence-policy requirements are satisfied and no recorded counterevidence contradicts the claim."
        return VerificationVerdict(
            verifier_id="deterministic-blind-verifier/v1",
            verdict=verdict,
            rationale=rationale,
            checked_evidence_ids=tuple(item.evidence_id for item in evidence_items),
            missing_requirements=missing,
        )


class FindingStore:
    def __init__(self, database: Database, audit: AuditStore):
        self.database = database
        self.audit = audit

    def create_signal(
        self,
        *,
        engagement_id: str,
        engagement_revision: int,
        task_id: str,
        asset_id: str,
        finding_type: str,
        claim: str,
        severity: str,
        evidence_policy_id: str,
        evidence_ids: tuple[str, ...],
        remediation: str = "",
    ) -> Finding:
        if evidence_policy_id not in DEFAULT_POLICIES:
            raise ValidationFailure(f"unknown evidence policy: {evidence_policy_id}")
        dedupe_key = sha256_digest(
            {
                "asset_id": asset_id,
                "finding_type": finding_type,
                "claim": " ".join(claim.lower().split()),
            }
        )
        finding = Finding(
            finding_id=new_id("FIND"),
            engagement_id=engagement_id,
            engagement_revision=engagement_revision,
            task_id=task_id,
            asset_id=asset_id,
            finding_type=finding_type,
            claim=claim,
            state=FindingState.SIGNAL,
            severity=severity,  # type: ignore[arg-type]
            confidence=0.0,
            evidence_policy_id=evidence_policy_id,
            evidence_ids=evidence_ids,
            remediation=remediation,
        )
        try:
            with self.database.transaction() as connection:
                connection.execute(
                    insert(findings).values(
                        finding_id=finding.finding_id,
                        engagement_id=finding.engagement_id,
                        task_id=finding.task_id,
                        asset_id=finding.asset_id,
                        state=finding.state.value,
                        dedupe_key=dedupe_key,
                        finding_json=finding.model_dump_json(),
                        updated_at=finding.updated_at,
                    )
                )
                self.audit.append(
                    engagement_id,
                    "finding.created",
                    {
                        "finding_id": finding.finding_id,
                        "state": finding.state.value,
                        "finding_type": finding_type,
                        "dedupe_key": dedupe_key,
                    },
                    connection=connection,
                )
            return finding
        except IntegrityError:
            row = self.database.fetch_one(
                select(findings.c.finding_json).where(
                    findings.c.engagement_id == engagement_id,
                    findings.c.dedupe_key == dedupe_key,
                )
            )
            if row is None:
                raise
            return Finding.model_validate_json(str(row["finding_json"]))

    def get(self, finding_id: str) -> Finding:
        row = self.database.fetch_one(
            select(findings.c.finding_json).where(findings.c.finding_id == finding_id)
        )
        if row is None:
            raise KeyError(finding_id)
        return Finding.model_validate_json(str(row["finding_json"]))

    def list_for_engagement(self, engagement_id: str) -> list[Finding]:
        rows = self.database.fetch_all(
            select(findings.c.finding_json)
            .where(findings.c.engagement_id == engagement_id)
            .order_by(findings.c.updated_at.asc())
        )
        return [Finding.model_validate_json(str(row["finding_json"])) for row in rows]

    def transition(
        self,
        finding_id: str,
        target: FindingState,
        *,
        confidence: float | None = None,
        verifier_verdict: VerificationVerdict | None = None,
    ) -> Finding:
        current = self.get(finding_id)
        if target not in _ALLOWED_TRANSITIONS[current.state]:
            raise ValidationFailure(f"invalid finding transition: {current.state} -> {target}")
        if target is FindingState.CONFIRMED:
            if verifier_verdict is None or verifier_verdict.verdict != "confirm":
                raise ValidationFailure("confirmed finding requires an independent confirm verdict")
            if verifier_verdict.missing_requirements:
                raise ValidationFailure("confirmed finding has unsatisfied evidence requirements")
        now = datetime.now(timezone.utc)
        updated = current.model_copy(
            update={
                "state": target,
                "confidence": current.confidence if confidence is None else confidence,
                "verifier_verdict": verifier_verdict or current.verifier_verdict,
                "updated_at": now,
            }
        )
        with self.database.transaction() as connection:
            connection.execute(
                update(findings)
                .where(findings.c.finding_id == finding_id)
                .values(
                    state=target.value,
                    finding_json=updated.model_dump_json(),
                    updated_at=now,
                )
            )
            self.audit.append(
                current.engagement_id,
                "finding.transition",
                {
                    "finding_id": finding_id,
                    "from": current.state.value,
                    "to": target.value,
                    "verifier_id": verifier_verdict.verifier_id if verifier_verdict else None,
                },
                connection=connection,
            )
        return updated

    def verify_candidate(
        self,
        finding_id: str,
        evidence_items: tuple[EvidenceEnvelope, ...],
        verifier: BlindVerifier,
    ) -> Finding:
        current = self.get(finding_id)
        if current.state is not FindingState.CANDIDATE:
            raise ValidationFailure("only candidate findings may be independently verified")
        policy = DEFAULT_POLICIES[current.evidence_policy_id]
        verdict = verifier.verify(current.claim, current.finding_type, policy, evidence_items)
        target = {
            "confirm": FindingState.CONFIRMED,
            "reject": FindingState.REJECTED,
            "unresolved": FindingState.UNRESOLVED,
        }[verdict.verdict]
        confidence = 0.95 if target is FindingState.CONFIRMED else current.confidence
        return self.transition(
            finding_id,
            target,
            confidence=confidence,
            verifier_verdict=verdict,
        )
