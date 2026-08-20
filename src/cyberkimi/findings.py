from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .domain import EvidenceRecord, FindingState, VerificationResult
from .evidence import EVIDENCE_POLICIES, ORACLES, EvidenceError
from .store import Database, canonical_json


ALLOWED_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.SIGNAL: frozenset({FindingState.HYPOTHESIS, FindingState.REJECTED}),
    FindingState.HYPOTHESIS: frozenset(
        {FindingState.SUPPORTED, FindingState.REJECTED, FindingState.UNRESOLVED}
    ),
    FindingState.SUPPORTED: frozenset(
        {FindingState.REPRODUCED, FindingState.CONFIRMED, FindingState.DISPUTED, FindingState.REJECTED}
    ),
    FindingState.REPRODUCED: frozenset(
        {FindingState.CONFIRMED, FindingState.DISPUTED, FindingState.REJECTED}
    ),
    FindingState.DISPUTED: frozenset(
        {FindingState.CONFIRMED, FindingState.REJECTED, FindingState.UNRESOLVED}
    ),
    FindingState.UNRESOLVED: frozenset(
        {FindingState.SUPPORTED, FindingState.REJECTED}
    ),
    FindingState.CONFIRMED: frozenset(),
    FindingState.REJECTED: frozenset(),
}


class FindingLifecycle:
    def __init__(self, database: Database) -> None:
        self.database = database

    def create_signal(
        self,
        *,
        engagement_id: str,
        task_id: str,
        finding_type: str,
        claim: str,
        asset_revision: str,
    ) -> str:
        finding_id = f"F-{uuid.uuid4().hex}"
        now = datetime.now(timezone.utc).isoformat()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO findings "
                "(finding_id, engagement_id, task_id, finding_type, state, claim, "
                "asset_revision, verification_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                (
                    finding_id,
                    engagement_id,
                    task_id,
                    finding_type,
                    FindingState.SIGNAL.value,
                    claim,
                    asset_revision,
                    now,
                    now,
                ),
            )
        return finding_id

    def attach_evidence(self, finding_id: str, evidence_id: str) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO finding_evidence (finding_id, evidence_id) VALUES (?, ?)",
                (finding_id, evidence_id),
            )

    def transition(self, finding_id: str, destination: FindingState) -> None:
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT state FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if row is None:
                raise EvidenceError(f"unknown finding: {finding_id}")
            current = FindingState(row["state"])
            if destination not in ALLOWED_TRANSITIONS[current]:
                raise EvidenceError(f"invalid finding transition: {current} -> {destination}")
            connection.execute(
                "UPDATE findings SET state = ?, updated_at = ? WHERE finding_id = ?",
                (destination.value, datetime.now(timezone.utc).isoformat(), finding_id),
            )

    def evidence_for(self, finding_id: str) -> list[EvidenceRecord]:
        rows = self.database.fetch_all(
            "SELECT e.* FROM evidence e JOIN finding_evidence fe "
            "ON fe.evidence_id = e.evidence_id WHERE fe.finding_id = ? ORDER BY e.created_at",
            (finding_id,),
        )
        return [
            EvidenceRecord(
                evidence_id=row["evidence_id"],
                task_id=row["task_id"],
                asset_revision=row["asset_revision"],
                evidence_type=row["evidence_type"],
                evidence_class=row["evidence_class"],
                payload=json.loads(row["payload_json"]),
                artifact_sha256=row["artifact_sha256"],
                source_session_id=row["source_session_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def verify_and_finalize(
        self,
        finding_id: str,
        blind_verification: VerificationResult,
    ) -> FindingState:
        row = self.database.fetch_one(
            "SELECT finding_type, state FROM findings WHERE finding_id = ?", (finding_id,)
        )
        if row is None:
            raise EvidenceError(f"unknown finding: {finding_id}")
        finding_type = row["finding_type"]
        policy = EVIDENCE_POLICIES.get(finding_type)
        if policy is None:
            raise EvidenceError(f"no typed evidence policy for finding type: {finding_type}")
        evidence = self.evidence_for(finding_id)
        oracle = ORACLES[policy.deterministic_oracle]
        oracle_result = oracle(evidence)
        accepted, missing = policy.evaluate(evidence, oracle_result, blind_verification)
        destination = FindingState.CONFIRMED if accepted else (
            FindingState.REJECTED
            if blind_verification.verdict == "rejected"
            else FindingState.UNRESOLVED
        )
        current = FindingState(row["state"])
        if destination == FindingState.CONFIRMED and current not in {
            FindingState.SUPPORTED,
            FindingState.REPRODUCED,
            FindingState.DISPUTED,
        }:
            raise EvidenceError("a scanner signal cannot transition directly to confirmed")
        verification_payload = {
            **blind_verification.model_dump(mode="json"),
            "deterministic_oracle": policy.deterministic_oracle,
            "oracle_result": oracle_result,
            "missing_typed_evidence": missing,
        }
        with self.database.transaction() as connection:
            connection.execute(
                "UPDATE findings SET state = ?, verification_json = ?, updated_at = ? "
                "WHERE finding_id = ?",
                (
                    destination.value,
                    canonical_json(verification_payload),
                    datetime.now(timezone.utc).isoformat(),
                    finding_id,
                ),
            )
        return destination
