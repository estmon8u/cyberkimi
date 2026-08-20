from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken

from .data_handling import ModelContent, prepare_for_model
from .domain import DataClassification, EvidenceRecord, VerificationResult
from .store import Database, canonical_json


class EvidenceError(RuntimeError):
    pass


class ArtifactStore:
    def __init__(self, root: str | Path, database: Database) -> None:
        self.root = Path(root)
        self.database = database
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def persist(self, content: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = hashlib.sha256(content).hexdigest()
        path = self.root / "sha256" / digest[:2] / digest
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not path.exists():
            temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if temporary.exists():
                    temporary.unlink()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO artifacts "
                "(sha256, byte_count, media_type, storage_path, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    digest,
                    len(content),
                    media_type,
                    str(path),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return digest

    def read(self, digest: str) -> bytes:
        row = self.database.fetch_one(
            "SELECT storage_path FROM artifacts WHERE sha256 = ?", (digest,)
        )
        if row is None:
            raise EvidenceError(f"unknown artifact: {digest}")
        content = Path(row["storage_path"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise EvidenceError("artifact integrity check failed")
        return content


class CredentialVault:
    """Local encrypted vault; raw values never become model-visible evidence."""

    def __init__(self, root: str | Path, key: bytes) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._fernet = Fernet(key)

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def store(self, kind: str, fingerprint: str, value: str) -> str:
        record_id = hashlib.sha256(f"{kind}:{fingerprint}".encode()).hexdigest()
        destination = self.root / f"{record_id}.vault"
        if not destination.exists():
            payload = canonical_json(
                {
                    "kind": kind,
                    "fingerprint": fingerprint,
                    "value": value,
                    "stored_at": datetime.now(timezone.utc).isoformat(),
                }
            ).encode()
            encrypted = self._fernet.encrypt(payload)
            temporary = destination.with_suffix(f".{uuid.uuid4().hex}.tmp")
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(encrypted)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    temporary.unlink()
        return record_id

    def retrieve_redacted(self, record_id: str) -> str:
        path = self.root / f"{record_id}.vault"
        if not path.exists():
            raise EvidenceError("vault record does not exist")
        try:
            document = json.loads(self._fernet.decrypt(path.read_bytes()))
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise EvidenceError("vault integrity check failed") from exc
        return f"<VAULT:{document['kind']}:{document['fingerprint'][:12]}>"


class EvidenceStore:
    def __init__(
        self,
        database: Database,
        artifacts: ArtifactStore,
        vault: CredentialVault,
    ) -> None:
        self.database = database
        self.artifacts = artifacts
        self.vault = vault

    def record_text(
        self,
        *,
        task_id: str,
        asset_revision: str,
        evidence_type: str,
        evidence_class: str,
        text: str,
        classification: DataClassification,
        source_session_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> tuple[EvidenceRecord, ModelContent]:
        artifact_digest = self.artifacts.persist(text.encode(), media_type="text/plain")
        model_content = prepare_for_model(classification, text)
        vault_refs = [
            self.vault.store(candidate.kind, candidate.fingerprint, candidate.value)
            for candidate in model_content.vault_candidates
        ]
        record = EvidenceRecord(
            evidence_id=f"E-{uuid.uuid4().hex}",
            task_id=task_id,
            asset_revision=asset_revision,
            evidence_type=evidence_type,
            evidence_class=evidence_class,
            payload={
                **(payload or {}),
                "model_text": model_content.text,
                "classification": classification.value,
                "redaction_count": model_content.redaction_count,
                "vault_refs": vault_refs,
            },
            artifact_sha256=artifact_digest,
            source_session_id=source_session_id,
            created_at=datetime.now(timezone.utc),
        )
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO evidence "
                "(evidence_id, task_id, asset_revision, evidence_type, evidence_class, "
                "payload_json, artifact_sha256, source_session_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.evidence_id,
                    record.task_id,
                    record.asset_revision,
                    record.evidence_type,
                    record.evidence_class,
                    canonical_json(record.payload),
                    record.artifact_sha256,
                    record.source_session_id,
                    record.created_at.isoformat(),
                ),
            )
        return record, model_content

    def for_task(self, task_id: str) -> list[EvidenceRecord]:
        rows = self.database.fetch_all(
            "SELECT * FROM evidence WHERE task_id = ? ORDER BY created_at", (task_id,)
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


@dataclass(frozen=True)
class EvidencePolicy:
    required_evidence: frozenset[str]
    minimum_evidence_classes: int
    deterministic_oracle: str

    def evaluate(
        self,
        evidence: list[EvidenceRecord],
        oracle_result: bool | None,
        blind_verification: VerificationResult,
    ) -> tuple[bool, tuple[str, ...]]:
        types = {item.evidence_type for item in evidence}
        classes = {item.evidence_class for item in evidence}
        missing = tuple(sorted(self.required_evidence - types))
        accepted = (
            not missing
            and len(classes) >= self.minimum_evidence_classes
            and oracle_result is True
            and blind_verification.verdict == "confirmed"
            and blind_verification.claim_supported
            and blind_verification.impact_supported
        )
        return accepted, missing


EVIDENCE_POLICIES: dict[str, EvidencePolicy] = {
    "authorization_inconsistency": EvidencePolicy(
        required_evidence=frozenset(
            {"source_location", "route_to_handler", "missing_enforcement", "counterevidence_search"}
        ),
        minimum_evidence_classes=2,
        deterministic_oracle="route_trace_verifier",
    ),
    "dependency_advisory": EvidencePolicy(
        required_evidence=frozenset(
            {"dependency_record", "advisory_record", "version_match", "counterevidence_search"}
        ),
        minimum_evidence_classes=2,
        deterministic_oracle="version_range_checker",
    ),
    "secret_exposure": EvidencePolicy(
        required_evidence=frozenset(
            {"source_location", "secret_pattern_match", "vault_confirmation", "counterevidence_search"}
        ),
        minimum_evidence_classes=2,
        deterministic_oracle="vault_cross_checker",
    ),
}


class Oracle(Protocol):
    def __call__(self, evidence: list[EvidenceRecord]) -> bool:
        ...


def route_trace_verifier(evidence: list[EvidenceRecord]) -> bool:
    types = {item.evidence_type for item in evidence}
    return {"route_to_handler", "missing_enforcement"}.issubset(types)


def version_range_checker(evidence: list[EvidenceRecord]) -> bool:
    return any(
        item.evidence_type == "version_match" and item.payload.get("matched") is True
        for item in evidence
    )


def vault_cross_checker(evidence: list[EvidenceRecord]) -> bool:
    vault_refs = {
        reference
        for item in evidence
        for reference in item.payload.get("vault_refs", [])
        if isinstance(reference, str)
    }
    return bool(vault_refs) and any(
        item.evidence_type == "vault_confirmation" for item in evidence
    )


ORACLES: dict[str, Oracle] = {
    "route_trace_verifier": route_trace_verifier,
    "version_range_checker": version_range_checker,
    "vault_cross_checker": vault_cross_checker,
}
