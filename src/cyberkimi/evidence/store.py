from __future__ import annotations

import hashlib
from pathlib import Path

from sqlalchemy import select

from cyberkimi.evidence.models import ArtifactRecord, EvidenceRecord
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import ArtifactRow, EvidenceRow


class ArtifactStore:
    def __init__(self, database: Database, root: Path) -> None:
        self.database = database
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def persist(self, raw: bytes, *, media_type: str, source_run_id: str | None) -> ArtifactRecord:
        digest = hashlib.sha256(raw).hexdigest()
        relative = Path("sha256") / digest[:2] / digest
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.chmod(0o700)
        if not destination.exists():
            temporary = destination.with_suffix(".tmp")
            temporary.write_bytes(raw)
            temporary.chmod(0o600)
            temporary.replace(destination)
        with self.database.transaction(immediate=True) as session:
            row = session.scalar(select(ArtifactRow).where(ArtifactRow.sha256 == digest))
            if row is None:
                record = ArtifactRecord(
                    sha256=digest,
                    media_type=media_type,
                    byte_count=len(raw),
                    relative_path=str(relative),
                    source_run_id=source_run_id,
                )
                session.add(
                    ArtifactRow(
                        artifact_id=record.artifact_id,
                        sha256=digest,
                        media_type=media_type,
                        byte_count=len(raw),
                        relative_path=str(relative),
                        source_run_id=source_run_id,
                    )
                )
                return record
            return ArtifactRecord(
                artifact_id=row.artifact_id,
                sha256=row.sha256,
                media_type=row.media_type,
                byte_count=row.byte_count,
                relative_path=row.relative_path,
                source_run_id=row.source_run_id,
            )

    def read(self, artifact_id: str) -> bytes:
        with self.database.read_session() as session:
            row = session.get(ArtifactRow, artifact_id)
            if row is None:
                raise KeyError(artifact_id)
            path = (self.root / row.relative_path).resolve()
            if not path.is_relative_to(self.root.resolve()):
                raise ValueError("artifact path escaped the store")
            return path.read_bytes()


class EvidenceStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record(self, evidence: EvidenceRecord) -> EvidenceRecord:
        with self.database.transaction(immediate=True) as session:
            session.add(
                EvidenceRow(
                    evidence_id=evidence.evidence_id,
                    task_id=evidence.task_id,
                    asset_versioned_id=evidence.asset_versioned_id,
                    evidence_type=evidence.evidence_type,
                    evidence_class=evidence.evidence_class,
                    summary=evidence.summary,
                    payload_json=evidence.payload,
                    artifact_id=evidence.artifact_id,
                    provenance_json=evidence.provenance,
                )
            )
        return evidence

    def list_for_task(self, task_id: str) -> tuple[EvidenceRecord, ...]:
        with self.database.read_session() as session:
            rows = session.scalars(
                select(EvidenceRow)
                .where(EvidenceRow.task_id == task_id)
                .order_by(EvidenceRow.created_at)
            ).all()
        return tuple(
            EvidenceRecord(
                evidence_id=row.evidence_id,
                task_id=row.task_id,
                asset_versioned_id=row.asset_versioned_id,
                evidence_type=row.evidence_type,
                evidence_class=row.evidence_class,
                summary=row.summary,
                payload=row.payload_json,
                artifact_id=row.artifact_id,
                provenance=row.provenance_json,
            )
            for row in rows
        )
