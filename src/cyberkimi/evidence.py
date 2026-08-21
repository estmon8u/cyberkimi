"""Content-addressed artifacts, local secret vault, redaction, and evidence envelopes."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import insert, select

from cyberkimi.audit import AuditStore
from cyberkimi.canonical import canonical_bytes, sha256_bytes, sha256_digest
from cyberkimi.errors import AuthorizationError, ValidationFailure
from cyberkimi.ids import new_id
from cyberkimi.models import ArtifactRecord, Engagement, EvidenceEnvelope, ToolManifest, ToolResult
from cyberkimi.persistence import Database, artifacts, evidence, vault_records

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "github_token",
        re.compile(r"(?<![A-Za-z0-9_])(?:ghp|github_pat)_[A-Za-z0-9_]{20,255}"),
    ),
    (
        "jwt",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    (
        "generic_assignment",
        re.compile(
            r"(?i)(?P<prefix>\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*[\"']?)(?P<value>[A-Za-z0-9_./+\-=]{8,})(?P<suffix>[\"']?)"
        ),
    ),
)

_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
)


class ArtifactStore:
    def __init__(self, directory: Path, database: Database, audit: AuditStore):
        self.directory = directory
        self.database = database
        self.audit = audit
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def put(
        self,
        engagement_id: str,
        data: bytes,
        media_type: str,
        *,
        tool_run_id: str | None = None,
    ) -> ArtifactRecord:
        digest = sha256_bytes(data)
        hex_digest = digest.split(":", 1)[1]
        path = self.directory / hex_digest[:2] / hex_digest[2:]
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.exists():
            temporary = path.with_suffix(".tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        record = ArtifactRecord(
            artifact_id=new_id("ART"),
            digest=digest,
            media_type=media_type,
            size_bytes=len(data),
            local_path=str(path),
            created_at=datetime.now(timezone.utc),
            tool_run_id=tool_run_id,
        )
        with self.database.transaction() as connection:
            existing = connection.execute(
                select(artifacts.c.artifact_id).where(artifacts.c.digest == digest)
            ).first()
            if existing is None:
                connection.execute(
                    insert(artifacts).values(
                        artifact_id=record.artifact_id,
                        digest=digest,
                        record_json=record.model_dump_json(),
                        created_at=record.created_at,
                    )
                )
            else:
                row = connection.execute(
                    select(artifacts.c.record_json).where(artifacts.c.digest == digest)
                ).scalar_one()
                record = ArtifactRecord.model_validate_json(str(row))
            self.audit.append(
                engagement_id,
                "artifact.stored",
                {
                    "artifact_id": record.artifact_id,
                    "digest": record.digest,
                    "media_type": record.media_type,
                    "size_bytes": record.size_bytes,
                    "tool_run_id": tool_run_id,
                },
                connection=connection,
            )
        return record

    def read(self, digest: str, *, max_bytes: int) -> bytes:
        row = self.database.fetch_one(select(artifacts).where(artifacts.c.digest == digest))
        if row is None:
            raise KeyError(digest)
        record = ArtifactRecord.model_validate_json(str(row["record_json"]))
        if record.size_bytes > max_bytes:
            raise ValidationFailure("artifact exceeds requested read budget")
        data = Path(record.local_path).read_bytes()
        if sha256_bytes(data) != digest:
            raise ValidationFailure("artifact digest verification failed")
        return data


class SecretVault:
    def __init__(self, key_path: Path, database: Database, audit: AuditStore):
        self.key_path = key_path
        self.database = database
        self.audit = audit

    def ensure_key(self) -> None:
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.key_path.exists():
            return
        temporary = self.key_path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, Fernet.generate_key())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.key_path)
        os.chmod(self.key_path, 0o600)

    def _fernet(self) -> Fernet:
        self.ensure_key()
        return Fernet(self.key_path.read_bytes())

    def store(self, engagement_id: str, secret_type: str, plaintext: str) -> str:
        secret_ref = new_id("SEC")
        ciphertext = self._fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
        fingerprint = "sha256:" + hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
        with self.database.transaction() as connection:
            connection.execute(
                insert(vault_records).values(
                    secret_ref=secret_ref,
                    engagement_id=engagement_id,
                    secret_type=secret_type,
                    ciphertext=ciphertext,
                    fingerprint=fingerprint,
                    created_at=datetime.now(timezone.utc),
                )
            )
            self.audit.append(
                engagement_id,
                "secret.vaulted",
                {
                    "secret_ref": secret_ref,
                    "secret_type": secret_type,
                    "fingerprint": fingerprint,
                },
                connection=connection,
            )
        return secret_ref

    def reveal(self, engagement_id: str, secret_ref: str) -> str:
        row = self.database.fetch_one(
            select(vault_records).where(
                vault_records.c.secret_ref == secret_ref,
                vault_records.c.engagement_id == engagement_id,
            )
        )
        if row is None:
            raise KeyError(secret_ref)
        try:
            return self._fernet().decrypt(str(row["ciphertext"]).encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise AuthorizationError("vault ciphertext could not be authenticated") from exc

    def list_metadata(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self.database.fetch_all(
            select(
                vault_records.c.secret_ref,
                vault_records.c.secret_type,
                vault_records.c.fingerprint,
                vault_records.c.created_at,
            ).where(vault_records.c.engagement_id == engagement_id)
        )
        return rows


class Redactor:
    def __init__(self, vault: SecretVault):
        self.vault = vault

    def redact(
        self,
        engagement_id: str,
        text: str,
        *,
        redact_pii: bool = True,
    ) -> tuple[str, tuple[str, ...]]:
        secret_refs: list[str] = []
        result = text
        for secret_type, pattern in _SECRET_PATTERNS:
            if secret_type == "generic_assignment":

                def replace_assignment(match: re.Match[str]) -> str:
                    value = match.group("value")
                    secret_ref = self.vault.store(engagement_id, secret_type, value)
                    secret_refs.append(secret_ref)
                    return f"{match.group('prefix')}<secret-ref:{secret_ref}>{match.group('suffix')}"

                result = pattern.sub(replace_assignment, result)
            else:

                def replace_secret(match: re.Match[str], kind: str = secret_type) -> str:
                    secret_ref = self.vault.store(engagement_id, kind, match.group(0))
                    secret_refs.append(secret_ref)
                    return f"<secret-ref:{secret_ref}>"

                result = pattern.sub(replace_secret, result)
        if redact_pii:
            for pattern in _PII_PATTERNS:
                result = pattern.sub("<pii-redacted>", result)
        return result, tuple(secret_refs)


class EvidenceStore:
    def __init__(
        self,
        database: Database,
        audit: AuditStore,
        artifacts_store: ArtifactStore,
        redactor: Redactor,
    ):
        self.database = database
        self.audit = audit
        self.artifacts = artifacts_store
        self.redactor = redactor

    def from_tool_result(
        self,
        engagement: Engagement,
        task_id: str,
        asset_id: str,
        asset_binding_digest: str,
        tool: ToolManifest,
        tool_run_id: str,
        result: ToolResult,
        *,
        evidence_type: str,
        summary: str,
        excerpt_limit: int = 20_000,
    ) -> EvidenceEnvelope:
        raw = canonical_bytes(result)
        artifact = self.artifacts.put(
            engagement.engagement_id,
            raw,
            "application/json",
            tool_run_id=tool_run_id,
        )
        visible_source = json.dumps(result.structured, ensure_ascii=False, sort_keys=True)
        if result.stdout:
            visible_source += "\n" + result.stdout
        if result.stderr:
            visible_source += "\n" + result.stderr
        visible_source = visible_source[:excerpt_limit]
        redacted, secret_refs = self.redactor.redact(
            engagement.engagement_id,
            visible_source,
            redact_pii=engagement.data_policy.redact_pii_before_model,
        )
        envelope = EvidenceEnvelope(
            evidence_id=new_id("EVID"),
            engagement_id=engagement.engagement_id,
            engagement_revision=engagement.revision,
            task_id=task_id,
            asset_id=asset_id,
            asset_binding_digest=asset_binding_digest,
            tool_template_id=tool.template_id,
            tool_manifest_digest=sha256_digest(tool),
            tool_run_id=tool_run_id,
            artifact_digest=artifact.digest,
            evidence_type=evidence_type,
            summary=summary,
            excerpt=redacted,
            secret_refs=secret_refs,
            content_hash=sha256_digest(
                {
                    "artifact": artifact.digest,
                    "summary": summary,
                    "excerpt": redacted,
                    "provenance": {
                        "tool": tool.template_id,
                        "tool_run_id": tool_run_id,
                        "asset_binding_digest": asset_binding_digest,
                    },
                }
            ),
            created_at=datetime.now(timezone.utc),
            provenance={
                "tool_template_id": tool.template_id,
                "tool_manifest_digest": sha256_digest(tool),
                "tool_run_id": tool_run_id,
                "asset_id": asset_id,
                "asset_binding_digest": asset_binding_digest,
                "artifact_digest": artifact.digest,
            },
        )
        with self.database.transaction() as connection:
            connection.execute(
                insert(evidence).values(
                    evidence_id=envelope.evidence_id,
                    engagement_id=envelope.engagement_id,
                    task_id=envelope.task_id,
                    asset_id=envelope.asset_id,
                    content_hash=envelope.content_hash,
                    evidence_json=envelope.model_dump_json(),
                    created_at=envelope.created_at,
                )
            )
            self.audit.append(
                engagement.engagement_id,
                "evidence.recorded",
                {
                    "evidence_id": envelope.evidence_id,
                    "evidence_type": evidence_type,
                    "content_hash": envelope.content_hash,
                    "artifact_digest": artifact.digest,
                    "secret_ref_count": len(secret_refs),
                },
                connection=connection,
            )
        return envelope

    def get(self, evidence_id: str) -> EvidenceEnvelope:
        row = self.database.fetch_one(select(evidence).where(evidence.c.evidence_id == evidence_id))
        if row is None:
            raise KeyError(evidence_id)
        return EvidenceEnvelope.model_validate_json(str(row["evidence_json"]))

    def list_for_task(self, task_id: str) -> list[EvidenceEnvelope]:
        rows = self.database.fetch_all(
            select(evidence.c.evidence_json)
            .where(evidence.c.task_id == task_id)
            .order_by(evidence.c.created_at.asc())
        )
        return [EvidenceEnvelope.model_validate_json(str(row["evidence_json"])) for row in rows]
