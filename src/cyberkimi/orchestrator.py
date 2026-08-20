from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from .authorization import AuthorizationRegistry, ScopeSigner
from .domain import DataClassification, FindingState, VerificationResult
from .evidence import ArtifactStore, CredentialVault, EvidenceStore
from .findings import FindingLifecycle
from .manifest import EngagementManifest, load_manifest
from .review import RepositoryBoundary
from .store import Database, canonical_json


@dataclass(frozen=True)
class StatePaths:
    root: Path
    database: Path
    signing_key: Path
    vault_key: Path
    artifacts: Path
    vault: Path
    reports: Path

    @classmethod
    def under(cls, root: str | Path) -> "StatePaths":
        base = Path(root).expanduser().resolve()
        return cls(
            root=base,
            database=base / "cyberkimi.db",
            signing_key=base / "scope-signing.key",
            vault_key=base / "vault.key",
            artifacts=base / "artifacts",
            vault=base / "vault",
            reports=base / "reports",
        )


@dataclass(frozen=True)
class ReviewResult:
    task_id: str
    engagement_id: str
    asset_revision: str
    file_count: int
    dependency_count: int
    secret_signal_count: int
    confirmed_finding_count: int
    unresolved_finding_count: int
    report_path: Path


class CyberKimi:
    def __init__(self, state_directory: str | Path = ".cyberkimi") -> None:
        self.paths = StatePaths.under(state_directory)
        self.paths.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.paths.reports.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = Database(self.paths.database)
        self.database.initialize()
        self.signer = ScopeSigner(self._load_or_create_bytes(self.paths.signing_key, 32))
        vault_key = self._load_or_create_fernet_key(self.paths.vault_key)
        self.registry = AuthorizationRegistry(self.database, self.signer)
        self.artifacts = ArtifactStore(self.paths.artifacts, self.database)
        self.vault = CredentialVault(self.paths.vault, vault_key)
        self.evidence = EvidenceStore(self.database, self.artifacts, self.vault)
        self.findings = FindingLifecycle(self.database)

    @staticmethod
    def _load_or_create_bytes(path: Path, length: int) -> bytes:
        if path.exists():
            value = path.read_bytes()
            if len(value) != length:
                raise ValueError(f"invalid key length at {path}")
            return value
        value = os.urandom(length)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        return value

    @staticmethod
    def _load_or_create_fernet_key(path: Path) -> bytes:
        if path.exists():
            value = path.read_bytes()
            Fernet(value)
            return value
        value = Fernet.generate_key()
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        return value

    def register_manifest(self, manifest: EngagementManifest) -> list[str]:
        engagement = manifest.engagement_revision()
        self.registry.register_engagement(engagement)
        revisions = manifest.asset_revisions(self.signer)
        for asset in revisions:
            self.registry.register_asset(asset)
        return [asset.versioned_id for asset in revisions]

    def register_manifest_file(self, path: str | Path) -> list[str]:
        return self.register_manifest(load_manifest(path))

    def review_repository(
        self,
        *,
        engagement_id: str,
        asset_id: str,
        goal: str,
    ) -> ReviewResult:
        engagement = self.registry.latest_engagement(engagement_id)
        if not engagement.active():
            raise ValueError("engagement is not active")
        asset = self.registry.resolve_asset(asset_id, engagement_id)
        if asset.asset_type != "repository":
            raise ValueError("review mode requires a repository asset")
        repository = RepositoryBoundary(asset.canonical_location)
        task_id = f"TASK-{uuid.uuid4().hex}"
        files = repository.list_files()
        dependencies = repository.dependencies()
        secret_signals = repository.secret_signals()

        inventory_text = canonical_json(
            {
                "goal": goal,
                "asset": asset.versioned_id,
                "files": files,
                "dependency_count": len(dependencies),
            }
        )
        self.evidence.record_text(
            task_id=task_id,
            asset_revision=asset.versioned_id,
            evidence_type="repository_inventory",
            evidence_class="metadata",
            text=inventory_text,
            classification=asset.data_classification,
            payload={"file_count": len(files)},
        )
        if dependencies:
            self.evidence.record_text(
                task_id=task_id,
                asset_revision=asset.versioned_id,
                evidence_type="dependency_record",
                evidence_class="manifest",
                text=canonical_json([item.__dict__ for item in dependencies]),
                classification=asset.data_classification,
                payload={"dependency_count": len(dependencies)},
            )

        unresolved = 0
        findings_for_report: list[dict[str, Any]] = []
        for signal in secret_signals:
            raw_file = repository.read_text(signal.path)
            source_record, _ = self.evidence.record_text(
                task_id=task_id,
                asset_revision=asset.versioned_id,
                evidence_type="source_location",
                evidence_class="source",
                text=f"{signal.path}:{signal.line}:{signal.column}",
                classification=DataClassification.INTERNAL,
                payload={
                    "path": signal.path,
                    "line": signal.line,
                    "column": signal.column,
                    "redacted_excerpt": signal.excerpt,
                },
            )
            match_record, model_content = self.evidence.record_text(
                task_id=task_id,
                asset_revision=asset.versioned_id,
                evidence_type="secret_pattern_match",
                evidence_class="detector",
                text=raw_file,
                classification=DataClassification.CONFIDENTIAL,
                payload={"path": signal.path, "line": signal.line, "pattern_kind": signal.kind},
            )
            vault_record, _ = self.evidence.record_text(
                task_id=task_id,
                asset_revision=asset.versioned_id,
                evidence_type="vault_confirmation",
                evidence_class="vault",
                text=canonical_json(
                    {
                        "candidate_count": len(model_content.vault_candidates),
                        "fingerprints": [
                            candidate.fingerprint for candidate in model_content.vault_candidates
                        ],
                    }
                ),
                classification=DataClassification.INTERNAL,
                payload={"vault_refs": match_record.payload.get("vault_refs", [])},
            )
            counter_record, _ = self.evidence.record_text(
                task_id=task_id,
                asset_revision=asset.versioned_id,
                evidence_type="counterevidence_search",
                evidence_class="search",
                text=(
                    "Automatic confirmation withheld. Review whether the value is a fixture, "
                    "example, placeholder, revoked credential, generated artifact, or unreachable "
                    "test-only material."
                ),
                classification=DataClassification.INTERNAL,
                payload={"automatic_confirmation": False},
            )
            finding_id = self.findings.create_signal(
                engagement_id=engagement_id,
                task_id=task_id,
                finding_type="secret_exposure",
                claim=f"Potential secret-like value at {signal.path}:{signal.line}",
                asset_revision=asset.versioned_id,
            )
            for record in (source_record, match_record, vault_record, counter_record):
                self.findings.attach_evidence(finding_id, record.evidence_id)
            self.findings.transition(finding_id, FindingState.HYPOTHESIS)
            destination = self.findings.verify_and_finalize(
                finding_id,
                VerificationResult(
                    verdict="unresolved",
                    claim_supported=True,
                    impact_supported=False,
                    missing_evidence=("human or independent impact verification",),
                    alternative_explanations=(
                        "test fixture",
                        "documentation example",
                        "revoked or non-production credential",
                    ),
                    reason_codes=("DETERMINISTIC_SIGNAL_ONLY",),
                    confidence=0.5,
                ),
            )
            unresolved += destination == FindingState.UNRESOLVED
            findings_for_report.append(
                {
                    "finding_id": finding_id,
                    "state": destination.value,
                    "claim": f"Potential secret-like value at {signal.path}:{signal.line}",
                    "pattern_kind": signal.kind,
                    "redacted_excerpt": signal.excerpt,
                }
            )

        report = {
            "schema_version": "cyberkimi.review.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engagement_id": engagement_id,
            "engagement_revision": engagement.versioned_id,
            "task_id": task_id,
            "asset_revision": asset.versioned_id,
            "goal": goal,
            "summary": {
                "file_count": len(files),
                "dependency_count": len(dependencies),
                "secret_signal_count": len(secret_signals),
                "confirmed_finding_count": 0,
                "unresolved_finding_count": unresolved,
            },
            "dependencies": [item.__dict__ for item in dependencies],
            "findings": findings_for_report,
            "limitations": [
                "Deterministic offline review does not query external advisory databases.",
                "Secret-like signals require independent impact verification before confirmation.",
                "A configured Kimi session may add hypotheses but cannot bypass finding policies.",
            ],
        }
        report_path = self.paths.reports / f"{task_id}.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True))
        return ReviewResult(
            task_id=task_id,
            engagement_id=engagement_id,
            asset_revision=asset.versioned_id,
            file_count=len(files),
            dependency_count=len(dependencies),
            secret_signal_count=len(secret_signals),
            confirmed_finding_count=0,
            unresolved_finding_count=unresolved,
            report_path=report_path,
        )
