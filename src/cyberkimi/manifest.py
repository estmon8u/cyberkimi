from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .authorization import ScopeSigner
from .domain import (
    DEFAULT_BUDGET,
    AssetRevision,
    DataClassification,
    EngagementRevision,
    RiskTier,
)


class ManifestAsset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["repository", "logs", "lab"]
    location: str
    trust_domain: str = "local"
    content_revision: str = "working-tree"
    access: Literal["read_only", "read_write", "active_validation"] = "read_only"
    allowed_effects: frozenset[str]
    data_classification: DataClassification = DataClassification.INTERNAL
    network_identifiers: tuple[str, ...] = ()


class EngagementManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engagement_id: str
    revision: int = Field(ge=1)
    owner: str
    approver: str
    authorization_basis: str = "local_owner_attestation"
    authorization_status: str = "self_attested"
    created_at: datetime
    expires_at: datetime
    maximum_risk_tier: RiskTier = RiskTier.R1_READ_ONLY
    capability_flags: frozenset[str] = frozenset()
    self_attested_approvals: bool = False
    assets: tuple[ManifestAsset, ...]

    @model_validator(mode="after")
    def unique_assets(self) -> "EngagementManifest":
        aliases = [asset.id for asset in self.assets]
        if len(aliases) != len(set(aliases)):
            raise ValueError("asset IDs must be unique")
        return self

    def engagement_revision(self) -> EngagementRevision:
        return EngagementRevision(
            engagement_id=self.engagement_id,
            revision=self.revision,
            owner=self.owner,
            authorization_basis=self.authorization_basis,
            authorization_status=self.authorization_status,
            approver=self.approver,
            created_at=self.created_at,
            expires_at=self.expires_at,
            maximum_risk_tier=self.maximum_risk_tier,
            capability_flags=self.capability_flags,
            budget=DEFAULT_BUDGET,
            self_attested_approvals=self.self_attested_approvals,
        )

    def asset_revisions(self, signer: ScopeSigner) -> list[AssetRevision]:
        revisions: list[AssetRevision] = []
        for source in self.assets:
            location = Path(source.location).expanduser().resolve(strict=True)
            evidence_digest = hashlib.sha256(
                f"{self.authorization_basis}:{self.owner}:{source.id}:{location}".encode()
            ).hexdigest()
            unsigned = {
                "asset_alias": source.id,
                "revision": self.revision,
                "engagement_id": self.engagement_id,
                "asset_type": source.type,
                "canonical_location": str(location),
                "trust_domain": source.trust_domain,
                "content_revision": source.content_revision,
                "allowed_effects": sorted(source.allowed_effects),
                "data_classification": source.data_classification.value,
                "network_identifiers": list(source.network_identifiers),
                "authorization_evidence_digest": evidence_digest,
            }
            revisions.append(
                AssetRevision.model_validate({**unsigned, "signature": signer.sign(unsigned)})
            )
        return revisions


def load_manifest(path: str | Path) -> EngagementManifest:
    document = yaml.safe_load(Path(path).read_text())
    if not isinstance(document, dict):
        raise ValueError("engagement manifest must be a YAML mapping")
    return EngagementManifest.model_validate(document)


def write_manifest(manifest: EngagementManifest, path: str | Path) -> None:
    payload = manifest.model_dump(mode="json")
    Path(path).write_text(yaml.safe_dump(payload, sort_keys=False))


def provision_repository_manifest(
    target: str | Path,
    *,
    owner: str,
    classification: DataClassification = DataClassification.INTERNAL,
    expires_in_days: int = 7,
) -> EngagementManifest:
    location = Path(target).expanduser().resolve(strict=True)
    if not location.is_dir():
        raise ValueError("repository target must be a directory")
    now = datetime.now(timezone.utc)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", location.name).strip("-") or "repository"
    return EngagementManifest(
        engagement_id=f"ENG-{uuid.uuid4().hex[:12].upper()}",
        revision=1,
        owner=owner,
        approver=owner,
        created_at=now,
        expires_at=now + timedelta(days=expires_in_days),
        maximum_risk_tier=RiskTier.R1_READ_ONLY,
        assets=(
            ManifestAsset(
                id=f"repo:{slug}",
                type="repository",
                location=str(location),
                access="read_only",
                allowed_effects=frozenset(
                    {"file.read", "file.search", "process.local", "evidence.write"}
                ),
                data_classification=classification,
            ),
        ),
    )
