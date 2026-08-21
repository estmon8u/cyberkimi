"""Immutable engagement manifest lifecycle and local-only drafting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import insert, select, update

from cyberkimi.assets import AssetRegistry, build_binding
from cyberkimi.audit import AuditStore
from cyberkimi.authorization import SignedEnvelope
from cyberkimi.canonical import sha256_digest
from cyberkimi.errors import ValidationFailure
from cyberkimi.models import (
    Asset,
    AssetKind,
    AssuranceLevel,
    Authorization,
    DataClassification,
    DataPolicy,
    Engagement,
    EngagementStatus,
    NetworkPolicy,
    RiskTier,
)
from cyberkimi.persistence import Database, engagement_revisions


class EngagementService:
    def __init__(
        self,
        database: Database,
        audit: AuditStore,
        signer: SignedEnvelope,
        asset_registry: AssetRegistry,
    ):
        self.database = database
        self.audit = audit
        self.signer = signer
        self.asset_registry = asset_registry

    def draft_local(
        self,
        local_path: Path,
        *,
        engagement_id: str,
        name: str,
        owner_id: str,
        expires_in: timedelta = timedelta(days=7),
        classification: DataClassification = DataClassification.INTERNAL,
        external_model_allowed: bool = False,
    ) -> Engagement:
        canonical = local_path.resolve(strict=True)
        kind = AssetKind.REPOSITORY if (canonical / ".git").exists() else AssetKind.DIRECTORY
        asset = Asset(
            asset_id=f"repo:{name}@1",
            kind=kind,
            locator_type="local_path",
            canonical_locator=str(canonical),
            binding=build_binding(canonical, kind),
            allowed_effects=frozenset(
                {
                    "repository.read",
                    "repository.search",
                    "repository.diff_read",
                    "process.local_readonly",
                    "artifact.read",
                    "artifact.write",
                    "source.patch_scratch",
                    "source.test_scratch",
                }
            ),
            data_classification=classification,
        )
        now = datetime.now(timezone.utc)
        return Engagement(
            engagement_id=engagement_id,
            revision=1,
            name=name,
            owner_id=owner_id,
            created_at=now,
            expires_at=now + expires_in,
            authorization=Authorization(
                assurance_level=AssuranceLevel.A1_LOCAL_OWNER,
                status="active",
                approver_ids=(owner_id,),
            ),
            data_policy=DataPolicy(
                classification=classification,
                external_model_allowed=external_model_allowed,
                allowed_model_providers=("moonshot",) if external_model_allowed else (),
            ),
            risk_ceiling=RiskTier.R1_LOCAL_READ_ONLY,
            assets=(asset,),
            network_policy=NetworkPolicy(),
            status=EngagementStatus.DRAFT,
        )

    @staticmethod
    def load_manifest(path: Path) -> Engagement:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValidationFailure("engagement manifest must be a mapping")
        if "engagement" in raw:
            nested = raw["engagement"]
            if not isinstance(nested, dict):
                raise ValidationFailure("engagement section must be a mapping")
            raw = {"schema_version": raw.get("schema_version"), **nested}
            if "id" in raw:
                raw["engagement_id"] = raw.pop("id")
        return Engagement.model_validate(raw)

    @staticmethod
    def write_manifest(engagement: Engagement, path: Path) -> None:
        data = engagement.model_dump(mode="json", exclude_none=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def validate(self, engagement: Engagement) -> str:
        if engagement.authorization.assurance_level is AssuranceLevel.A0_UNVERIFIED:
            if engagement.risk_ceiling > RiskTier.R0_REASONING_ONLY:
                raise ValidationFailure("A0 engagement cannot authorize executable risk")
        if engagement.risk_ceiling >= RiskTier.R3_BOUNDED_LAB_VALIDATION:
            if engagement.authorization.assurance_level is not AssuranceLevel.A2_ORG_APPROVED:
                raise ValidationFailure("R3 ceiling requires A2 organizational approval")
        if engagement.data_policy.classification is DataClassification.RESTRICTED:
            if engagement.data_policy.external_model_allowed:
                raise ValidationFailure("RESTRICTED data cannot be sent to an external model")
        classification_rank = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 1,
            DataClassification.CONFIDENTIAL: 2,
            DataClassification.RESTRICTED: 3,
        }
        for asset in engagement.assets:
            if classification_rank[asset.data_classification] < classification_rank[engagement.data_policy.classification]:
                raise ValidationFailure("asset classification cannot be less restrictive than engagement data policy")
            canonical = Path(asset.canonical_locator).resolve(strict=True)
            if str(canonical) != asset.canonical_locator:
                raise ValidationFailure(f"asset path must be canonical: {asset.asset_id}")
            actual = build_binding(canonical, asset.kind)
            if actual != asset.binding:
                raise ValidationFailure(f"asset binding changed before registration: {asset.asset_id}")
        return sha256_digest(engagement)

    def create(self, engagement: Engagement) -> tuple[Engagement, str]:
        if engagement.revision != 1:
            raise ValidationFailure("engagement create requires revision 1")
        active = engagement.model_copy(update={"status": EngagementStatus.ACTIVE})
        digest = self.validate(active)
        signature = self.signer.sign(active)
        with self.database.transaction() as connection:
            existing = connection.execute(
                select(engagement_revisions.c.revision).where(
                    engagement_revisions.c.engagement_id == active.engagement_id
                )
            ).first()
            if existing is not None:
                raise ValidationFailure("engagement already exists; use amend")
            connection.execute(
                insert(engagement_revisions).values(
                    engagement_id=active.engagement_id,
                    revision=active.revision,
                    status=active.status.value,
                    manifest_json=active.model_dump_json(),
                    manifest_digest=digest,
                    signature_token=signature,
                    created_at=active.created_at,
                )
            )
            self.audit.append(
                active.engagement_id,
                "engagement.created",
                {"revision": active.revision, "manifest_digest": digest},
                connection=connection,
            )
        self.asset_registry.register_engagement_assets(active)
        return active, signature

    def amend(self, engagement_id: str, replacement: Engagement) -> tuple[Engagement, str]:
        current = self.get_active(engagement_id)
        if replacement.engagement_id != engagement_id:
            raise ValidationFailure("amendment cannot change engagement ID")
        if replacement.revision != current.revision + 1:
            raise ValidationFailure("amendment revision must increment by exactly one")
        if replacement.created_at < current.created_at:
            raise ValidationFailure("amendment creation time cannot move backwards")
        active = replacement.model_copy(update={"status": EngagementStatus.ACTIVE})
        digest = self.validate(active)
        signature = self.signer.sign(active)
        with self.database.transaction() as connection:
            connection.execute(
                update(engagement_revisions)
                .where(
                    engagement_revisions.c.engagement_id == engagement_id,
                    engagement_revisions.c.revision == current.revision,
                )
                .values(status=EngagementStatus.SUPERSEDED.value)
            )
            connection.execute(
                insert(engagement_revisions).values(
                    engagement_id=engagement_id,
                    revision=active.revision,
                    status=active.status.value,
                    manifest_json=active.model_dump_json(),
                    manifest_digest=digest,
                    signature_token=signature,
                    created_at=active.created_at,
                )
            )
            self.audit.append(
                engagement_id,
                "engagement.amended",
                {
                    "previous_revision": current.revision,
                    "revision": active.revision,
                    "manifest_digest": digest,
                },
                connection=connection,
            )
        self.asset_registry.register_engagement_assets(active)
        return active, signature

    def revoke(self, engagement_id: str, revision: int) -> None:
        with self.database.transaction() as connection:
            result = connection.execute(
                update(engagement_revisions)
                .where(
                    engagement_revisions.c.engagement_id == engagement_id,
                    engagement_revisions.c.revision == revision,
                    engagement_revisions.c.status == EngagementStatus.ACTIVE.value,
                )
                .values(status=EngagementStatus.REVOKED.value)
            )
            if result.rowcount != 1:
                raise KeyError(f"active engagement revision not found: {engagement_id}@{revision}")
            self.audit.append(
                engagement_id,
                "engagement.revoked",
                {"revision": revision},
                connection=connection,
            )

    def get(self, engagement_id: str, revision: int) -> Engagement:
        row = self.database.fetch_one(
            select(engagement_revisions.c.manifest_json, engagement_revisions.c.status).where(
                engagement_revisions.c.engagement_id == engagement_id,
                engagement_revisions.c.revision == revision,
            )
        )
        if row is None:
            raise KeyError(f"{engagement_id}@{revision}")
        manifest = Engagement.model_validate_json(str(row["manifest_json"]))
        return manifest.model_copy(update={"status": EngagementStatus(str(row["status"]))})

    def get_active(self, engagement_id: str) -> Engagement:
        row = self.database.fetch_one(
            select(engagement_revisions.c.manifest_json, engagement_revisions.c.status)
            .where(
                engagement_revisions.c.engagement_id == engagement_id,
                engagement_revisions.c.status == EngagementStatus.ACTIVE.value,
            )
            .order_by(engagement_revisions.c.revision.desc())
            .limit(1)
        )
        if row is None:
            raise KeyError(f"active engagement not found: {engagement_id}")
        return Engagement.model_validate_json(str(row["manifest_json"]))
