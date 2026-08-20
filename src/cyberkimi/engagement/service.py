from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Any

from pydantic import Field
from sqlalchemy import Select, select, update
from sqlalchemy.orm import Session

from cyberkimi.core import StrictModel, canonical_json, fingerprint, new_id, utc_now
from cyberkimi.engagement.models import AssetDeclaration, EngagementManifest
from cyberkimi.engagement.scope_token import ScopeTokenClaims, ScopeTokenCodec
from cyberkimi.errors import AuthorizationError, ValidationFailure
from cyberkimi.persistence.database import Database
from cyberkimi.persistence.models import (
    AssetAliasRow,
    AssetRevisionRow,
    AuditEventRow,
    EngagementRow,
    ScopeTokenRow,
)


class AssetRevision(StrictModel):
    engagement_id: str
    asset_alias: str
    revision: int = Field(ge=1)
    versioned_id: str
    asset_type: str
    canonical_location: str
    access_mode: str
    data_classification: str
    trust_domain: str
    network_policy: dict[str, Any]
    allowed_effects: frozenset[str]
    content_digest: str | None
    parent_versioned_id: str | None
    authorization_evidence: dict[str, Any]
    signature: str
    created_at: datetime


class CompiledScope(StrictModel):
    token: str
    claims: ScopeTokenClaims
    assets: dict[str, AssetRevision]


class EngagementService:
    def __init__(self, database: Database, signing_key: bytes) -> None:
        self.database = database
        self.signing_key = signing_key
        self.token_codec = ScopeTokenCodec(signing_key)

    def register(self, manifest: EngagementManifest) -> CompiledScope:
        now = utc_now()
        if manifest.engagement.expires_at <= now:
            raise ValidationFailure("cannot register an expired engagement")
        with self.database.transaction(immediate=True) as session:
            existing = session.scalar(
                select(EngagementRow).where(
                    EngagementRow.engagement_id == manifest.id,
                    EngagementRow.revision == manifest.revision,
                )
            )
            if existing:
                raise ValidationFailure(
                    f"engagement {manifest.id}@{manifest.revision} already exists"
                )
            session.execute(
                update(EngagementRow)
                .where(EngagementRow.engagement_id == manifest.id)
                .values(active=False)
            )
            session.add(
                EngagementRow(
                    engagement_id=manifest.id,
                    revision=manifest.revision,
                    manifest_json=manifest.model_dump(mode="json"),
                    manifest_hash=fingerprint(manifest),
                    active=True,
                )
            )
            assets: dict[str, AssetRevision] = {}
            for declaration in manifest.scope.normalized_assets():
                assets[declaration.id] = self._register_initial_or_progressed_asset(
                    session, manifest, declaration
                )
            compiled = self._issue_scope_token(session, manifest, assets)
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=manifest.id,
                    event_type="engagement.registered",
                    actor=manifest.authorization.approver,
                    before_json={},
                    after_json={
                        "engagement_revision": manifest.revision,
                        "assets": {k: v.versioned_id for k, v in assets.items()},
                    },
                    details_json={"manifest_hash": fingerprint(manifest)},
                )
            )
            return compiled

    def get_manifest(self, engagement_id: str, revision: int | None = None) -> EngagementManifest:
        with self.database.read_session() as session:
            statement: Select[tuple[EngagementRow]] = select(EngagementRow).where(
                EngagementRow.engagement_id == engagement_id
            )
            if revision is None:
                statement = statement.where(EngagementRow.active.is_(True))
            else:
                statement = statement.where(EngagementRow.revision == revision)
            row = session.scalar(statement.order_by(EngagementRow.revision.desc()))
            if not row:
                raise ValidationFailure(f"unknown engagement: {engagement_id}")
            return EngagementManifest.model_validate(row.manifest_json)

    def resolve_asset(self, engagement_id: str, alias_or_versioned_id: str) -> AssetRevision:
        with self.database.read_session() as session:
            return self._resolve_asset(session, engagement_id, alias_or_versioned_id)

    def progress_asset(
        self,
        *,
        engagement_id: str,
        asset_alias: str,
        changes: dict[str, Any],
        authorization_evidence: dict[str, Any],
        actor: str,
    ) -> AssetRevision:
        manifest = self.get_manifest(engagement_id)
        if not manifest.authorization.allow_harness_asset_progression:
            raise AuthorizationError("engagement does not allow harness-managed asset progression")
        allowed_change_fields = {
            "canonical_location",
            "access_mode",
            "data_classification",
            "trust_domain",
            "network_policy",
            "allowed_effects",
            "content_digest",
        }
        unknown = set(changes) - allowed_change_fields
        if unknown:
            raise ValidationFailure(f"unsupported asset revision fields: {sorted(unknown)}")
        with self.database.transaction(immediate=True) as session:
            current = self._resolve_asset(session, engagement_id, asset_alias)
            before = current.model_dump(mode="json")
            payload = before | changes
            payload["revision"] = current.revision + 1
            payload["versioned_id"] = f"{asset_alias}@{current.revision + 1}"
            payload["parent_versioned_id"] = current.versioned_id
            payload["authorization_evidence"] = authorization_evidence
            payload["created_at"] = utc_now()
            payload["signature"] = self._sign_asset_payload(
                {k: v for k, v in payload.items() if k != "signature"}
            )
            revision = AssetRevision.model_validate(payload)
            self._insert_asset_revision(session, revision)
            session.flush()
            alias_row = session.get(AssetAliasRow, asset_alias)
            if alias_row is None:
                raise ValidationFailure("asset alias disappeared during progression")
            alias_row.current_versioned_id = revision.versioned_id
            alias_row.updated_at = utc_now()
            session.add(
                AuditEventRow(
                    event_id=new_id("AUDIT"),
                    engagement_id=engagement_id,
                    event_type="asset.revision_created",
                    actor=actor,
                    before_json=before,
                    after_json=revision.model_dump(mode="json"),
                    details_json={"authorization_evidence": authorization_evidence},
                )
            )
            return revision

    def issue_scope(self, engagement_id: str) -> CompiledScope:
        manifest = self.get_manifest(engagement_id)
        with self.database.transaction(immediate=True) as session:
            assets = {
                declaration.id: self._resolve_asset(session, engagement_id, declaration.id)
                for declaration in manifest.scope.normalized_assets()
            }
            return self._issue_scope_token(session, manifest, assets)

    def verify_scope_token(self, token: str) -> ScopeTokenClaims:
        claims = self.token_codec.verify(token)
        with self.database.read_session() as session:
            row = session.get(ScopeTokenRow, claims.token_id)
            if row is None or row.revoked:
                raise AuthorizationError("scope token is unknown or revoked")
            if row.token_hash != self.token_codec.token_hash(token):
                raise AuthorizationError("scope token hash mismatch")
            manifest = self.get_manifest(claims.engagement_id, claims.engagement_revision)
            if manifest.engagement.expires_at <= utc_now():
                raise AuthorizationError("engagement expired")
        return claims

    def _register_initial_or_progressed_asset(
        self,
        session: Session,
        manifest: EngagementManifest,
        declaration: AssetDeclaration,
    ) -> AssetRevision:
        alias_row = session.get(AssetAliasRow, declaration.id)
        if alias_row is None:
            revision_number = 1
            parent = None
        else:
            current = self._resolve_asset(session, manifest.id, declaration.id)
            desired = self._asset_declaration_payload(manifest, declaration)
            current_comparable = {
                "asset_type": current.asset_type,
                "canonical_location": current.canonical_location,
                "access_mode": current.access_mode,
                "data_classification": current.data_classification,
                "trust_domain": current.trust_domain,
                "network_policy": current.network_policy,
                "allowed_effects": sorted(current.allowed_effects),
                "content_digest": current.content_digest,
            }
            if current_comparable == desired:
                return current
            if not manifest.authorization.allow_harness_asset_progression:
                raise AuthorizationError(
                    f"asset {declaration.id} changed but asset progression is not authorized"
                )
            revision_number = current.revision + 1
            parent = current.versioned_id
        versioned_id = f"{declaration.id}@{revision_number}"
        payload: dict[str, Any] = {
            "engagement_id": manifest.id,
            "asset_alias": declaration.id,
            "revision": revision_number,
            "versioned_id": versioned_id,
            **self._asset_declaration_payload(manifest, declaration),
            "parent_versioned_id": parent,
            "authorization_evidence": {
                "basis": manifest.authorization.basis,
                "status": manifest.authorization.status,
                "engagement_revision": manifest.revision,
                "evidence": list(manifest.authorization.evidence),
            },
            "created_at": utc_now(),
        }
        payload["signature"] = self._sign_asset_payload(payload)
        revision = AssetRevision.model_validate(payload)
        self._insert_asset_revision(session, revision)
        session.flush()
        if alias_row is None:
            session.add(
                AssetAliasRow(
                    asset_alias=declaration.id,
                    engagement_id=manifest.id,
                    current_versioned_id=versioned_id,
                )
            )
        else:
            alias_row.current_versioned_id = versioned_id
            alias_row.updated_at = utc_now()
        return revision

    def _asset_declaration_payload(
        self, manifest: EngagementManifest, declaration: AssetDeclaration
    ) -> dict[str, Any]:
        return {
            "asset_type": declaration.type.value,
            "canonical_location": declaration.location,
            "access_mode": declaration.access.value,
            "data_classification": declaration.data_classification.value,
            "trust_domain": declaration.trust_domain,
            "network_policy": declaration.network.model_dump(mode="json"),
            "allowed_effects": sorted(declaration.allowed_effects),
            "content_digest": declaration.content_digest,
        }

    def _insert_asset_revision(self, session: Session, revision: AssetRevision) -> None:
        session.add(
            AssetRevisionRow(
                engagement_id=revision.engagement_id,
                asset_alias=revision.asset_alias,
                revision=revision.revision,
                versioned_id=revision.versioned_id,
                asset_type=revision.asset_type,
                canonical_location=revision.canonical_location,
                access_mode=revision.access_mode,
                data_classification=revision.data_classification,
                trust_domain=revision.trust_domain,
                network_policy_json=revision.network_policy,
                allowed_effects_json=sorted(revision.allowed_effects),
                content_digest=revision.content_digest,
                parent_versioned_id=revision.parent_versioned_id,
                authorization_evidence_json=revision.authorization_evidence,
                signature=revision.signature,
                created_at=revision.created_at,
            )
        )

    def _resolve_asset(
        self, session: Session, engagement_id: str, alias_or_versioned_id: str
    ) -> AssetRevision:
        if "@" in alias_or_versioned_id:
            row = session.scalar(
                select(AssetRevisionRow).where(
                    AssetRevisionRow.versioned_id == alias_or_versioned_id,
                    AssetRevisionRow.engagement_id == engagement_id,
                )
            )
        else:
            alias = session.get(AssetAliasRow, alias_or_versioned_id)
            if alias is None or alias.engagement_id != engagement_id:
                raise ValidationFailure(
                    f"unknown asset {alias_or_versioned_id!r} for engagement {engagement_id}"
                )
            row = session.scalar(
                select(AssetRevisionRow).where(
                    AssetRevisionRow.versioned_id == alias.current_versioned_id
                )
            )
        if row is None:
            raise ValidationFailure(f"asset not found: {alias_or_versioned_id}")
        revision = AssetRevision(
            engagement_id=row.engagement_id,
            asset_alias=row.asset_alias,
            revision=row.revision,
            versioned_id=row.versioned_id,
            asset_type=row.asset_type,
            canonical_location=row.canonical_location,
            access_mode=row.access_mode,
            data_classification=row.data_classification,
            trust_domain=row.trust_domain,
            network_policy=row.network_policy_json,
            allowed_effects=frozenset(row.allowed_effects_json),
            content_digest=row.content_digest,
            parent_versioned_id=row.parent_versioned_id,
            authorization_evidence=row.authorization_evidence_json,
            signature=row.signature,
            created_at=(row.created_at.replace(tzinfo=UTC) if row.created_at.tzinfo is None else row.created_at),
        )
        unsigned = revision.model_dump(mode="python", exclude={"signature"})
        if not hmac.compare_digest(revision.signature, self._sign_asset_payload(unsigned)):
            raise AuthorizationError("asset revision signature mismatch")
        return revision

    def _issue_scope_token(
        self,
        session: Session,
        manifest: EngagementManifest,
        assets: dict[str, AssetRevision],
    ) -> CompiledScope:
        claims = ScopeTokenClaims(
            engagement_id=manifest.id,
            engagement_revision=manifest.revision,
            assets={alias: asset.versioned_id for alias, asset in assets.items()},
            maximum_risk_tier=manifest.maximum_risk_tier,
            engagement_flags=manifest.engagement.flags,
            issued_at=utc_now(),
            expires_at=manifest.engagement.expires_at,
            nonce=secrets.token_urlsafe(18),
        )
        token = self.token_codec.issue(claims)
        session.add(
            ScopeTokenRow(
                token_id=claims.token_id,
                engagement_id=manifest.id,
                engagement_revision=manifest.revision,
                token_hash=self.token_codec.token_hash(token),
                claims_json=claims.model_dump(mode="json"),
                expires_at=claims.expires_at,
            )
        )
        return CompiledScope(token=token, claims=claims, assets=assets)

    def _sign_asset_payload(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self.signing_key,
            canonical_json(payload).encode(),
            hashlib.sha256,
        ).hexdigest()
