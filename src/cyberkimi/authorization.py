from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .domain import AssetRevision, EngagementRevision
from .store import Database, canonical_json


class AuthorizationError(RuntimeError):
    pass


class RevisionConflict(AuthorizationError):
    pass


class ScopeSigner:
    """HMAC signer used by the trusted control plane for scope artifacts."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("scope signing key must be at least 32 bytes")
        self._key = key

    def sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: dict[str, Any], signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class AuthorizationRegistry:
    def __init__(self, database: Database, signer: ScopeSigner) -> None:
        self.database = database
        self.signer = signer

    def register_engagement(self, engagement: EngagementRevision) -> None:
        document = engagement.model_dump(mode="json")
        serialized = canonical_json(document)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        try:
            with self.database.transaction() as connection:
                previous = connection.execute(
                    "SELECT revision FROM engagement_revisions "
                    "WHERE engagement_id = ? ORDER BY revision DESC LIMIT 1",
                    (engagement.engagement_id,),
                ).fetchone()
                expected = 1 if previous is None else int(previous["revision"]) + 1
                if engagement.revision != expected:
                    raise RevisionConflict(
                        f"engagement revision must progress from {expected - 1} to {expected}"
                    )
                connection.execute(
                    "INSERT INTO engagement_revisions "
                    "(engagement_id, revision, document_json, document_sha256, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        engagement.engagement_id,
                        engagement.revision,
                        serialized,
                        digest,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RevisionConflict("engagement revision already exists") from exc

    def register_asset(self, asset: AssetRevision) -> None:
        unsigned = asset.model_dump(mode="json", exclude={"signature"})
        if not self.signer.verify(unsigned, asset.signature):
            raise AuthorizationError("asset revision signature is invalid")
        serialized = canonical_json(asset.model_dump(mode="json"))
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        try:
            with self.database.transaction() as connection:
                engagement = connection.execute(
                    "SELECT 1 FROM engagement_revisions WHERE engagement_id = ? LIMIT 1",
                    (asset.engagement_id,),
                ).fetchone()
                if engagement is None:
                    raise AuthorizationError("asset references an unknown engagement")
                previous = connection.execute(
                    "SELECT revision FROM asset_revisions "
                    "WHERE asset_alias = ? ORDER BY revision DESC LIMIT 1",
                    (asset.asset_alias,),
                ).fetchone()
                expected = 1 if previous is None else int(previous["revision"]) + 1
                if asset.revision != expected:
                    raise RevisionConflict(
                        f"asset revision must progress from {expected - 1} to {expected}"
                    )
                connection.execute(
                    "INSERT INTO asset_revisions "
                    "(asset_alias, revision, engagement_id, document_json, document_sha256, "
                    "signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        asset.asset_alias,
                        asset.revision,
                        asset.engagement_id,
                        serialized,
                        digest,
                        asset.signature,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RevisionConflict("asset revision already exists") from exc

    def resolve_asset(self, identifier: str, engagement_id: str) -> AssetRevision:
        if "@" in identifier:
            alias, revision_text = identifier.rsplit("@", 1)
            try:
                revision = int(revision_text)
            except ValueError as exc:
                raise AuthorizationError("invalid versioned asset identifier") from exc
            row = self.database.fetch_one(
                "SELECT document_json FROM asset_revisions "
                "WHERE asset_alias = ? AND revision = ? AND engagement_id = ?",
                (alias, revision, engagement_id),
            )
        else:
            row = self.database.fetch_one(
                "SELECT document_json FROM asset_revisions "
                "WHERE asset_alias = ? AND engagement_id = ? "
                "ORDER BY revision DESC LIMIT 1",
                (identifier, engagement_id),
            )
        if row is None:
            raise AuthorizationError(f"asset is not registered in engagement: {identifier}")
        asset = AssetRevision.model_validate(json.loads(row["document_json"]))
        unsigned = asset.model_dump(mode="json", exclude={"signature"})
        if not self.signer.verify(unsigned, asset.signature):
            raise AuthorizationError("stored asset signature failed verification")
        return asset

    def latest_engagement(self, engagement_id: str) -> EngagementRevision:
        row = self.database.fetch_one(
            "SELECT document_json FROM engagement_revisions "
            "WHERE engagement_id = ? ORDER BY revision DESC LIMIT 1",
            (engagement_id,),
        )
        if row is None:
            raise AuthorizationError(f"unknown engagement: {engagement_id}")
        return EngagementRevision.model_validate(json.loads(row["document_json"]))
