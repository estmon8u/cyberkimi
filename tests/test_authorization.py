from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyberkimi.authorization import AuthorizationRegistry, RevisionConflict, ScopeSigner
from cyberkimi.domain import AssetRevision, DataClassification, EngagementRevision, RiskTier
from cyberkimi.store import Database


def engagement(revision: int = 1) -> EngagementRevision:
    now = datetime.now(timezone.utc)
    return EngagementRevision(
        engagement_id="ENG-TEST",
        revision=revision,
        owner="owner",
        approver="owner",
        authorization_basis="local_owner_attestation",
        authorization_status="self_attested",
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
        maximum_risk_tier=RiskTier.R3_BOUNDED_VALIDATION,
    )


def signed_asset(signer: ScopeSigner, revision: int, location: str) -> AssetRevision:
    unsigned = {
        "asset_alias": "repo:service",
        "revision": revision,
        "engagement_id": "ENG-TEST",
        "asset_type": "repository",
        "canonical_location": location,
        "trust_domain": "local",
        "content_revision": f"commit-{revision}",
        "allowed_effects": ["file.read", "process.local"],
        "data_classification": DataClassification.INTERNAL.value,
        "network_identifiers": [],
        "authorization_evidence_digest": "a" * 64,
    }
    return AssetRevision.model_validate({**unsigned, "signature": signer.sign(unsigned)})


def test_revisions_are_immutable_and_alias_resolves_latest(tmp_path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    signer = ScopeSigner(b"x" * 32)
    registry = AuthorizationRegistry(database, signer)
    registry.register_engagement(engagement(1))
    first = signed_asset(signer, 1, "/tmp/service-v1")
    second = signed_asset(signer, 2, "/tmp/service-v2")
    registry.register_asset(first)
    registry.register_asset(second)

    assert registry.resolve_asset("repo:service", "ENG-TEST").versioned_id == "repo:service@2"
    assert registry.resolve_asset("repo:service@1", "ENG-TEST").canonical_location == "/tmp/service-v1"


def test_revision_progression_cannot_skip_or_overwrite(tmp_path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    signer = ScopeSigner(b"x" * 32)
    registry = AuthorizationRegistry(database, signer)
    registry.register_engagement(engagement(1))
    registry.register_asset(signed_asset(signer, 1, "/tmp/service-v1"))

    with pytest.raises(RevisionConflict):
        registry.register_asset(signed_asset(signer, 1, "/tmp/overwritten"))
    with pytest.raises(RevisionConflict):
        registry.register_asset(signed_asset(signer, 3, "/tmp/skipped"))
