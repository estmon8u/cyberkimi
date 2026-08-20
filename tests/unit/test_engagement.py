from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from cyberkimi.core import DataClassification, RiskTier, TrustProfile, utc_now
from cyberkimi.engagement.manifest import provision_repository_manifest
from cyberkimi.engagement.models import DataHandlingSpec, EngagementManifest
from cyberkimi.engagement.service import EngagementService
from cyberkimi.errors import AuthorizationError, ScopeTokenError, ValidationFailure
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import AssetRevisionRow, EngagementRow


def make_manifest(repo: Path, *, engagement_id: str = "ENG-TEST") -> EngagementManifest:
    repo.mkdir(exist_ok=True)
    return provision_repository_manifest(
        target=repo,
        owner="Esteban",
        engagement_id=engagement_id,
    )


def test_registers_versioned_asset_and_scope_token(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    manifest = make_manifest(tmp_path / "auth-service")
    service = EngagementService(database, signing_key)

    compiled = service.register(manifest)

    assert compiled.claims.engagement_id == manifest.id
    assert compiled.claims.assets == {"repo:auth-service": "repo:auth-service@1"}
    verified = service.verify_scope_token(compiled.token)
    assert verified.token_id == compiled.claims.token_id
    asset = service.resolve_asset(manifest.id, "repo:auth-service")
    assert asset.versioned_id == "repo:auth-service@1"


def test_scope_token_tampering_is_rejected(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    service = EngagementService(database, signing_key)
    compiled = service.register(make_manifest(tmp_path / "repo"))
    token = compiled.token
    replacement = "A" if token[-1] != "A" else "B"

    with pytest.raises(ScopeTokenError):
        service.token_codec.verify(token[:-1] + replacement)


def test_expired_manifest_cannot_be_registered(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    manifest = make_manifest(tmp_path / "repo")
    expired_info = manifest.engagement.model_copy(
        update={
            "created_at": utc_now() - timedelta(days=2),
            "expires_at": utc_now() - timedelta(days=1),
        }
    )
    expired = manifest.model_copy(update={"engagement": expired_info})

    with pytest.raises(ValidationFailure, match="expired"):
        EngagementService(database, signing_key).register(expired)


def test_asset_location_change_requires_authorized_progression(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    original = make_manifest(tmp_path / "repo-v1")
    service = EngagementService(database, signing_key)
    service.register(original)

    replacement_path = tmp_path / "repo-v2"
    replacement_path.mkdir()
    repo_decl = original.scope.repositories[0].model_copy(update={"path": str(replacement_path)})
    scope = original.scope.model_copy(update={"repositories": (repo_decl,)})
    engagement = original.engagement.model_copy(update={"revision": 2})
    changed = original.model_copy(update={"engagement": engagement, "scope": scope})

    with pytest.raises(AuthorizationError, match="progression"):
        service.register(changed)


def test_authorized_progression_creates_new_immutable_revision(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    original = make_manifest(tmp_path / "repo-v1")
    authorization = original.authorization.model_copy(
        update={"allow_harness_asset_progression": True}
    )
    original = original.model_copy(update={"authorization": authorization})
    service = EngagementService(database, signing_key)
    service.register(original)

    replacement_path = tmp_path / "repo-v2"
    replacement_path.mkdir()
    repo_decl = original.scope.repositories[0].model_copy(update={"path": str(replacement_path)})
    scope = original.scope.model_copy(update={"repositories": (repo_decl,)})
    engagement = original.engagement.model_copy(update={"revision": 2})
    changed = original.model_copy(update={"engagement": engagement, "scope": scope})

    service.register(changed)

    current = service.resolve_asset(original.id, "repo:repo-v1")
    previous = service.resolve_asset(original.id, "repo:repo-v1@1")
    assert current.versioned_id == "repo:repo-v1@2"
    assert current.parent_versioned_id == previous.versioned_id
    assert previous.canonical_location.endswith("repo-v1")
    assert current.canonical_location.endswith("repo-v2")


def test_failed_duplicate_registration_is_atomic(
    database: Database, signing_key: bytes, tmp_path: Path
) -> None:
    manifest = make_manifest(tmp_path / "repo")
    service = EngagementService(database, signing_key)
    service.register(manifest)

    with pytest.raises(ValidationFailure):
        service.register(manifest)

    with database.read_session() as session:
        engagement_count = session.scalar(select(func.count()).select_from(EngagementRow))
        asset_count = session.scalar(select(func.count()).select_from(AssetRevisionRow))
    assert engagement_count == 1
    assert asset_count == 1


def test_extended_budget_requires_flag(tmp_path: Path) -> None:
    manifest = make_manifest(tmp_path / "repo")
    payload = manifest.model_dump(mode="json")
    payload["budgets"]["selected"] = "extended"

    with pytest.raises(ValueError, match="extended_operations"):
        EngagementManifest.model_validate(payload)


def test_comprehensive_profile_requires_flag(tmp_path: Path) -> None:
    manifest = make_manifest(tmp_path / "repo")
    payload = manifest.model_dump(mode="json")
    payload["allowed_trust_profiles"] = [
        TrustProfile.RESTRICTED.value,
        TrustProfile.COMPREHENSIVE.value,
    ]
    payload["maximum_risk_tier"] = RiskTier.R4_EXTENDED_OPERATIONS.value

    with pytest.raises(ValueError, match="R4 requires|COMPREHENSIVE"):
        EngagementManifest.model_validate(payload)


def test_raw_secret_transmission_is_never_allowed() -> None:
    with pytest.raises(ValueError, match="never sends raw secrets"):
        DataHandlingSpec(send_raw_secrets_to_model=True)


def test_classification_is_engagement_scoped(tmp_path: Path) -> None:
    manifest = provision_repository_manifest(
        target=(tmp_path / "repo"),
        owner="Esteban",
        engagement_id="ENG-CLASS",
        classification=DataClassification.CONFIDENTIAL,
    ) if (tmp_path / "repo").mkdir() is None else None
    assert manifest is not None
    assert (
        manifest.scope.repositories[0].data_classification
        == DataClassification.CONFIDENTIAL
    )
