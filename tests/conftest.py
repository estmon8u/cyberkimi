from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from cyberkimi.assets import AssetRegistry, asset_binding_digest
from cyberkimi.audit import AuditStore
from cyberkimi.authorization import (
    ApprovalService,
    GrantService,
    ScopeTokenService,
    SignedEnvelope,
    SigningKeyStore,
)
from cyberkimi.config import Settings
from cyberkimi.engagement import EngagementService
from cyberkimi.evidence import ArtifactStore, EvidenceStore, Redactor, SecretVault
from cyberkimi.findings import FindingStore
from cyberkimi.models import DataClassification, TaskMode, TaskSpec
from cyberkimi.persistence import Database
from cyberkimi.policy import AuthorizationCoordinator, PolicyEngine
from cyberkimi.tools import AdapterRegistry, default_profile, load_default_registry


@pytest.fixture
def repo_path(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(
        "API_KEY = 'abcdefghijk12345'\n\ndef get_order(user_id, order):\n"
        "    return order\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname="fixture"\nversion="0.0.1"\n', encoding="utf-8"
    )
    return root


@pytest.fixture
def runtime(tmp_path: Path, repo_path: Path) -> dict[str, object]:
    settings = Settings(state_directory=tmp_path / "state")
    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    audit = AuditStore(database)
    keys = SigningKeyStore(settings.scope_private_key_path, settings.scope_public_key_path)
    signer = SignedEnvelope(keys)
    assets = AssetRegistry(database, audit)
    engagement_service = EngagementService(database, audit, signer, assets)
    draft = engagement_service.draft_local(
        repo_path,
        engagement_id="ENG-TEST",
        name="fixture",
        owner_id="user:test",
        expires_in=timedelta(hours=2),
        classification=DataClassification.INTERNAL,
        external_model_allowed=False,
    )
    engagement, _signature = engagement_service.create(draft)
    registry = load_default_registry(database)
    approvals = ApprovalService(database, audit)
    grants = GrantService(database, audit, signer)
    scopes = ScopeTokenService(database, audit, signer)
    policy = PolicyEngine()
    coordinator = AuthorizationCoordinator(database, audit, policy, approvals, grants)
    adapters = AdapterRegistry()
    vault = SecretVault(settings.vault_key_path, database, audit)
    artifacts = ArtifactStore(settings.artifact_directory, database, audit)
    evidence = EvidenceStore(database, audit, artifacts, Redactor(vault))
    finding_store = FindingStore(database, audit)
    return {
        "settings": settings,
        "database": database,
        "audit": audit,
        "keys": keys,
        "signer": signer,
        "assets": assets,
        "engagement_service": engagement_service,
        "engagement": engagement,
        "registry": registry,
        "approvals": approvals,
        "grants": grants,
        "scopes": scopes,
        "policy": policy,
        "coordinator": coordinator,
        "adapters": adapters,
        "vault": vault,
        "artifacts": artifacts,
        "evidence": evidence,
        "findings": finding_store,
    }


def make_task(runtime: dict[str, object], *, task_id: str = "TASK-TEST") -> tuple[TaskSpec, str, str]:
    engagement = runtime["engagement"]
    scopes = runtime["scopes"]
    assert hasattr(engagement, "assets")
    asset = engagement.assets[0]  # type: ignore[attr-defined]
    task = TaskSpec(
        task_id=task_id,
        engagement_id=engagement.engagement_id,  # type: ignore[attr-defined]
        engagement_revision=engagement.revision,  # type: ignore[attr-defined]
        asset_id=asset.asset_id,
        mode=TaskMode.REVIEW,
        goal="Review access-control enforcement and search for secrets",
        allowed_effects=frozenset(asset.allowed_effects),
        risk_ceiling=engagement.risk_ceiling,  # type: ignore[attr-defined]
    )
    token, digest = scopes.issue(  # type: ignore[attr-defined]
        engagement,
        task,
        {asset.asset_id: asset_binding_digest(asset)},
    )
    return task, token, digest


@pytest.fixture
def task_scope(runtime: dict[str, object]) -> tuple[TaskSpec, str, str]:
    return make_task(runtime)


@pytest.fixture
def repository_read(runtime: dict[str, object]):
    registry = runtime["registry"]
    tool = registry.get("repository.read@1.0.0")  # type: ignore[attr-defined]
    return tool, default_profile(tool)
