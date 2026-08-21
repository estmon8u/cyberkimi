"""Composition root for the deterministic CyberKimi control plane."""

from __future__ import annotations

from dataclasses import dataclass

from cyberkimi.approvals import ApprovalQueue
from cyberkimi.assets import AssetRegistry
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
from cyberkimi.operator import Operator
from cyberkimi.persistence import Database
from cyberkimi.policy import AuthorizationCoordinator, PolicyEngine
from cyberkimi.tools import AdapterRegistry, ToolRegistry, load_default_registry


@dataclass(frozen=True)
class Runtime:
    settings: Settings
    database: Database
    audit: AuditStore
    keys: SigningKeyStore
    signer: SignedEnvelope
    assets: AssetRegistry
    engagements: EngagementService
    registry: ToolRegistry
    approvals: ApprovalService
    approval_queue: ApprovalQueue
    grants: GrantService
    scopes: ScopeTokenService
    policy: PolicyEngine
    coordinator: AuthorizationCoordinator
    adapters: AdapterRegistry
    operator: Operator
    vault: SecretVault
    artifacts: ArtifactStore
    evidence: EvidenceStore
    findings: FindingStore


def build_runtime(settings: Settings) -> Runtime:
    """Create all services with one database, audit store, and local key boundary."""

    settings.ensure_directories()
    database = Database(settings.database_path)
    database.initialize()
    audit = AuditStore(database)
    keys = SigningKeyStore(settings.scope_private_key_path, settings.scope_public_key_path)
    keys.ensure()
    signer = SignedEnvelope(keys)
    assets = AssetRegistry(database, audit)
    engagements = EngagementService(database, audit, signer, assets)
    registry = load_default_registry(database)
    approvals = ApprovalService(database, audit)
    approval_queue = ApprovalQueue(database, audit, approvals)
    grants = GrantService(database, audit, signer)
    scopes = ScopeTokenService(database, audit, signer)
    policy = PolicyEngine()
    coordinator = AuthorizationCoordinator(database, audit, policy, approvals, grants)
    adapters = AdapterRegistry()
    operator = Operator(database, audit, grants, adapters)
    vault = SecretVault(settings.vault_key_path, database, audit)
    vault.ensure_key()
    artifacts = ArtifactStore(settings.artifact_directory, database, audit)
    evidence = EvidenceStore(database, audit, artifacts, Redactor(vault))
    findings = FindingStore(database, audit)
    return Runtime(
        settings=settings,
        database=database,
        audit=audit,
        keys=keys,
        signer=signer,
        assets=assets,
        engagements=engagements,
        registry=registry,
        approvals=approvals,
        approval_queue=approval_queue,
        grants=grants,
        scopes=scopes,
        policy=policy,
        coordinator=coordinator,
        adapters=adapters,
        operator=operator,
        vault=vault,
        artifacts=artifacts,
        evidence=evidence,
        findings=findings,
    )
