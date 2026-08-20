from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import func, select

from cyberkimi.core import RiskTier, TaskMode
from cyberkimi.engagement.manifest import provision_repository_manifest
from cyberkimi.engagement.service import EngagementService
from cyberkimi.evidence import ArtifactStore, CredentialVault, EvidenceStore
from cyberkimi.errors import ToolExecutionError
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import ToolRunRow, VaultItemRow
from cyberkimi.policy import AuthorizationRequest, PolicyEngine
from cyberkimi.tasking import ProposedAction, TaskSpec
from cyberkimi.tools import ToolRegistry
from cyberkimi.tools.handlers import HandlerRegistry
from cyberkimi.tools.operator import ToolOperator


def _operator_stack(
    database: Database,
    signing_key: bytes,
    tmp_path: Path,
) -> tuple[Path, object, object, PolicyEngine, ArtifactStore, CredentialVault, ToolOperator]:
    root = tmp_path / "repo"
    root.mkdir()
    manifest = provision_repository_manifest(
        target=root,
        owner="Esteban",
        engagement_id="ENG-OPERATOR",
    )
    engagements = EngagementService(database, signing_key)
    compiled = engagements.register(manifest)
    tools = ToolRegistry.from_directory(Path(__file__).parents[2] / "tool_manifests")
    policy = PolicyEngine(database, engagements, tools, signing_key)
    artifacts = ArtifactStore(database, tmp_path / "artifacts")
    vault = CredentialVault(database, tmp_path / "vault", Fernet.generate_key())
    operator = ToolOperator(
        database=database,
        engagements=engagements,
        policy=policy,
        tools=tools,
        handlers=HandlerRegistry(),
        artifacts=artifacts,
        evidence=EvidenceStore(database),
        vault=vault,
    )
    return root, manifest, compiled, policy, artifacts, vault, operator


def test_secret_scan_keeps_raw_secret_local_and_vaults_it(
    database: Database,
    signing_key: bytes,
    tmp_path: Path,
) -> None:
    root, manifest, compiled, policy, artifacts, vault, operator = _operator_stack(
        database, signing_key, tmp_path
    )
    secret = "sk_live_1234567890abcdef"
    (root / "app.py").write_text(f'api_key = "{secret}"\n', encoding="utf-8")
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Detect candidate secrets without transmitting raw values",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read", "scanner.execute"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="source.secret_scan",
        target_asset_id="repo:repo",
        arguments={"max_results": 20},
        purpose="Locate and locally vault candidate credentials",
    )
    outcome = policy.authorize_adaptive(
        AuthorizationRequest(
            scope_token=compiled.token,
            task=task,
            action=action,
            actor="Esteban",
        )
    )
    assert outcome.grant_token is not None

    evidence = operator.execute(
        task=task,
        action=action,
        grant_token=outcome.grant_token,
    )

    assert secret not in str(evidence.payload)
    assert evidence.artifact_id is not None
    assert secret in artifacts.read(evidence.artifact_id).decode("utf-8")
    vault_refs = evidence.provenance["vault_refs"]
    assert len(vault_refs) == 1
    assert vault.retrieve(vault_refs[0]) == secret
    with database.read_session() as session:
        run_count = session.scalar(select(func.count()).select_from(ToolRunRow))
        vault_count = session.scalar(select(func.count()).select_from(VaultItemRow))
    assert run_count == 1
    assert vault_count == 1


def test_repository_read_rejects_path_escape_after_grant_consumption(
    database: Database,
    signing_key: bytes,
    tmp_path: Path,
) -> None:
    root, manifest, compiled, policy, _artifacts, _vault, operator = _operator_stack(
        database, signing_key, tmp_path
    )
    (root / "safe.py").write_text("print('safe')\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    task = TaskSpec(
        engagement_id=manifest.id,
        mode=TaskMode.REVIEW,
        objective="Read a bounded source excerpt",
        assets=("repo:repo",),
        risk_tier=RiskTier.R1_READ_ONLY,
        allowed_effects=frozenset({"file.read"}),
    )
    action = ProposedAction(
        task_id=task.task_id,
        action_template="repository.read",
        target_asset_id="repo:repo",
        arguments={"path": "../outside.txt"},
        purpose="Attempt a source read",
    )
    outcome = policy.authorize_adaptive(
        AuthorizationRequest(
            scope_token=compiled.token,
            task=task,
            action=action,
            actor="Esteban",
        )
    )
    assert outcome.grant_token is not None

    with pytest.raises(ToolExecutionError, match="escaped the declared asset"):
        operator.execute(
            task=task,
            action=action,
            grant_token=outcome.grant_token,
        )

    with database.read_session() as session:
        failed = session.scalar(
            select(func.count()).select_from(ToolRunRow).where(ToolRunRow.status == "failed")
        )
    assert failed == 1
