from __future__ import annotations

import json

from cyberkimi.manifest import provision_repository_manifest
from cyberkimi.orchestrator import CyberKimi


def test_repository_can_be_registered_reviewed_and_reported(tmp_path) -> None:
    repository = tmp_path / "service"
    repository.mkdir()
    (repository / "pyproject.toml").write_text(
        '[project]\nname="fixture"\nversion="0.1.0"\ndependencies=["pydantic>=2"]\n'
    )
    (repository / "app.py").write_text(
        'def handler():\n    password = "fixture-secret-value-123"\n    return password\n'
    )
    instance = CyberKimi(tmp_path / "state")
    manifest = provision_repository_manifest(repository, owner="tester")
    assets = instance.register_manifest(manifest)

    result = instance.review_repository(
        engagement_id=manifest.engagement_id,
        asset_id=manifest.assets[0].id,
        goal="Review the local fixture repository",
    )

    assert assets == [f"{manifest.assets[0].id}@1"]
    assert result.file_count == 2
    assert result.dependency_count == 1
    assert result.secret_signal_count >= 1
    assert result.confirmed_finding_count == 0
    assert result.unresolved_finding_count >= 1
    report = json.loads(result.report_path.read_text())
    assert report["summary"]["confirmed_finding_count"] == 0
    assert all(finding["state"] == "unresolved" for finding in report["findings"])
    assert "fixture-secret-value-123" not in result.report_path.read_text()


def test_state_keys_are_private(tmp_path) -> None:
    instance = CyberKimi(tmp_path / "state")
    assert instance.paths.signing_key.stat().st_mode & 0o077 == 0
    assert instance.paths.vault_key.stat().st_mode & 0o077 == 0
