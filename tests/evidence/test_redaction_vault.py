from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy import func, select

from cyberkimi.core import DataClassification
from cyberkimi.evidence import CredentialVault, extract_secrets, prepare_for_model
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import VaultItemRow


def test_confidential_evidence_redacts_secrets_and_pii() -> None:
    secret = "sk_live_1234567890abcdef"
    model_evidence = prepare_for_model(
        {
            "message": f'api_key = "{secret}"',
            "email": "alice@example.com",
            "address": "192.168.10.25",
        },
        DataClassification.CONFIDENTIAL,
    )

    rendered = str(model_evidence.content)
    assert secret not in rendered
    assert "alice@example.com" not in rendered
    assert "192.168.10.25" not in rendered
    assert model_evidence.redactions >= 3
    assert not model_evidence.restricted_summary


def test_restricted_evidence_is_replaced_by_a_structured_summary() -> None:
    model_evidence = prepare_for_model(
        {
            "authorization": {"result": "missing enforcement"},
            "secret": "sk_live_1234567890abcdef",
        },
        DataClassification.RESTRICTED,
    )

    assert model_evidence.restricted_summary
    assert model_evidence.content["kind"] == "restricted_security_summary"
    assert "sk_live_1234567890abcdef" not in str(model_evidence.content)
    assert "authorization" in model_evidence.content["security_labels"]


def test_vault_encrypts_and_deduplicates_values(database: Database, tmp_path: Path) -> None:
    secret = "sk_live_1234567890abcdef"
    vault = CredentialVault(database, tmp_path / "vault", Fernet.generate_key())

    first = vault.store(
        secret,
        secret_type="api_key",
        source_artifact_id="ARTIFACT-1",
    )
    second = vault.store(
        secret,
        secret_type="api_key",
        source_artifact_id="ARTIFACT-2",
    )

    assert first == second
    assert vault.retrieve(first) == secret
    encrypted_files = tuple((tmp_path / "vault").rglob("*.enc"))
    assert len(encrypted_files) == 1
    assert secret.encode() not in encrypted_files[0].read_bytes()
    with database.read_session() as session:
        count = session.scalar(select(func.count()).select_from(VaultItemRow))
    assert count == 1


def test_secret_extraction_handles_source_and_json_assignments() -> None:
    values = dict(
        extract_secrets(
            'api_key = "sk_live_1234567890abcdef"\n'
            '{"access_token":"token_1234567890abcdef"}'
        )
    )

    assert values["api_key"] == "sk_live_1234567890abcdef"
    assert values["api_key"] != values.get("bearer")
    assert "token_1234567890abcdef" in values.values()
