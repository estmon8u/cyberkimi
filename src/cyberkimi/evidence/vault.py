from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy import select

from cyberkimi.core import new_id
from cyberkimi.persistence import Database
from cyberkimi.persistence.models import VaultItemRow


class CredentialVault:
    def __init__(self, database: Database, root: Path, key: bytes) -> None:
        self.database = database
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.cipher = Fernet(key)

    def store(
        self,
        value: str,
        *,
        secret_type: str,
        source_artifact_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        digest = hashlib.sha256(value.encode()).hexdigest()
        with self.database.transaction(immediate=True) as session:
            existing = session.scalar(
                select(VaultItemRow).where(VaultItemRow.secret_hash == digest)
            )
            if existing:
                return existing.vault_id
            vault_id = new_id("VAULT")
            relative = Path("sha256") / digest[:2] / f"{digest}.enc"
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.parent.chmod(0o700)
            temporary = destination.with_suffix(".tmp")
            temporary.write_bytes(self.cipher.encrypt(value.encode()))
            temporary.chmod(0o600)
            temporary.replace(destination)
            session.add(
                VaultItemRow(
                    vault_id=vault_id,
                    secret_hash=digest,
                    encrypted_relative_path=str(relative),
                    secret_type=secret_type,
                    source_artifact_id=source_artifact_id,
                    metadata_json=metadata or {},
                )
            )
            return vault_id

    def retrieve(self, vault_id: str) -> str:
        with self.database.read_session() as session:
            row = session.get(VaultItemRow, vault_id)
            if row is None:
                raise KeyError(vault_id)
            encrypted = (self.root / row.encrypted_relative_path).read_bytes()
        return self.cipher.decrypt(encrypted).decode()
