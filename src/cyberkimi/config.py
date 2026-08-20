from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import Field

from cyberkimi.core import StrictModel


class Settings(StrictModel):
    database_url: str = "sqlite:///./cyberkimi.db"
    home: Path = Path(".cyberkimi")
    model: str = "kimi-k3"
    model_base_url: str = "https://api.moonshot.ai/v1"
    moonshot_api_key: str | None = None
    signing_key: bytes = Field(repr=False)
    vault_key: bytes = Field(repr=False)
    enable_comprehensive: bool = False

    @property
    def artifact_dir(self) -> Path:
        return self.home / "artifacts"

    @property
    def vault_dir(self) -> Path:
        return self.home / "vault"

    @classmethod
    def from_env(cls, *, create_keys: bool = False) -> "Settings":
        home = Path(os.getenv("CYBERKIMI_HOME", ".cyberkimi"))
        signing_key = _load_or_create_key(
            env_name="CYBERKIMI_SIGNING_KEY",
            path=home / "keys" / "signing.key",
            create=create_keys,
            fernet=False,
        )
        vault_key = _load_or_create_key(
            env_name="CYBERKIMI_VAULT_KEY",
            path=home / "keys" / "vault.key",
            create=create_keys,
            fernet=True,
        )
        return cls(
            database_url=os.getenv("CYBERKIMI_DATABASE_URL", "sqlite:///./cyberkimi.db"),
            home=home,
            model=os.getenv("CYBERKIMI_MODEL", "kimi-k3"),
            model_base_url=os.getenv(
                "CYBERKIMI_MODEL_BASE_URL", "https://api.moonshot.ai/v1"
            ),
            moonshot_api_key=os.getenv("MOONSHOT_API_KEY"),
            signing_key=signing_key,
            vault_key=vault_key,
            enable_comprehensive=os.getenv("CYBERKIMI_ENABLE_COMPREHENSIVE", "0")
            in {"1", "true", "TRUE", "yes", "YES"},
        )

    def initialize_directories(self) -> None:
        for directory in (
            self.home,
            self.home / "keys",
            self.artifact_dir,
            self.vault_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)


def _load_or_create_key(*, env_name: str, path: Path, create: bool, fernet: bool) -> bytes:
    env_value = os.getenv(env_name)
    if env_value:
        return env_value.encode("utf-8")
    if path.exists():
        return path.read_bytes().strip()
    if not create:
        raise RuntimeError(
            f"{env_name} is not set and {path} does not exist; run 'cyberkimi init'"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    value = Fernet.generate_key() if fernet else base64.urlsafe_b64encode(os.urandom(32))
    path.write_bytes(value + b"\n")
    path.chmod(0o600)
    return value
