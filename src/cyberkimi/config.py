"""Runtime configuration with secure local defaults."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    state_directory: Path = Field(default=Path(".cyberkimi"))
    moonshot_api_key: str | None = None
    moonshot_base_url: str = "https://api.moonshot.ai/v1"
    moonshot_model: str = "kimi-k3"
    model_timeout_seconds: float = 120.0
    provider_no_training: bool = False

    @property
    def database_path(self) -> Path:
        return self.state_directory / "cyberkimi.sqlite3"

    @property
    def artifact_directory(self) -> Path:
        return self.state_directory / "artifacts"

    @property
    def key_directory(self) -> Path:
        return self.state_directory / "keys"

    @property
    def scope_private_key_path(self) -> Path:
        return self.key_directory / "scope_ed25519.pem"

    @property
    def scope_public_key_path(self) -> Path:
        return self.key_directory / "scope_ed25519.pub.pem"

    @property
    def vault_key_path(self) -> Path:
        return self.key_directory / "vault_fernet.key"

    @property
    def fingerprint_key_path(self) -> Path:
        return self.key_directory / "fingerprint_hmac.key"

    def ensure_directories(self) -> None:
        self.state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.key_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.artifact_directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, state_directory: Path | None = None) -> "Settings":
        return cls(
            state_directory=state_directory or Path(os.getenv("CYBERKIMI_STATE_DIR", ".cyberkimi")),
            moonshot_api_key=os.getenv("MOONSHOT_API_KEY"),
            moonshot_base_url=os.getenv("MOONSHOT_BASE_URL", "https://api.moonshot.ai/v1"),
            moonshot_model=os.getenv("MOONSHOT_MODEL", "kimi-k3"),
            provider_no_training=os.getenv("CYBERKIMI_PROVIDER_NO_TRAINING", "false").lower()
            in {"1", "true", "yes"},
        )
