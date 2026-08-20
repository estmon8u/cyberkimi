from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .domain import ExecutionGrant, TrustProfile
from .policy import PolicyEngine
from .store import Database


CONTROL_PLANE_ENV_PREFIXES = (
    "MOONSHOT_",
    "KIMI_",
    "OPENAI_",
    "CYBERKIMI_SIGNING_",
    "CYBERKIMI_VAULT_",
    "DATABASE_",
)


class ExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegisteredCommand:
    command_id: str
    argv: tuple[str, ...]
    allowed_profiles: frozenset[TrustProfile]

    def __post_init__(self) -> None:
        if not self.argv:
            raise ValueError("registered command must contain an executable")
        if any("\x00" in part for part in self.argv):
            raise ValueError("command arguments cannot contain NUL bytes")


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    started_at: datetime
    finished_at: datetime


class KillSwitch:
    def __init__(self, database: Database) -> None:
        self.database = database
        with self.database.transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS kill_switches ("
                "engagement_id TEXT PRIMARY KEY, armed INTEGER NOT NULL, "
                "reason TEXT, updated_at TEXT NOT NULL)"
            )

    def arm(self, engagement_id: str, reason: str) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO kill_switches (engagement_id, armed, reason, updated_at) "
                "VALUES (?, 1, ?, ?) ON CONFLICT(engagement_id) DO UPDATE SET "
                "armed = 1, reason = excluded.reason, updated_at = excluded.updated_at",
                (engagement_id, reason, datetime.now(timezone.utc).isoformat()),
            )

    def clear(self, engagement_id: str) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO kill_switches (engagement_id, armed, reason, updated_at) "
                "VALUES (?, 0, NULL, ?) ON CONFLICT(engagement_id) DO UPDATE SET "
                "armed = 0, reason = NULL, updated_at = excluded.updated_at",
                (engagement_id, datetime.now(timezone.utc).isoformat()),
            )

    def is_armed(self, engagement_id: str) -> bool:
        row = self.database.fetch_one(
            "SELECT armed FROM kill_switches WHERE engagement_id = ?", (engagement_id,)
        )
        return row is not None and bool(row["armed"])


class RestrictedProcessOperator:
    """Executes pre-registered argv arrays only; no shell or model-provided command text."""

    def __init__(
        self,
        policy: PolicyEngine,
        kill_switch: KillSwitch,
        commands: Mapping[str, RegisteredCommand],
        *,
        maximum_output_bytes: int = 2_000_000,
    ) -> None:
        self.policy = policy
        self.kill_switch = kill_switch
        self.commands = dict(commands)
        self.maximum_output_bytes = maximum_output_bytes

    async def execute(
        self,
        *,
        grant: ExecutionGrant,
        command_id: str,
        engagement_id: str,
        asset_root: Path,
        artifact_directory: Path,
        environment: Mapping[str, str] | None = None,
    ) -> ExecutionResult:
        if grant.engagement_revision.split("@", 1)[0] != engagement_id:
            raise ExecutionError("grant engagement mismatch")
        if self.kill_switch.is_armed(engagement_id):
            raise ExecutionError("engagement kill switch is armed")
        command = self.commands.get(command_id)
        if command is None:
            raise ExecutionError("command is not registered")
        profile = TrustProfile(grant.deployment_profile)
        if profile not in command.allowed_profiles:
            raise ExecutionError("command is not authorized for selected trust profile")
        if profile != TrustProfile.RESTRICTED:
            raise ExecutionError("process backend is limited to the restricted trust profile")
        resolved_root = asset_root.resolve(strict=True)
        resolved_artifacts = artifact_directory.resolve()
        resolved_artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.policy.consume_grant(grant)

        clean_environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(resolved_artifacts),
            "CYBERKIMI_ASSET_ROOT": str(resolved_root),
            "CYBERKIMI_ARTIFACT_DIR": str(resolved_artifacts),
        }
        for key, value in (environment or {}).items():
            if any(key.upper().startswith(prefix) for prefix in CONTROL_PLANE_ENV_PREFIXES):
                raise ExecutionError(f"control-plane environment variable is prohibited: {key}")
            clean_environment[key] = value

        started = datetime.now(timezone.utc)
        process = await asyncio.create_subprocess_exec(
            *command.argv,
            cwd=resolved_root,
            env=clean_environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=grant.effective_timeout_seconds
            )
        except TimeoutError:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
            stdout_bytes = b""
            stderr_bytes = b"execution timed out"

        combined_size = len(stdout_bytes) + len(stderr_bytes)
        truncated = combined_size > self.maximum_output_bytes
        if truncated:
            stdout_limit = min(len(stdout_bytes), self.maximum_output_bytes // 2)
            stderr_limit = self.maximum_output_bytes - stdout_limit
            stdout_bytes = stdout_bytes[:stdout_limit]
            stderr_bytes = stderr_bytes[:stderr_limit]
        finished = datetime.now(timezone.utc)
        return ExecutionResult(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            timed_out=timed_out,
            output_truncated=truncated,
            started_at=started,
            finished_at=finished,
        )
