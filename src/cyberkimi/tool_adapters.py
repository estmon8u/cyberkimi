"""Safe, fixed-shape local tool adapters."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cyberkimi.assets import safe_resolve
from cyberkimi.errors import ToolUnavailable, ValidationFailure
from cyberkimi.models import Asset, DeploymentProfile, ToolManifest, ToolResult, ToolRunStatus

BLOCKED_ENV_NAMES = frozenset(
    {
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "CYBERKIMI_SCOPE_PRIVATE_KEY",
        "CYBERKIMI_VAULT_KEY",
        "DOCKER_HOST",
        "CONTAINER_HOST",
    }
)


class ToolAdapter(Protocol):
    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult: ...


class FixedSubprocessRunner:
    """Run only an adapter-constructed argv with a sanitized environment."""

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: int,
        output_bytes: int,
        extra_env: Mapping[str, str] | None = None,
    ) -> tuple[int, str, str, bool]:
        if not argv or any("\x00" in value for value in argv):
            raise ValidationFailure("invalid fixed command arguments")
        env: dict[str, str] = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(cwd),
        }
        if extra_env:
            for key, value in extra_env.items():
                if key in BLOCKED_ENV_NAMES or key.startswith("CYBERKIMI_"):
                    raise ValidationFailure(f"control-plane environment variable forbidden: {key}")
                env[key] = value
        for key in BLOCKED_ENV_NAMES:
            env.pop(key, None)
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=env,
                shell=False,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise ToolUnavailable(f"binary not installed: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"")[:output_bytes].decode("utf-8", errors="replace")
            stderr = (exc.stderr or b"")[:output_bytes].decode("utf-8", errors="replace")
            return 124, stdout, stderr, True
        stdout_bytes = completed.stdout[:output_bytes]
        stderr_bytes = completed.stderr[:output_bytes]
        truncated = len(completed.stdout) > output_bytes or len(completed.stderr) > output_bytes
        return (
            completed.returncode,
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            truncated,
        )


class RepositoryListAdapter:
    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult:
        started = datetime.now(timezone.utc)
        root = Path(asset.canonical_locator).resolve(strict=True)
        max_files = int(arguments.get("max_files", 10_000))
        files: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if len(files) >= max_files:
                break
            if not path.is_file() or ".git" in path.parts:
                continue
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size_bytes": path.stat().st_size,
                }
            )
        return ToolResult(
            status=ToolRunStatus.SUCCESS,
            tool_template_id=manifest.template_id,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            structured={"files": files, "truncated": len(files) >= max_files},
        )


class RepositoryReadAdapter:
    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult:
        started = datetime.now(timezone.utc)
        root = Path(asset.canonical_locator)
        path = safe_resolve(root, str(arguments["path"]))
        max_bytes = min(int(arguments.get("max_bytes", 200_000)), profile.output_bytes)
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            raise ValidationFailure("binary file cannot be decoded as model-visible source")
        clipped = data[:max_bytes]
        return ToolResult(
            status=ToolRunStatus.SUCCESS,
            tool_template_id=manifest.template_id,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            structured={
                "path": path.relative_to(root.resolve()).as_posix(),
                "size_bytes": len(data),
                "content": clipped.decode("utf-8", errors="replace"),
            },
            truncated=len(data) > max_bytes,
        )


class RepositorySearchAdapter:
    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult:
        started = datetime.now(timezone.utc)
        root = Path(asset.canonical_locator).resolve(strict=True)
        query = str(arguments["query"])
        max_results = int(arguments.get("max_results", 200))
        globs = tuple(str(item) for item in arguments.get("include_globs", ["*"]))
        regex = re.compile(query if bool(arguments.get("regex", False)) else re.escape(query))
        results: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if len(results) >= max_results:
                break
            if not path.is_file() or ".git" in path.parts:
                continue
            relative = path.relative_to(root).as_posix()
            if not any(fnmatch.fnmatch(relative, pattern) for pattern in globs):
                continue
            if path.stat().st_size > 2_000_000:
                continue
            data = path.read_bytes()
            if b"\x00" in data[:8192]:
                continue
            for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    results.append(
                        {"path": relative, "line": line_number, "excerpt": line[:500]}
                    )
                    if len(results) >= max_results:
                        break
        return ToolResult(
            status=ToolRunStatus.SUCCESS,
            tool_template_id=manifest.template_id,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            structured={"matches": results},
            truncated=len(results) >= max_results,
        )


class DependencyExtractAdapter:
    FILES = (
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "package-lock.json",
        "Cargo.toml",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "conanfile.py",
        "conanfile.txt",
    )

    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult:
        started = datetime.now(timezone.utc)
        root = Path(asset.canonical_locator).resolve(strict=True)
        manifests: list[dict[str, Any]] = []
        for name in self.FILES:
            for path in root.rglob(name):
                if ".git" in path.parts or not path.is_file():
                    continue
                data = path.read_text(encoding="utf-8", errors="replace")[: profile.output_bytes]
                manifests.append(
                    {"path": path.relative_to(root).as_posix(), "content": data}
                )
        return ToolResult(
            status=ToolRunStatus.SUCCESS,
            tool_template_id=manifest.template_id,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            structured={"manifests": manifests},
        )


class ExternalJsonAdapter:
    """Execute a fixed external scanner and parse JSON/SARIF/CycloneDX output."""

    def __init__(self, runner: FixedSubprocessRunner):
        self.runner = runner

    def _argv(self, adapter: str, root: Path, arguments: dict[str, Any]) -> list[str]:
        if adapter == "semgrep":
            return [
                "semgrep",
                "scan",
                "--json",
                "--metrics=off",
                "--config",
                str(arguments.get("config", "auto")),
                str(root),
            ]
        if adapter == "gitleaks":
            return [
                "gitleaks",
                "detect",
                "--no-git",
                "--source",
                str(root),
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--redact",
            ]
        if adapter == "osv":
            return ["osv-scanner", "scan", "source", "--format", "json", str(root)]
        if adapter == "syft":
            return ["syft", f"dir:{root}", "-o", "cyclonedx-json"]
        raise ValidationFailure(f"unknown fixed external adapter: {adapter}")

    def execute(
        self,
        manifest: ToolManifest,
        asset: Asset,
        arguments: dict[str, Any],
        profile: DeploymentProfile,
    ) -> ToolResult:
        started = datetime.now(timezone.utc)
        root = Path(asset.canonical_locator).resolve(strict=True)
        binary = {"semgrep": "semgrep", "gitleaks": "gitleaks", "osv": "osv-scanner", "syft": "syft"}[
            manifest.adapter
        ]
        if shutil.which(binary) is None:
            return ToolResult(
                status=ToolRunStatus.TOOL_UNAVAILABLE,
                tool_template_id=manifest.template_id,
                started_at=started,
                completed_at=datetime.now(timezone.utc),
                error_code="TOOL_UNAVAILABLE",
                stderr=f"{binary} is not installed",
            )
        code, stdout, stderr, truncated = self.runner.run(
            self._argv(manifest.adapter, root, arguments),
            cwd=root,
            timeout_seconds=profile.timeout_seconds,
            output_bytes=profile.output_bytes,
        )
        structured: dict[str, Any] = {}
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                structured = parsed if isinstance(parsed, dict) else {"items": parsed}
            except json.JSONDecodeError:
                structured = {"raw": stdout}
        return ToolResult(
            status=ToolRunStatus.SUCCESS if code in {0, 1} else ToolRunStatus.FAILED,
            tool_template_id=manifest.template_id,
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            exit_code=code,
            structured=structured,
            stdout="" if structured else stdout,
            stderr=stderr,
            truncated=truncated,
        )


class AdapterRegistry:
    def __init__(self):
        runner = FixedSubprocessRunner()
        external = ExternalJsonAdapter(runner)
        self._adapters: dict[str, ToolAdapter] = {
            "repository_list": RepositoryListAdapter(),
            "repository_read": RepositoryReadAdapter(),
            "repository_search": RepositorySearchAdapter(),
            "dependency_extract": DependencyExtractAdapter(),
            "semgrep": external,
            "gitleaks": external,
            "osv": external,
            "syft": external,
        }

    def register(self, name: str, adapter: ToolAdapter) -> None:
        if name in self._adapters:
            raise ValidationFailure(f"adapter already registered: {name}")
        self._adapters[name] = adapter

    def get(self, name: str) -> ToolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ToolUnavailable(f"adapter not registered: {name}") from exc
