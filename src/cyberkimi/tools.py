"""Immutable tool registry, eligibility resolver, and default manifests."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from sqlalchemy import select

from cyberkimi.canonical import sha256_digest
from cyberkimi.errors import ValidationFailure
from cyberkimi.models import (
    Asset,
    AssetKind,
    DeploymentProfile,
    RiskTier,
    TaskMode,
    TaskSpec,
    ToolManifest,
)
from cyberkimi.persistence import Database, tool_manifests
from cyberkimi.tool_adapters import AdapterRegistry, ToolAdapter


def manifest_digest(manifest: ToolManifest) -> str:
    return sha256_digest(manifest)


class ToolRegistry:
    def __init__(self, database: Database | None = None):
        self.database = database
        self._by_id: dict[str, ToolManifest] = {}
        self._by_api_name: dict[str, ToolManifest] = {}

    def register(self, manifest: ToolManifest) -> str:
        digest = manifest_digest(manifest)
        existing = self._by_id.get(manifest.template_id)
        if existing is not None and manifest_digest(existing) != digest:
            raise ValidationFailure(f"immutable tool version changed: {manifest.template_id}")
        alias = self._by_api_name.get(manifest.api_name)
        if alias is not None and alias.template_id != manifest.template_id:
            raise ValidationFailure(f"ambiguous API alias: {manifest.api_name}")
        self._by_id[manifest.template_id] = manifest
        self._by_api_name[manifest.api_name] = manifest
        if self.database is not None:
            row = self.database.fetch_one(
                select(tool_manifests).where(tool_manifests.c.template_id == manifest.template_id)
            )
            if row is None:
                self.database.put_json(
                    tool_manifests,
                    {
                        "template_id": manifest.template_id,
                        "api_name": manifest.api_name,
                        "manifest_digest": digest,
                        "manifest_json": manifest.model_dump_json(),
                    },
                )
            elif row["manifest_digest"] != digest:
                raise ValidationFailure(f"stored tool digest mismatch: {manifest.template_id}")
        return digest

    def get(self, template_id: str) -> ToolManifest:
        try:
            return self._by_id[template_id]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {template_id}") from exc

    def get_by_api_name(self, api_name: str) -> ToolManifest:
        try:
            return self._by_api_name[api_name]
        except KeyError as exc:
            raise KeyError(f"unknown tool API alias: {api_name}") from exc

    def all(self) -> tuple[ToolManifest, ...]:
        return tuple(sorted(self._by_id.values(), key=lambda item: item.template_id))

    @classmethod
    def from_directory(cls, directory: Path, database: Database | None = None) -> "ToolRegistry":
        registry = cls(database)
        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            registry.register(ToolManifest.model_validate(raw))
        return registry


class EligibleToolResolver:
    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def resolve(
        self,
        task: TaskSpec,
        asset: Asset,
        *,
        language_tags: frozenset[str] = frozenset(),
        requested_effects: frozenset[str] | None = None,
        limit: int = 8,
    ) -> tuple[ToolManifest, ...]:
        if not 1 <= limit <= 8:
            raise ValueError("eligible tool limit must be between one and eight")
        candidates: list[tuple[int, ToolManifest]] = []
        goal_tokens = set(re.findall(r"[A-Za-z0-9_]+", task.goal.lower()))
        for tool in self.registry.all():
            if task.mode not in tool.modes:
                continue
            if asset.kind not in tool.accepted_asset_kinds:
                continue
            if tool.minimum_risk > task.risk_ceiling:
                continue
            if requested_effects is not None and not requested_effects.issubset(tool.maximum_effects):
                continue
            if tool.network_mode == "LAB_ALLOWLIST" and task.mode is not TaskMode.LAB:
                continue
            tags = set(re.findall(r"[A-Za-z0-9_]+", f"{tool.name} {tool.category} {tool.description}".lower()))
            score = len(goal_tokens & tags) + len(language_tags & tags)
            candidates.append((score, tool))
        candidates.sort(key=lambda pair: (-pair[0], pair[1].template_id))
        return tuple(tool for _score, tool in candidates[:limit])


def validate_tool_arguments(manifest: ToolManifest, arguments: dict[str, Any]) -> None:
    errors = sorted(Draft202012Validator(manifest.arguments_schema).iter_errors(arguments), key=str)
    if errors:
        raise ValidationFailure(f"invalid arguments for {manifest.template_id}: {errors[0].message}")


def load_default_registry(database: Database | None = None) -> ToolRegistry:
    registry = ToolRegistry(database)
    for manifest in default_manifests():
        registry.register(manifest)
    return registry


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required or [],
    }


def default_manifests() -> tuple[ToolManifest, ...]:
    repo_kinds = frozenset({AssetKind.REPOSITORY, AssetKind.SOURCE_SNAPSHOT, AssetKind.DIRECTORY})
    r1 = RiskTier.R1_LOCAL_READ_ONLY
    review = frozenset({TaskMode.REVIEW})
    return (
        ToolManifest(
            name="repository.list",
            api_name="repository_list_v1",
            version="1.0.0",
            category="source_analysis",
            description="List bounded regular files in one registered repository.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema(
                {"max_files": {"type": "integer", "minimum": 1, "maximum": 100000}}
            ),
            output_schema_id="cyberkimi.repository_list/v1",
            adapter="repository_list",
        ),
        ToolManifest(
            name="repository.read",
            api_name="repository_read_v1",
            version="1.0.0",
            category="source_analysis",
            description="Read a bounded UTF-8 file beneath one registered repository root.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema(
                {
                    "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1000000},
                },
                ["path"],
            ),
            output_schema_id="cyberkimi.repository_read/v1",
            adapter="repository_read",
        ),
        ToolManifest(
            name="repository.search",
            api_name="repository_search_v1",
            version="1.0.0",
            category="source_analysis",
            description="Search bounded source text beneath one registered repository root.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.search", "repository.read"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema(
                {
                    "query": {"type": "string", "minLength": 1, "maxLength": 500},
                    "regex": {"type": "boolean"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 500},
                    "include_globs": {
                        "type": "array",
                        "maxItems": 20,
                        "items": {"type": "string", "maxLength": 200},
                    },
                },
                ["query"],
            ),
            output_schema_id="cyberkimi.repository_search/v1",
            adapter="repository_search",
        ),
        ToolManifest(
            name="repository.extract_dependencies",
            api_name="repository_extract_dependencies_v1",
            version="1.0.0",
            category="dependency_analysis",
            description="Extract registered dependency manifests without executing package managers.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema({}),
            output_schema_id="cyberkimi.dependency_manifests/v1",
            adapter="dependency_extract",
        ),
        ToolManifest(
            name="source.semgrep_scan",
            api_name="source_semgrep_scan_v1",
            version="1.0.0",
            category="static_analysis",
            description="Run pinned Semgrep configuration against one registered repository.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read", "process.local_readonly"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema(
                {"config": {"type": "string", "minLength": 1, "maxLength": 200}}
            ),
            output_schema_id="sarif-or-semgrep-json/v1",
            adapter="semgrep",
        ),
        ToolManifest(
            name="source.secret_scan_gitleaks",
            api_name="source_secret_scan_gitleaks_v1",
            version="1.0.0",
            category="secret_detection",
            description="Run Gitleaks with redacted output against one registered repository.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read", "process.local_readonly"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema({}),
            output_schema_id="gitleaks-json/v1",
            adapter="gitleaks",
        ),
        ToolManifest(
            name="dependency.osv_scan",
            api_name="dependency_osv_scan_v1",
            version="1.0.0",
            category="dependency_analysis",
            description="Run OSV-Scanner against local manifests and lockfiles.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset({"repository.read", "process.local_readonly"}),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema({}),
            output_schema_id="osv-json/v1",
            adapter="osv",
        ),
        ToolManifest(
            name="dependency.generate_sbom_syft",
            api_name="dependency_generate_sbom_syft_v1",
            version="1.0.0",
            category="dependency_analysis",
            description="Generate a CycloneDX SBOM with Syft from one registered repository.",
            modes=review,
            minimum_risk=r1,
            maximum_effects=frozenset(
                {"repository.read", "process.local_readonly", "artifact.write"}
            ),
            accepted_asset_kinds=repo_kinds,
            arguments_schema=_object_schema({}),
            output_schema_id="cyclonedx-json/v1",
            adapter="syft",
        ),
    )


def default_profile(manifest: ToolManifest) -> DeploymentProfile:
    return DeploymentProfile(
        profile_id=f"rootless-{manifest.name.replace('.', '-')}/v1",
        tool_template_id=manifest.template_id,
        timeout_seconds=min(60, manifest.runtime.timeout_seconds_max),
        memory_mb=min(512, manifest.runtime.memory_mb_max),
        output_bytes=min(2_000_000, manifest.runtime.output_bytes_max),
        network_mode=manifest.network_mode,
        source_mount=manifest.source_mount,
        effects=manifest.maximum_effects,
        risk_floor=manifest.minimum_risk,
    )
