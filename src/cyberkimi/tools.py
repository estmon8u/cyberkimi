from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .domain import EngagementRevision, ToolManifest, ToolProfile


class ToolRegistryError(RuntimeError):
    pass


class ToolRegistry:
    """Registry that keeps internal capability IDs separate from provider aliases."""

    def __init__(self, manifests: Iterable[ToolManifest] = ()) -> None:
        self._by_internal_id: dict[str, ToolManifest] = {}
        self._by_alias: dict[str, ToolManifest] = {}
        for manifest in manifests:
            self.register(manifest)

    def register(self, manifest: ToolManifest) -> None:
        if manifest.internal_id in self._by_internal_id:
            raise ToolRegistryError(f"duplicate tool ID: {manifest.internal_id}")
        if manifest.kimi_alias in self._by_alias:
            raise ToolRegistryError(f"duplicate Kimi alias: {manifest.kimi_alias}")
        self._by_internal_id[manifest.internal_id] = manifest
        self._by_alias[manifest.kimi_alias] = manifest

    def require(self, identifier: str) -> ToolManifest:
        manifest = self._by_internal_id.get(identifier) or self._by_alias.get(identifier)
        if manifest is None:
            raise ToolRegistryError(f"unknown tool: {identifier}")
        return manifest

    def select_profile(
        self,
        manifest: ToolManifest,
        engagement: EngagementRevision,
        preferred_profile: str | None = None,
    ) -> ToolProfile:
        candidates = (manifest.base_profile, *manifest.authorized_profiles)
        allowed = [
            profile
            for profile in candidates
            if profile.requires_engagement_flag is None
            or profile.requires_engagement_flag in engagement.capability_flags
        ]
        if preferred_profile:
            selected = next((p for p in allowed if p.name == preferred_profile), None)
            if selected is None:
                raise ToolRegistryError(
                    f"deployment profile {preferred_profile!r} is not authorized by engagement"
                )
            return selected
        return max(allowed, key=lambda profile: int(profile.risk_tier))

    def search(
        self,
        query: str,
        *,
        asset_type: str,
        engagement: EngagementRevision,
        top_k: int = 6,
    ) -> list[ToolManifest]:
        words = set(re.findall(r"[a-z0-9]+", query.lower()))
        scored: list[tuple[int, str, ToolManifest]] = []
        for manifest in self._by_internal_id.values():
            if asset_type not in manifest.accepted_asset_types:
                continue
            profile = self.select_profile(manifest, engagement)
            if profile.risk_tier > engagement.maximum_risk_tier:
                continue
            searchable = " ".join(
                [manifest.internal_id, manifest.kimi_alias, manifest.category]
            ).lower()
            score = sum(1 for word in words if word in searchable)
            scored.append((score, manifest.internal_id, manifest))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[2] for item in scored[: max(1, min(top_k, 8))]]

    @staticmethod
    def provider_definition(manifest: ToolManifest) -> dict[str, Any]:
        """Expose only the stable base schema; deployment profiles remain control-plane data."""
        return {
            "type": "function",
            "function": {
                "name": manifest.kimi_alias,
                "description": (
                    f"Typed {manifest.category} capability. Target assets must be registered; "
                    "execution parameters are resolved and authorized by the harness."
                ),
                "parameters": manifest.input_schema,
            },
        }

    def provider_definitions(self, manifests: Iterable[ToolManifest]) -> list[dict[str, Any]]:
        return [self.provider_definition(manifest) for manifest in manifests]
