from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml

from cyberkimi.errors import ValidationFailure
from cyberkimi.tools.models import ToolManifest


class ToolRegistry:
    def __init__(self, manifests: Iterable[ToolManifest] = ()) -> None:
        self._by_name: dict[str, ToolManifest] = {}
        self._by_alias: dict[str, ToolManifest] = {}
        for manifest in manifests:
            self.register(manifest)

    @classmethod
    def from_directory(cls, directory: Path) -> "ToolRegistry":
        registry = cls()
        for path in sorted(directory.glob("*.yaml")):
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
            registry.register(ToolManifest.model_validate(payload))
        return registry

    def register(self, manifest: ToolManifest) -> None:
        if manifest.name in self._by_name or manifest.kimi_alias in self._by_alias:
            raise ValidationFailure(f"duplicate tool name or alias: {manifest.name}")
        self._by_name[manifest.name] = manifest
        self._by_alias[manifest.kimi_alias] = manifest

    def require(self, name_or_alias: str) -> ToolManifest:
        manifest = self._by_name.get(name_or_alias) or self._by_alias.get(name_or_alias)
        if manifest is None:
            raise ValidationFailure(f"unknown action template: {name_or_alias}")
        return manifest

    def search(self, query: str, *, asset_type: str | None = None, limit: int = 8) -> tuple[ToolManifest, ...]:
        terms = {term.lower() for term in query.replace("_", " ").replace(".", " ").split() if term}
        scored: list[tuple[int, str, ToolManifest]] = []
        for manifest in self._by_name.values():
            if asset_type and all(item.value != asset_type for item in manifest.accepted_assets):
                continue
            haystack = " ".join(
                (manifest.name, manifest.category, manifest.description, manifest.kimi_alias)
            ).lower()
            score = sum(term in haystack for term in terms)
            scored.append((score, manifest.name, manifest))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return tuple(item[2] for item in scored[: max(1, min(limit, 8))])

    def all(self) -> tuple[ToolManifest, ...]:
        return tuple(self._by_name[name] for name in sorted(self._by_name))

    def __len__(self) -> int:
        return len(self._by_name)
