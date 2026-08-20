from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .data_handling import SECRET_PATTERNS


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hpp",
    ".go",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class SourceMatch:
    path: str
    line: int
    column: int
    kind: str
    excerpt: str


@dataclass(frozen=True)
class DependencyRecord:
    ecosystem: str
    name: str
    declared_version: str | None
    source_path: str


class RepositoryBoundary:
    def __init__(self, root: str | Path, *, maximum_file_bytes: int = 2_000_000) -> None:
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("repository asset must resolve to a directory")
        self.maximum_file_bytes = maximum_file_bytes

    def resolve(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve(strict=True)
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("path escapes registered repository root")
        return candidate

    def list_files(self) -> list[str]:
        files: list[str] = []
        for path in self.root.rglob("*"):
            if any(part in IGNORED_DIRECTORIES for part in path.relative_to(self.root).parts):
                continue
            if path.is_file() and path.stat().st_size <= self.maximum_file_bytes:
                files.append(path.relative_to(self.root).as_posix())
        return sorted(files)

    def read_text(self, relative_path: str) -> str:
        path = self.resolve(relative_path)
        if path.stat().st_size > self.maximum_file_bytes:
            raise ValueError("file exceeds configured read limit")
        return path.read_text(encoding="utf-8", errors="replace")

    def search(self, pattern: str, *, maximum_results: int = 200) -> list[SourceMatch]:
        expression = re.compile(pattern)
        matches: list[SourceMatch] = []
        for relative_path in self.list_files():
            if Path(relative_path).suffix.lower() not in TEXT_SUFFIXES:
                continue
            for line_number, line in enumerate(self.read_text(relative_path).splitlines(), start=1):
                for match in expression.finditer(line):
                    matches.append(
                        SourceMatch(
                            path=relative_path,
                            line=line_number,
                            column=match.start() + 1,
                            kind="repository_search",
                            excerpt=line[:500],
                        )
                    )
                    if len(matches) >= maximum_results:
                        return matches
        return matches

    def secret_signals(self, *, maximum_results: int = 200) -> list[SourceMatch]:
        results: list[SourceMatch] = []
        for relative_path in self.list_files():
            path = Path(relative_path)
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            # Documentation, snapshots, fixtures, and tests remain signals, but
            # are deliberately excluded from automatic high-confidence treatment.
            text = self.read_text(relative_path)
            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    line_start = text.rfind("\n", 0, match.start()) + 1
                    line_end = text.find("\n", match.end())
                    if line_end == -1:
                        line_end = len(text)
                    excerpt = text[line_start:line_end]
                    redacted = excerpt.replace(match.group(0), f"<REDACTED:{kind}>")
                    results.append(
                        SourceMatch(
                            path=relative_path,
                            line=line,
                            column=match.start() - line_start + 1,
                            kind=kind,
                            excerpt=redacted[:500],
                        )
                    )
                    if len(results) >= maximum_results:
                        return results
        return results

    def dependencies(self) -> list[DependencyRecord]:
        records: list[DependencyRecord] = []
        package_json = self.root / "package.json"
        if package_json.is_file():
            document = json.loads(package_json.read_text())
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, version in document.get(section, {}).items():
                    records.append(
                        DependencyRecord("npm", name, str(version), "package.json")
                    )
        requirements = self.root / "requirements.txt"
        if requirements.is_file():
            for line in requirements.read_text().splitlines():
                value = line.strip()
                if not value or value.startswith("#") or value.startswith("-"):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)(.*)", value)
                if match:
                    records.append(
                        DependencyRecord(
                            "pypi",
                            match.group(1),
                            match.group(2).strip() or None,
                            "requirements.txt",
                        )
                    )
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                import tomllib

                document = tomllib.loads(pyproject.read_text())
                for value in document.get("project", {}).get("dependencies", []):
                    match = re.match(r"([A-Za-z0-9_.-]+)(.*)", str(value))
                    if match:
                        records.append(
                            DependencyRecord(
                                "pypi",
                                match.group(1),
                                match.group(2).strip() or None,
                                "pyproject.toml",
                            )
                        )
            except (ValueError, OSError):
                pass
        return sorted(records, key=lambda item: (item.ecosystem, item.name.lower()))

    def python_routes(self) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []
        for relative_path in self.list_files():
            if not relative_path.endswith(".py"):
                continue
            text = self.read_text(relative_path)
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                decorators = [ast.unparse(item) for item in node.decorator_list]
                route_decorators = [
                    item
                    for item in decorators
                    if any(marker in item.lower() for marker in ("route", ".get", ".post", ".put", ".delete"))
                ]
                if route_decorators:
                    calls = [
                        ast.unparse(item.func)
                        for item in ast.walk(node)
                        if isinstance(item, ast.Call)
                    ]
                    routes.append(
                        {
                            "path": relative_path,
                            "line": node.lineno,
                            "handler": node.name,
                            "decorators": route_decorators,
                            "calls": calls,
                        }
                    )
        return routes
