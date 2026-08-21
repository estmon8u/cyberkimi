from __future__ import annotations

from pathlib import Path

import pytest

from cyberkimi.assets import directory_digest, safe_resolve
from cyberkimi.errors import ValidationFailure


def test_safe_resolve_blocks_traversal(repo_path: Path) -> None:
    with pytest.raises(ValidationFailure):
        safe_resolve(repo_path, "../outside")


def test_directory_digest_changes_with_content(repo_path: Path) -> None:
    before = directory_digest(repo_path)
    (repo_path / "new.txt").write_text("changed", encoding="utf-8")
    assert directory_digest(repo_path) != before
