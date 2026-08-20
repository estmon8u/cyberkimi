from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from cyberkimi.persistence import Database


@pytest.fixture
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(f"sqlite:///{tmp_path / 'cyberkimi-test.db'}")
    db.init_schema()
    yield db
    db.dispose()


@pytest.fixture
def signing_key() -> bytes:
    return b"test-signing-key-32-bytes-long!!"
