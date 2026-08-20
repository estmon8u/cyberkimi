from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS engagement_revisions (
    engagement_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (engagement_id, revision)
);

CREATE TABLE IF NOT EXISTS asset_revisions (
    asset_alias TEXT NOT NULL,
    revision INTEGER NOT NULL,
    engagement_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (asset_alias, revision)
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    action_template TEXT NOT NULL,
    target_asset_revision TEXT NOT NULL,
    tool_internal_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS budget_usage (
    root_task_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tool_calls INTEGER NOT NULL DEFAULT 0,
    runtime_seconds INTEGER NOT NULL DEFAULT 0,
    artifact_bytes INTEGER NOT NULL DEFAULT 0,
    model_turns INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS execution_grants (
    grant_id TEXT PRIMARY KEY,
    nonce TEXT NOT NULL UNIQUE,
    engagement_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    grant_json TEXT NOT NULL,
    consumed_at TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    engagement_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prior_event_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY,
    byte_count INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    asset_revision TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    artifact_sha256 TEXT,
    source_session_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_sha256) REFERENCES artifacts(sha256)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    state TEXT NOT NULL,
    claim TEXT NOT NULL,
    asset_revision TEXT NOT NULL,
    verification_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);

CREATE TABLE IF NOT EXISTS non_response_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    category TEXT NOT NULL,
    retryable INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    strategy TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS r4_execution_windows (
    engagement_id TEXT NOT NULL,
    executed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_latest ON asset_revisions(asset_alias, revision DESC);
CREATE INDEX IF NOT EXISTS idx_audit_engagement ON audit_events(engagement_id, sequence);
CREATE INDEX IF NOT EXISTS idx_evidence_task ON evidence(task_id, evidence_type);
CREATE INDEX IF NOT EXISTS idx_r4_window ON r4_execution_windows(engagement_id, executed_at);
"""


class Database:
    """Small SQLite boundary with explicit atomic write transactions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def fetch_one(self, query: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(query, parameters).fetchone()

    def fetch_all(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(connection.execute(query, parameters).fetchall())


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
