"""SQLite persistence and atomic control-plane coordination."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Connection, Engine

from cyberkimi.canonical import canonical_text

metadata = MetaData()

engagement_revisions = Table(
    "engagement_revisions",
    metadata,
    Column("engagement_id", String(200), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("status", String(32), nullable=False),
    Column("manifest_json", Text, nullable=False),
    Column("manifest_digest", String(80), nullable=False),
    Column("signature_token", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("engagement_id", "revision", name="uq_engagement_revision"),
)

assets = Table(
    "assets",
    metadata,
    Column("asset_id", String(300), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("engagement_revision", Integer, nullable=False),
    Column("kind", String(64), nullable=False),
    Column("binding_digest", String(80), nullable=False),
    Column("asset_json", Text, nullable=False),
    Column("status", String(32), nullable=False),
)

scope_tokens = Table(
    "scope_tokens",
    metadata,
    Column("token_digest", String(80), primary_key=True),
    Column("task_id", String(200), nullable=False, unique=True),
    Column("token", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked", Boolean, nullable=False, default=False),
)

tasks = Table(
    "tasks",
    metadata,
    Column("task_id", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("engagement_revision", Integer, nullable=False),
    Column("asset_id", String(300), nullable=False),
    Column("mode", String(32), nullable=False),
    Column("status", String(32), nullable=False),
    Column("task_json", Text, nullable=False),
    Column("scope_token_digest", String(80), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

pending_actions = Table(
    "pending_actions",
    metadata,
    Column("action_id", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("task_id", String(200), nullable=False),
    Column("action_digest", String(80), nullable=False, unique=True),
    Column("status", String(32), nullable=False),
    Column("action_json", Text, nullable=False),
    Column("preview_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", String(200), primary_key=True),
    Column("action_digest", String(80), nullable=False, unique=True),
    Column("decision", String(16), nullable=False),
    Column("approval_json", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True), nullable=True),
)

budget_reservations = Table(
    "budget_reservations",
    metadata,
    Column("reservation_id", String(200), primary_key=True),
    Column("task_id", String(200), nullable=False),
    Column("action_digest", String(80), nullable=False, unique=True),
    Column("tool_calls", Integer, nullable=False),
    Column("runtime_seconds", Integer, nullable=False),
    Column("artifact_bytes", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

execution_grants = Table(
    "execution_grants",
    metadata,
    Column("grant_id", String(200), primary_key=True),
    Column("action_digest", String(80), nullable=False, unique=True),
    Column("nonce", String(200), nullable=False, unique=True),
    Column("grant_token", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True), nullable=True),
)

tool_manifests = Table(
    "tool_manifests",
    metadata,
    Column("template_id", String(300), primary_key=True),
    Column("api_name", String(200), nullable=False, unique=True),
    Column("manifest_digest", String(80), nullable=False, unique=True),
    Column("manifest_json", Text, nullable=False),
)

tool_runs = Table(
    "tool_runs",
    metadata,
    Column("tool_run_id", String(200), primary_key=True),
    Column("grant_id", String(200), nullable=False, unique=True),
    Column("action_digest", String(80), nullable=False),
    Column("tool_template_id", String(300), nullable=False),
    Column("status", String(40), nullable=False),
    Column("result_json", Text, nullable=False),
    Column("action_json", Text, nullable=False),
    Column("asset_json", Text, nullable=False),
    Column("profile_json", Text, nullable=False),
    Column("result_digest", String(80), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

artifacts = Table(
    "artifacts",
    metadata,
    Column("artifact_id", String(200), primary_key=True),
    Column("digest", String(80), nullable=False, unique=True),
    Column("record_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

evidence = Table(
    "evidence",
    metadata,
    Column("evidence_id", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("task_id", String(200), nullable=False),
    Column("asset_id", String(300), nullable=False),
    Column("content_hash", String(80), nullable=False),
    Column("evidence_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

findings = Table(
    "findings",
    metadata,
    Column("finding_id", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("task_id", String(200), nullable=False),
    Column("asset_id", String(300), nullable=False),
    Column("state", String(32), nullable=False),
    Column("dedupe_key", String(80), nullable=False),
    Column("finding_json", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("engagement_id", "dedupe_key", name="uq_finding_dedupe"),
)

model_calls = Table(
    "model_calls",
    metadata,
    Column("model_call_id", String(200), primary_key=True),
    Column("task_id", String(200), nullable=False),
    Column("result", String(64), nullable=False),
    Column("record_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("engagement_id", String(200), nullable=False),
    Column("sequence", Integer, nullable=False),
    Column("event_type", String(100), nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("previous_event_hash", String(80), nullable=False),
    Column("event_hash", String(80), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("engagement_id", "sequence", name="uq_audit_sequence"),
    UniqueConstraint("engagement_id", "event_hash", name="uq_audit_hash"),
)

vault_records = Table(
    "vault_records",
    metadata,
    Column("secret_ref", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("secret_type", String(100), nullable=False),
    Column("ciphertext", Text, nullable=False),
    Column("fingerprint", String(80), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

reports = Table(
    "reports",
    metadata,
    Column("report_id", String(200), primary_key=True),
    Column("engagement_id", String(200), nullable=False),
    Column("format", String(32), nullable=False),
    Column("artifact_digest", String(80), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

non_response_events = Table(
    "non_response_events",
    metadata,
    Column("event_id", String(200), primary_key=True),
    Column("task_id", String(200), nullable=False),
    Column("category", String(64), nullable=False),
    Column("event_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

evaluation_runs = Table(
    "evaluation_runs",
    metadata,
    Column("evaluation_run_id", String(200), primary_key=True),
    Column("result_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


class Database:
    """A SQLite database with WAL mode and one logical writer."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite+pysqlite:///{path}", future=True)
        self._writer_lock = threading.RLock()
        self._configure_sqlite(self.engine)

    @staticmethod
    def _configure_sqlite(engine: Engine) -> None:
        @event.listens_for(engine, "connect")
        def set_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=FULL")
            cursor.close()

    def initialize(self) -> None:
        metadata.create_all(self.engine)

    @contextmanager
    def transaction(self) -> Iterator[Connection]:
        with self._writer_lock, self.engine.begin() as connection:
            yield connection

    def ping(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.exec_driver_sql("SELECT 1")
            return True
        except Exception:
            return False

    def put_json(
        self,
        table: Table,
        values: dict[str, Any],
        *,
        connection: Connection | None = None,
    ) -> None:
        if connection is not None:
            connection.execute(insert(table).values(**values))
            return
        with self.transaction() as tx:
            tx.execute(insert(table).values(**values))

    def fetch_one(self, statement: Any) -> dict[str, Any] | None:
        with self.engine.connect() as connection:
            row = connection.execute(statement).mappings().first()
            return dict(row) if row is not None else None

    def fetch_all(self, statement: Any) -> list[dict[str, Any]]:
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(statement).mappings().all()]

    def task_usage(self, task_id: str, connection: Connection) -> tuple[int, int, int]:
        rows = connection.execute(
            select(
                budget_reservations.c.tool_calls,
                budget_reservations.c.runtime_seconds,
                budget_reservations.c.artifact_bytes,
            ).where(
                budget_reservations.c.task_id == task_id,
                budget_reservations.c.state.in_(["reserved", "consumed"]),
            )
        ).all()
        return (
            sum(int(row.tool_calls) for row in rows),
            sum(int(row.runtime_seconds) for row in rows),
            sum(int(row.artifact_bytes) for row in rows),
        )

    def revoke_scope_token(self, token_digest: str) -> bool:
        with self.transaction() as connection:
            result = connection.execute(
                update(scope_tokens)
                .where(scope_tokens.c.token_digest == token_digest)
                .values(revoked=True)
            )
            return bool(result.rowcount)

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def json_value(value: Any) -> str:
        return canonical_text(value)
