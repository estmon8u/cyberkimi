"""Append-only audit hash chain."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, insert, select
from sqlalchemy.engine import Connection

from cyberkimi.canonical import canonical_text
from cyberkimi.errors import AuditWriteError
from cyberkimi.persistence import Database, audit_events

GENESIS_HASH = "sha256:" + ("0" * 64)


class AuditStore:
    def __init__(self, database: Database):
        self.database = database

    def append(
        self,
        engagement_id: str,
        event_type: str,
        payload: dict[str, Any],
        *,
        connection: Connection | None = None,
    ) -> str:
        try:
            if connection is not None:
                return self._append(connection, engagement_id, event_type, payload)
            with self.database.transaction() as tx:
                return self._append(tx, engagement_id, event_type, payload)
        except Exception as exc:
            if isinstance(exc, AuditWriteError):
                raise
            raise AuditWriteError(f"audit append failed: {exc}") from exc

    def _append(
        self,
        connection: Connection,
        engagement_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> str:
        latest = connection.execute(
            select(audit_events.c.sequence, audit_events.c.event_hash)
            .where(audit_events.c.engagement_id == engagement_id)
            .order_by(audit_events.c.sequence.desc())
            .limit(1)
        ).mappings().first()
        sequence = int(latest["sequence"]) + 1 if latest else 1
        previous = str(latest["event_hash"]) if latest else GENESIS_HASH
        payload_json = canonical_text(payload)
        raw = previous.encode("ascii") + payload_json.encode("utf-8")
        event_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
        connection.execute(
            insert(audit_events).values(
                engagement_id=engagement_id,
                sequence=sequence,
                event_type=event_type,
                payload_json=payload_json,
                previous_event_hash=previous,
                event_hash=event_hash,
                created_at=datetime.now(timezone.utc),
            )
        )
        return event_hash

    def verify(self, engagement_id: str) -> tuple[bool, str]:
        rows = self.database.fetch_all(
            select(audit_events)
            .where(audit_events.c.engagement_id == engagement_id)
            .order_by(audit_events.c.sequence.asc())
        )
        previous = GENESIS_HASH
        expected_sequence = 1
        for row in rows:
            if int(row["sequence"]) != expected_sequence:
                return False, f"sequence gap at {expected_sequence}"
            if row["previous_event_hash"] != previous:
                return False, f"previous hash mismatch at {expected_sequence}"
            raw = previous.encode("ascii") + str(row["payload_json"]).encode("utf-8")
            expected_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
            if row["event_hash"] != expected_hash:
                return False, f"event hash mismatch at {expected_sequence}"
            previous = expected_hash
            expected_sequence += 1
        return True, f"verified {len(rows)} events"

    def export(self, engagement_id: str) -> list[dict[str, Any]]:
        return self.database.fetch_all(
            select(audit_events)
            .where(audit_events.c.engagement_id == engagement_id)
            .order_by(audit_events.c.sequence.asc())
        )

    def count(self, engagement_id: str) -> int:
        row = self.database.fetch_one(
            select(func.count()).select_from(audit_events).where(
                audit_events.c.engagement_id == engagement_id
            )
        )
        return int(row["count_1"]) if row else 0
