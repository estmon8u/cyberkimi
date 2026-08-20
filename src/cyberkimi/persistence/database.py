from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from cyberkimi.persistence.models import Base


class Database:
    def __init__(self, url: str) -> None:
        connect_args: dict[str, object] = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        self.engine: Engine = create_engine(
            url,
            future=True,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        if url.startswith("sqlite"):
            event.listen(self.engine, "connect", _enable_sqlite_foreign_keys)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
            autoflush=False,
        )

    def init_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[Session]:
        session = self.session_factory()
        try:
            if immediate and self.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @contextmanager
    def read_session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
        finally:
            session.close()

    def dispose(self) -> None:
        self.engine.dispose()


def _enable_sqlite_foreign_keys(dbapi_connection: object, _connection_record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()
