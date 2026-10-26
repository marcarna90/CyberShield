"""Engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - driver callback
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def configure_database(url: str | None = None) -> Engine:
    """(Re)create the global engine and session factory."""
    global _engine, _session_factory
    url = url or get_settings().sqlalchemy_url
    if _engine is not None:
        _engine.dispose()
    if url.startswith("sqlite"):
        in_memory = url in ("sqlite://", "sqlite:///:memory:")
        if not in_memory:
            db_path = Path(url.split("sqlite:///", 1)[1])
            db_path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool if in_memory else None,
        )
        event.listen(engine, "connect", _sqlite_pragmas)
    else:
        engine = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)
    _engine = engine
    _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return engine


def get_engine() -> Engine:
    if _engine is None:
        return configure_database()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        configure_database()
    if _session_factory is None:  # pragma: no cover - configure_database always sets it
        raise RuntimeError("Database is not configured")
    return _session_factory


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session that is always closed."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for background jobs and the CLI."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
