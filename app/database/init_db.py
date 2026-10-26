"""Schema creation and first-run bootstrap (admin account)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.rbac import Role
from app.core.security import generate_password, password_policy_violations
from app.database import repository
from app.database.models import Base
from app.database.session import get_engine, get_session_factory

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BootstrapResult:
    admin_created: bool
    password_file: Path | None = None


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content + "\n")


def create_schema() -> None:
    Base.metadata.create_all(bind=get_engine())


def bootstrap_admin(db: Session, settings: Settings) -> BootstrapResult:
    """Create the first administrator when the user table is empty.

    The password comes from ``CYBERSHIELD_ADMIN_PASSWORD(_FILE)``; otherwise a
    strong random password is generated and written to
    ``<data_dir>/initial_admin_password`` with ``0600`` permissions. The
    password itself is never logged.
    """
    if repository.count_users(db) > 0:
        return BootstrapResult(admin_created=False)
    password = settings.admin_password_value
    password_file: Path | None = None
    if password is None:
        password = generate_password()
        password_file = settings.data_dir / "initial_admin_password"
        _write_private(password_file, password)
    elif password_policy_violations(password, settings.admin_username):
        raise ValueError("Configured admin password does not satisfy the password policy")
    repository.create_user(
        db,
        username=settings.admin_username,
        email=settings.admin_email,
        password=password,
        role=Role.ADMIN.value,
    )
    if password_file:
        logger.warning(
            "Initial administrator '%s' created. Password stored in %s (read it, then change it).",
            settings.admin_username,
            password_file,
        )
    else:
        logger.info("Initial administrator '%s' created from configured secret.", settings.admin_username)
    return BootstrapResult(admin_created=True, password_file=password_file)


def init_database(settings: Settings) -> BootstrapResult:
    create_schema()
    with get_session_factory()() as db:
        return bootstrap_admin(db, settings)
