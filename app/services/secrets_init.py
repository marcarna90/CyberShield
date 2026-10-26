"""First-boot secret generation (used by the Docker ``init`` service).

Creates, only if absent::

    jwt_secret      JWT signing key           owner app   mode 0400
    admin_password  initial admin password    owner app   mode 0400
    db_password     PostgreSQL password       owner db, group app, mode 0440

Existing files are never overwritten, so restarts keep the same secrets.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from app.core.security import generate_password


def _parse_owner(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    uid, _, gid = value.partition(":")
    return int(uid), int(gid or uid)


def init_secrets(directory: Path, app_owner: str | None = None, db_owner: str | None = None) -> dict[str, bool]:
    """Generate missing secrets. Returns ``{name: created}``."""
    directory.mkdir(parents=True, exist_ok=True)
    app = _parse_owner(app_owner)
    db = _parse_owner(db_owner)
    specs = {
        "jwt_secret": (lambda: secrets.token_urlsafe(64), app, 0o400),
        "admin_password": (generate_password, app, 0o400),
        # Root-owned (the postgres entrypoint reads it as root) and group-readable by the app.
        "db_password": (lambda: secrets.token_urlsafe(32), (db[0] if db else 0, app[1]) if app else db, 0o440),
    }
    created: dict[str, bool] = {}
    for name, (factory, owner, mode) in specs.items():
        path = directory / name
        created[name] = not path.exists()
        if created[name]:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(factory())
        if owner is not None and os.geteuid() == 0:
            os.chown(path, owner[0], owner[1])
        os.chmod(path, mode)
    if os.geteuid() == 0 and app is not None:
        os.chown(directory, 0, app[1])
    os.chmod(directory, 0o750 if app is not None else 0o700)
    return created
