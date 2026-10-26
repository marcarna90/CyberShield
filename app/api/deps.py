"""Request dependencies: settings, database session, authentication and authorisation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.rbac import has_permission
from app.core.security import TokenError, decode_access_token
from app.database import repository
from app.database.models import User
from app.database.session import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{get_settings().api_prefix}/auth/token")

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_app_settings(request: Request) -> Settings:
    """Settings bound to the running application (overridable in tests)."""
    return request.app.state.settings


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


SettingsDep = Annotated[Settings, Depends(get_app_settings)]
DbDep = Annotated[Session, Depends(get_db)]


def get_current_user(
    request: Request,
    token: Annotated[str, Depends(oauth2_scheme)],
    db: DbDep,
    settings: SettingsDep,
) -> User:
    """Validate the bearer token, revocation status, account state and role binding."""
    try:
        claims = decode_access_token(settings, token)
    except TokenError:
        raise _UNAUTHORIZED from None
    if repository.is_token_revoked(db, claims["jti"]):
        raise _UNAUTHORIZED
    user = repository.get_user_by_username(db, claims["sub"])
    if user is None or not user.is_active or user.role != claims["role"]:
        # Role changes or deactivation invalidate existing tokens immediately.
        raise _UNAUTHORIZED
    request.state.claims = claims
    request.state.user = user.username
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require(permission: str) -> Callable[..., User]:
    """Dependency factory enforcing a permission (deny by default)."""

    def dependency(user: CurrentUser) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    dependency.__name__ = f"require_{permission.replace(':', '_')}"
    return dependency
