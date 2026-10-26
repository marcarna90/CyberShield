"""Authentication: login (OAuth2 password flow), logout (token revocation), profile, password change."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser, DbDep, SettingsDep, client_ip
from app.api.schemas import MeOut, PasswordChange, TokenResponse
from app.core.audit import record_event
from app.core.models import utcnow
from app.core.rbac import permissions_for
from app.core.security import (
    create_access_token,
    hash_password,
    password_needs_rehash,
    password_policy_violations,
    verify_password,
)
from app.database import repository

router = APIRouter(prefix="/auth", tags=["auth"])

# Verified against when the user does not exist, so response time does not
# reveal whether a username is valid (ASVS 2.2.x / user enumeration).
_DUMMY_HASH = hash_password("cybershield-timing-equaliser")
_INVALID = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


@router.post("/token", response_model=TokenResponse, summary="Obtain an access token")
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbDep,
    settings: SettingsDep,
) -> TokenResponse:
    username = form.username[:64]
    user = repository.get_user_by_username(db, username)
    ip = client_ip(request)
    now = utcnow()
    if user is not None and user.locked_until is not None and user.locked_until > now:
        verify_password(form.password, _DUMMY_HASH)
        record_event(db, actor=username, action="auth.login", outcome="locked", ip=ip)
        raise _INVALID
    valid = verify_password(form.password, user.hashed_password if user else _DUMMY_HASH)
    if user is None or not valid or not user.is_active:
        if user is not None and not valid:
            user.failed_attempts += 1
            if user.failed_attempts >= settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_attempts = 0
            db.commit()
        record_event(db, actor=username, action="auth.login", outcome="failure", ip=ip)
        raise _INVALID
    if password_needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(form.password)
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()
    token, expires_at, _ = create_access_token(settings, user.username, user.role)
    record_event(db, actor=user.username, action="auth.login", ip=ip)
    return TokenResponse(access_token=token, expires_in=int((expires_at - now).total_seconds()), role=user.role)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke the current token")
def logout(request: Request, user: CurrentUser, db: DbDep) -> Response:
    claims = request.state.claims
    repository.revoke_token(db, claims["jti"], expires_at=utcnow() + timedelta(days=1))
    record_event(db, actor=user.username, action="auth.logout", ip=client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeOut, summary="Current user and permissions")
def me(user: CurrentUser) -> MeOut:
    return MeOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login=user.last_login,
        permissions=permissions_for(user.role),
    )


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT, summary="Change own password")
def change_password(request: Request, body: PasswordChange, user: CurrentUser, db: DbDep) -> Response:
    if not verify_password(body.current_password, user.hashed_password):
        record_event(db, actor=user.username, action="auth.change_password", outcome="failure", ip=client_ip(request))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    problems = password_policy_violations(body.new_password, user.username)
    if problems:
        raise HTTPException(status_code=422, detail="Password " + "; ".join(problems))
    user.hashed_password = hash_password(body.new_password)
    db.commit()
    repository.revoke_token(db, request.state.claims["jti"], expires_at=utcnow() + timedelta(days=1))
    record_event(db, actor=user.username, action="auth.change_password", ip=client_ip(request))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
