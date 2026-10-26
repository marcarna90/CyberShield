"""User administration (admin only)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select

from app.api.deps import DbDep, client_ip, require
from app.api.schemas import UserCreate, UserOut, UserUpdate
from app.core.audit import record_event
from app.core.rbac import Perm, Role
from app.core.security import password_policy_violations
from app.database import repository
from app.database.models import User

router = APIRouter(prefix="/users", tags=["users"])
Admin = Annotated[User, Depends(require(Perm.USERS_MANAGE))]


@router.get("", response_model=list[UserOut])
def list_users(_: Admin, db: DbDep) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(request: Request, body: UserCreate, admin: Admin, db: DbDep) -> User:
    problems = password_policy_violations(body.password, body.username)
    if problems:
        raise HTTPException(status_code=422, detail="Password " + "; ".join(problems))
    if repository.get_user_by_username(db, body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = repository.create_user(
        db, username=body.username, email=body.email, password=body.password, role=body.role.value
    )
    record_event(
        db,
        actor=admin.username,
        action="user.create",
        resource=body.username,
        ip=client_ip(request),
        details={"role": body.role.value},
    )
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(request: Request, user_id: int, body: UserUpdate, admin: Admin, db: DbDep) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    demoting_admin = user.role == Role.ADMIN and (
        (body.role is not None and body.role != Role.ADMIN) or body.is_active is False
    )
    if demoting_admin:
        active_admins = db.scalar(
            select(func.count(User.id)).where(User.role == Role.ADMIN.value, User.is_active.is_(True))
        )
        if (active_admins or 0) <= 1:
            raise HTTPException(status_code=409, detail="Cannot remove the last active administrator")
    changes = body.model_dump(exclude_none=True, mode="json")
    for key, value in changes.items():
        setattr(user, key, value)
    db.commit()
    record_event(
        db, actor=admin.username, action="user.update", resource=user.username, ip=client_ip(request), details=changes
    )
    return user
