"""Auth & user management endpoints (RBAC) — moved out of server.py.

Routes are mounted without prefix (full paths below) via
app.include_router (see server.py). Handlers are verbatim copies of the
originals: same paths, models, auth and payloads.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from auth import (
    require_auth,
    require_role,
    check_user,
    check_login_allowed,
    record_failed_login,
    clear_failed_logins,
    create_session,
    destroy_session,
    update_last_login,
    list_users,
    create_user,
    set_user_role,
    deactivate_user,
)

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class SetRoleRequest(BaseModel):
    role: str


@router.post("/api/v1/auth/login")
async def auth_login(req: LoginRequest):
    """Authenticate and return a Bearer session token.

    Brute-force protection: after LOGIN_MAX_ATTEMPTS failed attempts the
    account is locked for LOGIN_LOCKOUT_SECONDS (HTTP 429 with retry_after).
    """
    lock = check_login_allowed(req.username)
    if not lock["allowed"]:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "account_locked",
                "message": "Too many failed login attempts. Try again later.",
                "retry_after_seconds": lock["retry_after"],
            },
        )
    user = check_user(req.username, req.password)
    if not user:
        record_failed_login(req.username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    clear_failed_logins(req.username)
    update_last_login(user["id"])
    token = create_session(user["id"])
    return {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}


@router.post("/api/v1/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(default=None)):
    """Invalidate the current session token."""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        destroy_session(token)
    return {"status": "ok"}


@router.get("/api/v1/auth/me")
async def auth_me(user: dict = Depends(require_auth)):
    """Return the currently authenticated user."""
    return {"user": user}


@router.get("/api/v1/auth/users")
async def auth_list_users(user: dict = Depends(require_role("admin"))):
    """List all users (admin only)."""
    return {"users": list_users()}


@router.post("/api/v1/auth/users")
async def auth_create_user(req: CreateUserRequest, user: dict = Depends(require_role("admin"))):
    """Create a new user (admin only)."""
    uid = create_user(req.username, req.password, req.role)
    if uid is None:
        raise HTTPException(status_code=400, detail="Username taken or invalid role")
    return {"id": uid, "username": req.username, "role": req.role}


@router.patch("/api/v1/auth/users/{user_id}/role")
async def auth_set_role(user_id: int, req: SetRoleRequest, user: dict = Depends(require_role("admin"))):
    """Change a user's role (admin only)."""
    if not set_user_role(user_id, req.role):
        raise HTTPException(status_code=404, detail="User not found or invalid role")
    return {"status": "ok", "user_id": user_id, "role": req.role}


@router.delete("/api/v1/auth/users/{user_id}")
async def auth_deactivate_user(user_id: int, user: dict = Depends(require_role("admin"))):
    """Deactivate a user (admin only)."""
    if not deactivate_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "ok", "user_id": user_id}
