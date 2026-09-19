"""Auth & user management endpoints (RBAC) — moved out of server.py.

Routes are mounted without prefix (full paths below) via
app.include_router (see server.py). Handlers are verbatim copies of the
originals: same paths, models, auth and payloads.
"""
import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import RedirectResponse
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
    update_user_credentials,
    SESSION_TTL,
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


# ======================================================================
# Auth Setup Wizard — "claim the default admin" flow
#
# On first start the auth module creates a default `admin` with a random
# password printed to the server console. The wizard asks for that console
# password plus the new permanent credentials, and swaps them in place.
# ======================================================================

@router.get("/api/v1/auth/setup")
async def auth_setup_status():
    """
    Setup wizard status. No authentication required.
    `bootstrap_available` is True while the default admin still has its
    console-generated password (i.e. nobody has claimed it yet).
    """
    users = list_users()
    default_admin = next((u for u in users if u["username"] == "admin"), None)
    return {
        "configured": len(users) > 0,
        "user_count": len(users),
        "bootstrap_available": default_admin is not None,
        "auth_secret_set": bool(os.environ.get("RAGNAROK_AUTH_SECRET")),
        "session_ttl": SESSION_TTL,
    }


class SetupAdminRequest(BaseModel):
    console_password: str  # the random password printed at first startup
    new_username: str
    new_password: str


@router.post("/api/v1/auth/setup/admin")
async def auth_setup_claim_admin(req: SetupAdminRequest):
    """
    Claim the default admin account: verify the one-time console password,
    then replace username and password with the permanent credentials.
    Requires: console_password (from server startup log), new_username,
    new_password (min 8 chars). Works only while the default admin exists
    unclaimed; 409 once claimed.
    """
    users = list_users()
    default_admin = next((u for u in users if u["username"] == "admin"), None)
    if default_admin is None:
        raise HTTPException(
            status_code=409,
            detail="Default admin already claimed or missing. Use /api/v1/auth/login.",
        )

    if not req.new_username or not req.new_password:
        raise HTTPException(status_code=400, detail="new_username and new_password are required")

    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # Verify the console password against the default admin account
    if not check_user("admin", req.console_password):
        raise HTTPException(status_code=401, detail="Console password does not match the default admin")

    ok = update_user_credentials(
        default_admin["id"],
        new_username=req.new_username,
        new_password=req.new_password,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to update admin credentials")

    # Auto-login: fresh session for the renamed admin
    token = create_session(default_admin["id"])
    update_last_login(default_admin["id"])

    return {
        "status": "admin_claimed",
        "user": {"id": default_admin["id"], "username": req.new_username, "role": "admin"},
        "token": token,
        "message": "Admin claimed successfully. Store this token securely — it is your session.",
    }


# ======================================================================
# OIDC SSO endpoints
# ======================================================================

@router.get("/api/v1/auth/oidc/config")
def oidc_config():
    from auth import is_oidc_enabled, OIDC_ISSUER
    return {"enabled": is_oidc_enabled(), "issuer": OIDC_ISSUER}


@router.get("/api/v1/auth/oidc/login")
def oidc_login(redirect_uri: str, state: str = "state"):
    from auth import is_oidc_enabled, generate_oidc_login_url, OIDCError
    if not is_oidc_enabled():
        raise HTTPException(status_code=400, detail="OIDC is not enabled on this server")
    try:
        return RedirectResponse(url=generate_oidc_login_url(redirect_uri, state))
    except OIDCError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get("/api/v1/auth/oidc/callback")
def oidc_callback(code: str, redirect_uri: str, state: str = "state"):
    """
    Completes the OIDC login: exchanges the authorization `code` for a
    verified identity (signature-checked against the IdP's JWKS), maps it
    to a local user (auto-provisioned as 'viewer' on first login), and
    returns a Ragnarök Bearer session token in the same shape as
    /api/v1/auth/login. `redirect_uri` must match exactly what was sent
    to /api/v1/auth/oidc/login, per the OAuth2 spec.
    """
    from auth import is_oidc_enabled, exchange_oidc_code, find_or_create_oidc_user, create_session, update_last_login, OIDCError
    if not is_oidc_enabled():
        raise HTTPException(status_code=400, detail="OIDC is not enabled on this server")
    try:
        claims = exchange_oidc_code(code, redirect_uri)
        user = find_or_create_oidc_user(claims)
    except OIDCError as exc:
        raise HTTPException(status_code=401, detail=f"OIDC login failed: {exc}")

    update_last_login(user["id"])
    token = create_session(user["id"])
    return {"token": token, "user": user}
