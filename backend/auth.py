"""User authentication and role-based access control for Ragnarok.

Stores users and sessions in a local SQLite database (same pattern as the
existing audit DB). No external dependencies -- password hashing and session
tokens use the standard library only.

Roles (least privilege):
    admin   -- full access: execute modules, manage users, re-index, everything
    analyst -- read/query/export/notify (no module execution, no index management)
    viewer  -- read/query/export only (no execute, no index, no notify)

Backward compatibility: the X-API-Key header (RAGNAROK_API_KEY) still works on
all protected endpoints for non-interactive scripts. When a Bearer session
token is present, it takes precedence and the API key is ignored.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import base64
from typing import Optional, Dict, Any, List

from fastapi import Header, HTTPException, status

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

AUTH_DB_PATH = os.getenv(
    "RAGNAROK_AUTH_DB_PATH",
    os.path.join(os.path.dirname(__file__), "ragnarok_auth.db"),
)

# Secret used to sign session tokens. Auto-generated if not set (printed once).
_AUTH_SECRET = os.environ.get("RAGNAROK_AUTH_SECRET")
if not _AUTH_SECRET:
    _AUTH_SECRET = secrets.token_urlsafe(48)
    print("=" * 70)
    print("[RAGNAROK] RAGNAROK_AUTH_SECRET not set -- generated a temporary secret.")
    print("[RAGNAROK] Set it in your environment to persist sessions across restarts.")
    print("=" * 70)

SESSION_TTL = int(os.environ.get("RAGNAROK_SESSION_TTL", str(8 * 3600)))  # 8h default

# ---------------------------------------------------------------------------
# At-rest field encryption (auth DB)
#
# Usernames are PII: the DB stores an HMAC-SHA256 lookup key (deterministic,
# enables login lookups without plaintext) plus a Fernet-encrypted copy for
# display. The Fernet key is derived from RAGNAROK_AUTH_SECRET, so setting
# that env var (recommended in production) also pins the encryption key.
# Password hashes stay PBKDF2-salted (already safe at rest).
# ---------------------------------------------------------------------------

try:
    from cryptography.fernet import Fernet as _Fernet, InvalidToken as _InvalidToken
    _FERNET = _Fernet(base64.urlsafe_b64encode(
        hashlib.sha256((_AUTH_SECRET + ":field-encryption").encode()).digest()
    ))
except ImportError:  # pragma: no cover - loud failure per project principles
    raise RuntimeError(
        "The 'cryptography' package is required for auth data encryption. "
        "Install it with: pip install cryptography"
    )


def _enc_field(value: str) -> str:
    return _FERNET.encrypt(value.encode()).decode()


def _dec_field(token: str) -> Optional[str]:
    try:
        return _FERNET.decrypt(token.encode()).decode()
    except _InvalidToken:
        return None


def _username_key(username: str) -> str:
    """Deterministic lookup key: HMAC-SHA256 of the lowercased username."""
    return hmac.new(_AUTH_SECRET.encode(), username.strip().lower().encode(), hashlib.sha256).hexdigest()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db() -> None:
    """Create users + sessions tables and a default admin if empty."""
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                domain TEXT,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_tokens (
                token TEXT PRIMARY KEY,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                created_by INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                tenant_id INTEGER NOT NULL DEFAULT 1,
                ip_address TEXT,
                os_type TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                last_heartbeat REAL NOT NULL,
                rules_json TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                username_enc TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                tenant_id INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                last_login REAL,
                is_active INTEGER NOT NULL DEFAULT 1,
                auth_provider TEXT NOT NULL DEFAULT 'local',
                oidc_sub TEXT UNIQUE
            );

            CREATE TABLE IF NOT EXISTS failed_logins (
                username TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_fail REAL NOT NULL,
                locked_until REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                is_valid INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            """
        )
        conn.commit()

        # Create default tenant if none exists
        default_tenant = conn.execute("SELECT id FROM tenants WHERE id = 1").fetchone()
        if not default_tenant:
            conn.execute(
                "INSERT OR IGNORE INTO tenants (id, name, domain, created_at) VALUES (1, 'default-tenant', 'local', ?)",
                (time.time(),)
            )
            conn.commit()

        # Migration: DBs created before field encryption lack username_enc or tenant_id
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "username_enc" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN username_enc TEXT")
            conn.commit()
        if "tenant_id" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1")
            conn.commit()
        if "auth_provider" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'")
            conn.commit()
        if "oidc_sub" not in cols:
            # SQLite's ALTER TABLE ADD COLUMN rejects inline UNIQUE/PRIMARY KEY
            # constraints, so the column is added plain and uniqueness is
            # enforced by a separate index below (matches what CREATE TABLE
            # already gives fresh databases via the inline UNIQUE above).
            conn.execute("ALTER TABLE users ADD COLUMN oidc_sub TEXT")
            conn.commit()
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_sub ON users(oidc_sub) WHERE oidc_sub IS NOT NULL")
        conn.commit()
        # Convert legacy plaintext usernames (username_enc IS NULL)
        legacy = conn.execute(
            "SELECT id, username FROM users WHERE username_enc IS NULL"
        ).fetchall()
        for row in legacy:
            conn.execute(
                "UPDATE users SET username = ?, username_enc = ? WHERE id = ?",
                (_username_key(row["username"]), _enc_field(row["username"]), row["id"]),
            )
        if legacy:
            conn.commit()

        # Default admin if no users exist
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        if row[0] == 0:
            pw = secrets.token_urlsafe(12)
            pw_hash = _hash_password(pw)
            conn.execute(
                "INSERT INTO users (username, username_enc, password_hash, role, tenant_id, created_at) VALUES (?, ?, ?, ?, 1, ?)",
                (_username_key("admin"), _enc_field("admin"), pw_hash, "admin", time.time()),
            )
            conn.commit()
            print("=" * 70)
            print("[RAGNAROK] No users found -- created default admin account:")
            print("[RAGNAROK]   username: admin")
            print(f"[RAGNAROK]   password: {pw}")
            print("[RAGNAROK] Change this password after first login!")
            print("=" * 70)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-SHA256, stdlib only)
# ---------------------------------------------------------------------------

_HASH_ITERATIONS = 260_000


def _hash_password(password: str) -> str:
    """Return 'salt:hexhash' for storage."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _HASH_ITERATIONS)
    return f"{salt}:{dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Constant-time check of password against a 'salt:hexhash' string."""
    try:
        salt, hexhash = stored.split(":", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _HASH_ITERATIONS)
    return hmac.compare_digest(dk.hex(), hexhash)


def check_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Return user dict if credentials are valid, else None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, username, username_enc, password_hash, role, is_active FROM users WHERE username = ?",
            (_username_key(username),),
        ).fetchone()
    finally:
        conn.close()
    if not row or not row["is_active"]:
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    display = _dec_field(row["username_enc"]) if row["username_enc"] else row["username"]
    return {"id": row["id"], "username": display, "role": row["role"]}


def update_last_login(user_id: int) -> None:
    conn = _connect()
    try:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user_id))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Brute-force protection (failed-login lockout)
# ---------------------------------------------------------------------------

LOGIN_MAX_ATTEMPTS = int(os.environ.get("RAGNAROK_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("RAGNAROK_LOCKOUT_SECONDS", str(5 * 60)))


def check_login_allowed(username: str) -> Dict[str, Any]:
    """
    Return {'allowed': bool, 'retry_after': int} for a username.
    A lockout expires when locked_until passes; the fail counter also resets
    if the last failure is older than the lockout window (idle decay).
    """
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT fail_count, last_fail, locked_until FROM failed_logins WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    now = time.time()
    if not row:
        return {"allowed": True, "retry_after": 0}
    if row["locked_until"] > now:
        return {"allowed": False, "retry_after": int(row["locked_until"] - now) + 1}
    # Counter decay: older than the lockout window → start fresh
    if now - row["last_fail"] > LOGIN_LOCKOUT_SECONDS:
        _clear_failed_logins(username)
    return {"allowed": True, "retry_after": 0}


def record_failed_login(username: str) -> int:
    """Count a failed attempt; lock the account when the threshold is hit."""
    conn = _connect()
    try:
        now = time.time()
        row = conn.execute(
            "SELECT fail_count, last_fail FROM failed_logins WHERE username = ?",
            (username,),
        ).fetchone()
        prev_count = 0
        if row and (now - row["last_fail"]) <= LOGIN_LOCKOUT_SECONDS:
            prev_count = row["fail_count"]
        fail_count = prev_count + 1
        locked_until = (now + LOGIN_LOCKOUT_SECONDS) if fail_count >= LOGIN_MAX_ATTEMPTS else 0
        conn.execute(
            """INSERT INTO failed_logins (username, fail_count, last_fail, locked_until)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                   fail_count = excluded.fail_count,
                   last_fail = excluded.last_fail,
                   locked_until = excluded.locked_until""",
            (username, fail_count, now, locked_until),
        )
        conn.commit()
        return fail_count
    finally:
        conn.close()


def _clear_failed_logins(username: str) -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM failed_logins WHERE username = ?", (username,))
        conn.commit()
    finally:
        conn.close()


def clear_failed_logins(username: str) -> None:
    """Reset the failed-attempt counter (call after a successful login)."""
    _clear_failed_logins(username)

# ---------------------------------------------------------------------------
# Session tokens (HMAC-signed, stdlib only)
# ---------------------------------------------------------------------------


def _sign(payload: bytes) -> str:
    sig = hmac.new(_AUTH_SECRET.encode(), payload, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(payload).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(sig).decode().rstrip("=")
    )


def _verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            return None
        payload_b64 = parts[0]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64)
        expected = _sign(payload)
        if not hmac.compare_digest(token, expected):
            return None
        return json.loads(payload)
    except Exception:
        return None


def create_session(user_id: int) -> str:
    payload = json.dumps({"uid": user_id, "sid": secrets.token_hex(16)}).encode()
    token = _sign(payload)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, now, now + SESSION_TTL),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    data = _verify_token(token)
    if not data:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, s.is_valid, u.username, u.username_enc, u.role, u.is_active "
            "FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = ?",
            (token_hash,),
        ).fetchone()
    finally:
        conn.close()
    if not row or not row["is_valid"] or not row["is_active"]:
        return None
    if row["expires_at"] < time.time():
        return None
    display = _dec_field(row["username_enc"]) if row["username_enc"] else row["username"]
    return {"id": row["user_id"], "username": display, "role": row["role"]}


def destroy_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = _connect()
    try:
        conn.execute("UPDATE sessions SET is_valid = 0 WHERE token_hash = ?", (token_hash,))
        conn.commit()
    finally:
        conn.close()


def list_users() -> List[Dict[str, Any]]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, username, username_enc, role, created_at, last_login, is_active FROM users ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["username"] = _dec_field(r["username_enc"]) if r["username_enc"] else r["username"]
        d.pop("username_enc", None)
        out.append(d)
    return out


def create_user(username: str, password: str, role: str = "viewer") -> Optional[int]:
    if role not in ("admin", "analyst", "viewer"):
        return None
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, username_enc, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (_username_key(username), _enc_field(username), _hash_password(password), role, time.time()),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def set_user_role(user_id: int, role: str) -> bool:
    if role not in ("admin", "analyst", "viewer"):
        return False
    conn = _connect()
    try:
        cur = conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def deactivate_user(user_id: int) -> bool:
    conn = _connect()
    try:
        cur = conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

# API key still accepted for scripts (backward compat)
RAGNAROK_API_KEY = os.getenv("RAGNAROK_API_KEY", "")


def require_role(*allowed_roles: str):
    """FastAPI dependency enforcing Bearer session token OR X-API-Key.

    Usage:
        @app.get("/foo")
        async def foo(user: dict = Depends(require_role("admin", "analyst"))):
            ...
    """
    allowed = set(allowed_roles)

    async def _checker(
        authorization: Optional[str] = Header(default=None),
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    ):
        # 1. Try Bearer session token first
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
            user = validate_session(token)
            if user and user["role"] in allowed:
                return user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session",
            )
        # 2. Fallback: API key (admin-level only, for scripts)
        if x_api_key and x_api_key == RAGNAROK_API_KEY and "admin" in allowed:
            return {"id": 0, "username": "api-key", "role": "admin"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid credentials",
        )

    return _checker


def update_user_credentials(
    user_id: int,
    new_username: Optional[str] = None,
    new_password: Optional[str] = None,
) -> bool:
    """
    Update a user's username and/or password (used by the setup wizard's
    'claim the default admin' flow). Returns False if the user does not
    exist or the new username is already taken.
    """
    if not new_username and not new_password:
        return False
    conn = _connect()
    try:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return False
        if new_username:
            clash = conn.execute(
                "SELECT id FROM users WHERE username = ? AND id != ?",
                (_username_key(new_username), user_id),
            ).fetchone()
            if clash:
                return False
            conn.execute(
                "UPDATE users SET username = ?, username_enc = ? WHERE id = ?",
                (_username_key(new_username), _enc_field(new_username), user_id),
            )
        if new_password:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (_hash_password(new_password), user_id),
            )
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Multi-Tenant & Agent Management Helpers
# ---------------------------------------------------------------------------

def create_tenant(name: str, domain: Optional[str] = None) -> Optional[int]:
    """Create a new tenant organization for multi-tenancy isolation."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO tenants (name, domain, created_at) VALUES (?, ?, ?)",
            (name.strip(), domain.strip() if domain else None, time.time()),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def list_tenants() -> List[Dict[str, Any]]:
    """List all registered tenant organizations."""
    conn = _connect()
    try:
        rows = conn.execute("SELECT id, name, domain, created_at FROM tenants ORDER BY id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_agent_token(tenant_id: int = 1, expires_in_seconds: int = 86400, created_by: int = 1) -> str:
    """Generate a one-time/temporary enrollment token for registering new Heimdall agents."""
    token = "agt_" + secrets.token_urlsafe(32)
    now = time.time()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO agent_tokens (token, tenant_id, created_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?)",
            (token, tenant_id, now, now + expires_in_seconds, created_by),
        )
        conn.commit()
        return token
    finally:
        conn.close()


def register_agent(token: str, agent_id: str, name: str, ip_address: str, os_type: str) -> Optional[Dict[str, Any]]:
    """Register a new agent using a valid enrollment token."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT token, tenant_id, expires_at FROM agent_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if not row or row["expires_at"] < time.time():
            return None
        
        tenant_id = row["tenant_id"]
        now = time.time()
        conn.execute(
            """INSERT INTO agents (agent_id, name, tenant_id, ip_address, os_type, status, last_heartbeat, created_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
               ON CONFLICT(agent_id) DO UPDATE SET
                   name = excluded.name,
                   ip_address = excluded.ip_address,
                   os_type = excluded.os_type,
                   status = 'active',
                   last_heartbeat = excluded.last_heartbeat""",
            (agent_id, name, tenant_id, ip_address, os_type, now, now),
        )
        # Consume token after successful use
        conn.execute("DELETE FROM agent_tokens WHERE token = ?", (token,))
        conn.commit()
        return {"agent_id": agent_id, "tenant_id": tenant_id, "status": "active"}
    finally:
        conn.close()


def agent_heartbeat(agent_id: str, status_str: str = "active", rules_json: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Process heartbeat from an agent and return its assigned configuration."""
    conn = _connect()
    try:
        now = time.time()
        row = conn.execute("SELECT agent_id, tenant_id, rules_json FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not row:
            return None
        
        updates = ["status = ?", "last_heartbeat = ?"]
        params = [status_str, now]
        if rules_json:
            updates.append("rules_json = ?")
            params.append(rules_json)
        params.append(agent_id)

        conn.execute(f"UPDATE agents SET {', '.join(updates)} WHERE agent_id = ?", params)
        conn.commit()
        return {"agent_id": agent_id, "tenant_id": row["tenant_id"], "rules_json": row["rules_json"]}
    finally:
        conn.close()


def list_agents(tenant_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """List registered agents, optionally filtered by tenant."""
    conn = _connect()
    try:
        if tenant_id:
            rows = conn.execute(
                "SELECT agent_id, name, tenant_id, ip_address, os_type, status, last_heartbeat, created_at FROM agents WHERE tenant_id = ? ORDER BY last_heartbeat DESC",
                (tenant_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT agent_id, name, tenant_id, ip_address, os_type, status, last_heartbeat, created_at FROM agents ORDER BY last_heartbeat DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# OIDC / Single Sign-On (SSO) Support
#
# Standard confidential-client authorization code flow: the login URL sends
# the browser to the IdP; the IdP redirects back with a one-time `code`;
# exchange_oidc_code() swaps that code for an id_token at the IdP's token
# endpoint and cryptographically verifies its signature against the IdP's
# published JWKS before trusting any claim in it (name/email/subject).
# Endpoints are discovered from the IdP's own
# /.well-known/openid-configuration document (OIDC Discovery, RFC 8414-ish)
# instead of guessed per-provider, so this works against any spec-compliant
# IdP (Azure AD/Entra ID, Okta, Keycloak, Auth0, ...) without special-casing.
# ---------------------------------------------------------------------------

import requests as _requests
import jwt as _jwt
from jwt import PyJWKClient as _PyJWKClient

OIDC_ISSUER = os.environ.get("ASGARD_OIDC_ISSUER", "")
OIDC_CLIENT_ID = os.environ.get("ASGARD_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("ASGARD_OIDC_CLIENT_SECRET", "")


class OIDCError(Exception):
    """Raised for any OIDC discovery/exchange/verification failure. The
    message is safe to show to an admin configuring SSO, but callers should
    not leak it to an unauthenticated caller beyond a generic 400."""


def is_oidc_enabled() -> bool:
    return bool(OIDC_ISSUER and OIDC_CLIENT_ID)


# Cache of {issuer: discovery_document}. The discovery document is static
# for the lifetime of an IdP deployment, so process-lifetime caching avoids
# an extra network round trip on every login without any real staleness risk.
_oidc_discovery_cache: Dict[str, Dict[str, Any]] = {}
_jwks_client_cache: Dict[str, Any] = {}


def _discover_oidc_config(issuer: Optional[str] = None) -> Dict[str, Any]:
    issuer = (issuer or OIDC_ISSUER).rstrip("/")
    if issuer in _oidc_discovery_cache:
        return _oidc_discovery_cache[issuer]
    try:
        resp = _requests.get(f"{issuer}/.well-known/openid-configuration", timeout=8)
        resp.raise_for_status()
        config = resp.json()
    except Exception as exc:
        raise OIDCError(
            f"Impossibile scaricare la configurazione OIDC da {issuer}: {exc}"
        ) from exc

    for required in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if required not in config:
            raise OIDCError(
                f"Documento di discovery OIDC di {issuer} incompleto: manca '{required}'"
            )
    _oidc_discovery_cache[issuer] = config
    return config


def generate_oidc_login_url(redirect_uri: str, state: str) -> str:
    """Generate the OIDC authorization URL the browser should be sent to."""
    config = _discover_oidc_config()
    params = {
        "client_id": OIDC_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
    }
    from urllib.parse import urlencode
    return f"{config['authorization_endpoint']}?{urlencode(params)}"


def exchange_oidc_code(code: str, redirect_uri: str) -> Dict[str, Any]:
    """
    Exchange an authorization `code` for a verified identity.

    Performs the full confidential-client flow: POSTs to the IdP's token
    endpoint, then verifies the returned id_token's RS256 signature against
    the IdP's live JWKS (fetched/cached via PyJWKClient) and validates
    issuer/audience/expiry before returning any claim. Never trusts an
    unverified token. Raises OIDCError on any failure (network, bad
    credentials, invalid/expired/mis-issued token).
    """
    if not OIDC_CLIENT_SECRET:
        raise OIDCError(
            "ASGARD_OIDC_CLIENT_SECRET non configurato: richiesto per lo scambio "
            "del codice con un client confidenziale (standard per un'app server-side)."
        )

    config = _discover_oidc_config()

    try:
        token_resp = _requests.post(
            config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
    except Exception as exc:
        raise OIDCError(f"Errore di rete nello scambio del codice OIDC: {exc}") from exc

    if token_resp.status_code != 200:
        raise OIDCError(
            f"L'IdP ha rifiutato lo scambio del codice (HTTP {token_resp.status_code}): "
            f"{token_resp.text[:300]}"
        )

    token_data = token_resp.json()
    id_token = token_data.get("id_token")
    if not id_token:
        raise OIDCError("La risposta dell'IdP non contiene un id_token.")

    jwks_uri = config["jwks_uri"]
    if jwks_uri not in _jwks_client_cache:
        _jwks_client_cache[jwks_uri] = _PyJWKClient(jwks_uri)
    jwks_client = _jwks_client_cache[jwks_uri]

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = _jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=OIDC_CLIENT_ID,
            issuer=config["issuer"],
            options={"require": ["exp", "iat", "sub"]},
        )
    except _jwt.PyJWTError as exc:
        raise OIDCError(f"id_token non valido o firma non verificabile: {exc}") from exc

    return claims


def find_or_create_oidc_user(claims: Dict[str, Any], tenant_id: int = 1) -> Dict[str, Any]:
    """
    Map a verified OIDC identity to a local user row, creating it on first
    login. Looked up by the token's `sub` claim (stable per-IdP identifier
    per the OIDC spec), never by email/username alone, since those can
    change at the IdP. New SSO users are provisioned with the least-
    privileged role ('viewer'); an admin must explicitly promote them -
    SSO authenticates identity, it does not grant authorization.
    """
    sub = claims.get("sub")
    if not sub:
        raise OIDCError("id_token privo del claim 'sub' obbligatorio.")

    display_name = claims.get("preferred_username") or claims.get("email") or claims.get("name") or sub

    conn = _connect()
    try:
        row = conn.execute("SELECT id FROM users WHERE oidc_sub = ?", (sub,)).fetchone()
        if row:
            user_id = row["id"]
        else:
            now = time.time()
            cur = conn.execute(
                """INSERT INTO users
                   (username, username_enc, password_hash, role, tenant_id, created_at,
                    is_active, auth_provider, oidc_sub)
                   VALUES (?, ?, ?, 'viewer', ?, ?, 1, 'oidc', ?)""",
                (
                    _username_key(f"oidc:{sub}"),
                    _enc_field(display_name),
                    # SSO users never authenticate with a local password; store
                    # an unusable hash so check_user() can never match it.
                    _hash_password(secrets.token_urlsafe(32)),
                    tenant_id,
                    now,
                    sub,
                ),
            )
            conn.commit()
            user_id = cur.lastrowid

        row = conn.execute(
            "SELECT id, username_enc, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()

    display = _dec_field(row["username_enc"]) if row["username_enc"] else row["username"]
    return {"id": row["id"], "username": display, "role": row["role"]}


# Convenience: any authenticated user (regardless of role)
require_auth = require_role("admin", "analyst", "viewer")


# Initialize the auth database on module import (creates tables + default admin)
init_auth_db()



