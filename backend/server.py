import sys
import os
import secrets
import subprocess
import sqlite3
import json
import glob
import time
import re
import asyncio
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

# --- User authentication & RBAC (zero new deps, stdlib only) ---
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
    init_auth_db,
    SESSION_TTL,
)

# --- Asgard RAG Engine (Retrieval-Augmented Generation) ---
RAG_AVAILABLE = False
rag_retriever = None
rag_memory = None
rag_indexer = None
rag_insights = None
rag_timeline = None
rag_agents = None

try:
    from rag.retriever import AsgardRetriever
    from rag.memory import ConversationMemory
    from rag.indexer import AsgardIndexer
    from rag.insights import InsightsEngine
    from rag.timeline import TimelineEngine
    from rag.agents import AgentRouter
    rag_retriever = AsgardRetriever()
    rag_memory = ConversationMemory()
    rag_indexer = AsgardIndexer()
    rag_insights = InsightsEngine()
    rag_timeline = TimelineEngine()
    rag_agents = AgentRouter(retriever=rag_retriever)
    RAG_AVAILABLE = True
    print("[RAGNAROK] RAG Engine attivo — ChromaDB + FastEmbed + Insights")
except ImportError as e:
    print(f"[RAGNAROK] RAG Engine non disponibile (dipendenze mancanti: {e})")
except Exception as e:
    print(f"[RAGNAROK] RAG Engine non inizializzato: {e}")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# --- Setup wizard: load previously saved integration keys, if any ---
# These are the env vars that the modules Ragnarok launches (as subprocesses,
# which inherit the parent process environment) already know how to read.
# Loading them here, before anything else, means a value saved by the setup
# wizard on a previous run is honored on every subsequent start without the
# user ever having to open a config.yaml or .env file by hand.
SETUP_ENV_PATH = os.getenv(
    "RAGNAROK_SETUP_ENV_PATH",
    os.path.join(os.path.dirname(__file__), "asgard_setup.env"),
)


def _load_setup_env(path: str) -> None:
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key and value and key not in os.environ:
                    os.environ[key] = value
    except OSError as e:
        print(f"[RAGNAROK] Could not read setup config at {path}: {e}")


_load_setup_env(SETUP_ENV_PATH)

app = FastAPI(title="Asgard Enterprise SOC Orchestrator", version="6.0.0")

# CORS: restricted to the local origins the Ragnarok desktop shell is expected
# to run from during development. Using "*" together with allow_credentials
# would let ANY web page open in the user's browser call this local API (which
# can execute scans/audits on the host) — Starlette actually rejects that
# combination outright, but even a permissive explicit wildcard would be a
# real risk here, so we enumerate the known-good origins instead.
# - http://localhost:1420 / http://127.0.0.1:1420: default Vite/Tauri dev server port
# - tauri://localhost: origin used by the built Tauri webview on Windows/Linux
# - https://tauri.localhost: origin used by the built Tauri webview on some platforms
# Add any additional dev origins here explicitly if the frontend is served elsewhere.
ALLOWED_ORIGINS = [
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "tauri://localhost",
    "https://tauri.localhost",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Minimal API key protection for action-executing endpoints ---
# Endpoints that trigger module execution (subprocess launches, network scans,
# AD audits, etc.) require an X-API-Key header matching RAGNAROK_API_KEY.
# Status/health/report-reading endpoints stay open since they only expose
# read-only local state.
RAGNAROK_API_KEY = os.getenv("RAGNAROK_API_KEY", "")
if not RAGNAROK_API_KEY:
    RAGNAROK_API_KEY = secrets.token_urlsafe(32)
    print("=" * 70)
    print("[RAGNAROK] RAGNAROK_API_KEY not set — generated a temporary key:")
    print(f"[RAGNAROK]   {RAGNAROK_API_KEY}")
    print("[RAGNAROK] Set RAGNAROK_API_KEY in your environment to persist it.")
    print("=" * 70)


# --- Setup wizard fields ---
# Maps a friendly field name (used in the wizard UI and API payload) to the

# ======================================================================
# Auth & User Management Endpoints (RBAC)
# ======================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class SetRoleRequest(BaseModel):
    role: str


@app.post("/api/v1/auth/login")
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


@app.post("/api/v1/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(default=None)):
    """Invalidate the current session token."""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        destroy_session(token)
    return {"status": "ok"}


@app.get("/api/v1/auth/me")
async def auth_me(user: dict = Depends(require_auth)):
    """Return the currently authenticated user."""
    return {"user": user}


@app.get("/api/v1/auth/users")
async def auth_list_users(user: dict = Depends(require_role("admin"))):
    """List all users (admin only)."""
    return {"users": list_users()}


@app.post("/api/v1/auth/users")
async def auth_create_user(req: CreateUserRequest, user: dict = Depends(require_role("admin"))):
    """Create a new user (admin only)."""
    uid = create_user(req.username, req.password, req.role)
    if uid is None:
        raise HTTPException(status_code=400, detail="Username taken or invalid role")
    return {"id": uid, "username": req.username, "role": req.role}


@app.patch("/api/v1/auth/users/{user_id}/role")
async def auth_set_role(user_id: int, req: SetRoleRequest, user: dict = Depends(require_role("admin"))):
    """Change a user's role (admin only)."""
    if not set_user_role(user_id, req.role):
        raise HTTPException(status_code=404, detail="User not found or invalid role")
    return {"status": "ok", "user_id": user_id, "role": req.role}


@app.delete("/api/v1/auth/users/{user_id}")
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

@app.get("/api/v1/auth/setup")
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


@app.post("/api/v1/auth/setup/admin")
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
# Asgard RAG API Endpoints
# ======================================================================

class RAGIndexResponse(BaseModel):
    status: str
    results: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class RAGQueryRequest(BaseModel):
    query: str
    n_results: int = 5
    sources: Optional[List[str]] = None
    session_id: Optional[str] = None


class RAGQueryResponse(BaseModel):
    status: str
    context: str
    results: List[Dict[str, Any]]
    answer: Optional[str] = None


@app.post("/api/v1/rag/index", response_model=RAGIndexResponse)
async def rag_index_data(user: dict = Depends(require_role("admin"))):
    """Forza re-indicizzazione di tutti i dati Asgard."""
    if not RAG_AVAILABLE or rag_indexer is None:
        raise HTTPException(503, "RAG Engine non disponibile")
    try:
        results = rag_indexer.index_all()
        return RAGIndexResponse(status="success", results=results)
    except Exception as e:
        return RAGIndexResponse(status="error", error=str(e))


@app.get("/api/v1/rag/stats")
async def rag_stats():
    """Statistiche dell'indice RAG + Security Score."""
    if not RAG_AVAILABLE:
        return {"available": False, "rag_available": False, "collections": {}}
    try:
        stats = rag_indexer.get_stats()
        score = _compute_security_score(stats)
        return {
            "available": True,
            "rag_available": True,
            "collections": stats,
            "security_score": score,
        }
    except Exception as e:
        return {"available": False, "rag_available": False, "error": str(e)}


def _compute_security_score(collections: Dict[str, int]) -> Dict[str, Any]:
    """Score determinaristico 0-10 basato su indicatori oggettivi (nessun LLM)."""
    alerts = collections.get("heimdall_alerts", 0)
    ioc = collections.get("fenrir_ioc", 0)
    triage = collections.get("mjolnir_triage", 0)
    scans = collections.get("bifrost_scans", 0)
    compliance = collections.get("forseti_compliance", 0)
    playbooks = collections.get("sleipnir_playbooks", 0)
    score = 0
    score += 2 if alerts > 0 else 0
    score += 2 if ioc > 0 else 0
    score += 2 if compliance > 0 else 0
    score += 2 if scans > 0 else 0
    score += 1 if playbooks > 0 else 0
    score += 1 if RAG_AVAILABLE else 0
    score = min(score, 10)
    if score >= 8:
        level = "high"
        label = "Protezione elevata"
    elif score >= 5:
        level = "medium"
        label = "Protezione media"
    else:
        level = "low"
        label = "Protezione bassa"
    return {
        "score": score,
        "label": label,
        "level": level,
        "coverage": {
            "hids": alerts > 0,
            "threat_intel": ioc > 0,
            "compliance": compliance > 0,
            "scan": scans > 0,
            "soar": playbooks > 0,
            "rag": RAG_AVAILABLE,
        },
    }


@app.post("/api/v1/rag/query", response_model=RAGQueryResponse)
async def rag_query(req: RAGQueryRequest, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Query semantica sui dati Asgard indicizzati."""
    if not RAG_AVAILABLE or rag_retriever is None:
        raise HTTPException(503, "RAG Engine non disponibile")

    try:
        # Esegui ricerca semantica
        results = rag_retriever.search(
            query=req.query,
            n_results=req.n_results,
            sources=req.sources,
        )

        # Formatta contesto per LLM
        context = rag_retriever.format_for_llm(results)

        # Salva nella memoria conversazionale
        if req.session_id and rag_memory:
            rag_memory.add(req.session_id, "user", req.query)
            rag_memory.add(
                req.session_id, "system",
                f"[RAG context: {len(results)} results found]"
            )

        return RAGQueryResponse(
            status="success",
            context=context,
            results=results,
        )
    except Exception as e:
        raise HTTPException(500, f"RAG query failed: {e}")


@app.get("/api/v1/rag/sessions")
async def rag_sessions():
    """Lista sessioni conversazionali attive."""
    if not RAG_AVAILABLE or rag_memory is None:
        return {"sessions": []}
    try:
        sessions = rag_memory.get_all_sessions()
        return {"sessions": sessions}
    except Exception as e:
        return {"sessions": [], "error": str(e)}

# environment variable each downstream module actually reads. Every entry
# here corresponds to an env var a module genuinely consults today - this
# list is deliberately not padded with fields nothing reads yet.
SETUP_FIELDS: Dict[str, Dict[str, str]] = {
    "virustotal_api_key": {"env": "VT_API_KEY", "label": "Chiave API VirusTotal", "used_by": "Mjolnir"},
    "otx_api_key": {"env": "OTX_API_KEY", "label": "Chiave API AlienVault OTX", "used_by": "Fenrir"},
    "telegram_bot_token": {"env": "TELEGRAM_BOT_TOKEN", "label": "Token Bot Telegram", "used_by": "Heimdall"},
    "telegram_chat_id": {"env": "TELEGRAM_CHAT_ID", "label": "Chat ID Telegram", "used_by": "Heimdall"},
    "gjallarhorn_hub_url": {"env": "GJALLARHORN_HUB_URL", "label": "URL Hub Gjallarhorn", "used_by": "Heimdall, Sleipnir"},
    "gjallarhorn_api_key": {"env": "GJALLARHORN_API_KEY", "label": "Chiave API Gjallarhorn", "used_by": "Heimdall, Sleipnir"},
}


class SetupRequest(BaseModel):
    values: Dict[str, str]


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


@app.get("/api/v1/setup")
def get_setup_status(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Reports which integrations are configured, without ever returning the
    actual secret values back to the frontend."""
    fields = {}
    for field, meta in SETUP_FIELDS.items():
        raw = os.environ.get(meta["env"], "")
        fields[field] = {
            "label": meta["label"],
            "used_by": meta["used_by"],
            "configured": bool(raw),
            "preview": _mask(raw) if raw else None,
        }
    return {"fields": fields}


@app.post("/api/v1/setup")
def save_setup(req: SetupRequest, user: dict = Depends(require_role("admin"))):
    """Persists integration keys as env vars for this process (so the next
    module Ragnarok launches immediately picks them up) and writes them to
    a local file so they survive a restart. Unknown field names are ignored
    rather than silently accepted, so a typo in the frontend fails loudly."""
    unknown = [f for f in req.values if f not in SETUP_FIELDS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown setup field(s): {', '.join(unknown)}")

    updated = []
    for field, value in req.values.items():
        env_name = SETUP_FIELDS[field]["env"]
        value = value.strip()
        if not value:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = value
        updated.append(env_name)

    try:
        with open(SETUP_ENV_PATH, "w", encoding="utf-8") as f:
            f.write("# Written by the Ragnarok setup wizard. Do not commit this file.\n")
            for field, meta in SETUP_FIELDS.items():
                current = os.environ.get(meta["env"], "")
                if current:
                    f.write(f"{meta['env']}={current}\n")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Saved in memory but failed to persist to disk: {e}")

    return {"status": "saved", "updated_fields": updated}

# Auto-detect ASGARD_ROOT relative to backend directory or fallback to environment variable
DEFAULT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ASGARD_ROOT = os.getenv("ASGARD_ROOT", DEFAULT_ROOT)
FRONTEND_DIR = os.path.join(ASGARD_ROOT, "Ragnarok", "frontend")

START_TIME = time.time()

# --- Persistent audit log (SQLite) ---
# The in-memory event_log on TelemetryBroadcaster is capped at 200 entries and
# lost on restart. Every event that is broadcast is now also written to this
# SQLite database so the audit trail survives process restarts and can be
# paginated via GET /api/v1/audit-log.
AUDIT_DB_PATH = os.getenv(
    "RAGNAROK_AUDIT_DB_PATH",
    os.path.join(os.path.dirname(__file__), "ragnarok_audit.db"),
)


def init_audit_db() -> None:
    conn = sqlite3.connect(AUDIT_DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                type TEXT NOT NULL,
                payload TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


init_audit_db()


def record_audit_event(event: Dict[str, Any]) -> None:
    """Persist an event to the audit SQLite DB. Never raises: a DB hiccup
    should not take down telemetry broadcasting."""
    try:
        conn = sqlite3.connect(AUDIT_DB_PATH)
        try:
            conn.execute(
                "INSERT INTO events (timestamp, type, payload) VALUES (?, ?, ?)",
                (event.get("ts", time.time()), event.get("type", "unknown"), json.dumps(event)),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        print(f"[RAGNAROK] Failed to persist audit event: {e}")

MODULE_STATUS: Dict[str, Dict[str, Any]] = {
    "heimdall": {"name": "Heimdall HIDS", "path": "Heimdall", "entry": "run_local_demo.py", "healthy": False, "last_check": 0},
    "mjolnir": {"name": "Mjolnir Triage", "path": "Mjolnir", "entry": "main.py", "healthy": False, "last_check": 0},
    "bifrost": {"name": "Bifrost Network", "path": "Bifrost", "entry": "main.py", "healthy": False, "last_check": 0},
    "yggdrasil": {"name": "Yggdrasil AD", "path": "Yggdrasil", "entry": "main.py", "healthy": False, "last_check": 0},
    "fenrir": {"name": "Fenrir CTI", "path": "Fenrir", "entry": "main.py", "healthy": False, "last_check": 0},
    "sleipnir": {"name": "Sleipnir SOAR", "path": "Sleipnir", "entry": "main.py", "healthy": False, "last_check": 0},
}

EXEC_COUNTER: Dict[str, int] = {k: 0 for k in MODULE_STATUS}

class TelemetryBroadcaster:
    def __init__(self):
        self.connections: List[WebSocket] = []
        self.event_log: List[Dict[str, Any]] = []
        self._max_log = 200

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        for evt in self.event_log[-50:]:
            await ws.send_json(evt)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, event: Dict[str, Any]):
        self.event_log.append(event)
        if len(self.event_log) > self._max_log:
            self.event_log = self.event_log[-self._max_log:]
        record_audit_event(event)
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

telemetry = TelemetryBroadcaster()

class OllamaStatus(BaseModel):
    available: bool
    models: List[str] = []
    url: str = "http://localhost:11434"

@app.get("/api/v1/ollama/status")
def get_ollama_status():
    try:
        url = "http://localhost:11434/api/tags"
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            return {"available": True, "models": models, "url": "http://localhost:11434"}
    except Exception:
        return {"available": False, "models": [], "url": "http://localhost:11434"}

class ActionRequest(BaseModel):
    module: str
    action: str
    target: Optional[str] = "127.0.0.1"
    api_key: Optional[str] = None
    provider: Optional[str] = "openrouter"
    model: Optional[str] = "openai/gpt-4o-mini"

class ChatRequest(BaseModel):
    prompt: str
    history: Optional[List[Dict[str, str]]] = None
    api_key: Optional[str] = None
    provider: Optional[str] = "openrouter"
    model: Optional[str] = "openai/gpt-4o-mini"
    confirm: bool = False
    session_id: Optional[str] = None
    confirm: bool = False


# Keyword -> module routing table shared by the "detect" and "execute" halves
# of the chat orchestrator, so the proposed action shown to the user (before
# confirm=true) always matches exactly what will actually run.
CHAT_KEYWORD_ROUTES = [
    (("triage", "mjolnir"), "mjolnir"),
    (("scan", "bifrost"), "bifrost"),
    (("audit", "ad", "yggdrasil"), "yggdrasil"),
    (("threat", "fenrir"), "fenrir"),
    (("heimdall", "hids"), "heimdall"),
    (("playbook", "soar", "sleipnir"), "sleipnir"),
]


def _detect_chat_module(prompt_lower: str) -> Optional[str]:
    for keywords, module in CHAT_KEYWORD_ROUTES:
        if any(kw in prompt_lower for kw in keywords):
            return module
    return None

@app.get("/health")
def health():
    """Health-check pubblico per orchestratori Docker / Kubernetes."""
    return {"status": "healthy", "system": "Asgard Ragnarok"}

@app.get("/")
def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Asgard Enterprise SOC"}

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

async def _check_module_health(mod_key: str, info: Dict[str, Any]) -> Dict[str, Any]:
    """Real health check: try to actually run the module's entry point with
    --help and treat a clean (exit code 0) run as healthy. Falls back to the
    old "file exists" check when the subprocess itself cannot be spawned or
    times out (e.g. no python interpreter available, permissions issue) —
    NOT merely because the module doesn't understand --help, which instead
    surfaces as "degraded" with the module's own error output."""
    mod_path = os.path.join(ASGARD_ROOT, info["path"])
    entry_file = os.path.join(mod_path, info["entry"])

    file_exists = os.path.isfile(entry_file)
    if not file_exists:
        return {"healthy": False, "status": "degraded", "error": "entry file not found"}

    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, info["entry"], "--help",
            cwd=mod_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {"healthy": False, "status": "degraded", "error": "health check timed out after 5s"}

        if proc.returncode == 0:
            return {"healthy": True, "status": "healthy", "error": None}

        err_text = (stderr or stdout or b"").decode("utf-8", errors="replace").strip()
        return {
            "healthy": False,
            "status": "degraded",
            "error": err_text[:500] or f"exit code {proc.returncode}",
        }
    except Exception as e:
        # Subprocess could not even be spawned for an unexpected reason —
        # fall back to the simple "file exists" check.
        return {
            "healthy": file_exists,
            "status": "healthy" if file_exists else "degraded",
            "error": None if file_exists else f"health check unavailable: {e}",
        }


@app.get("/api/v1/status")
async def get_status():
    now = time.time()
    for mod_key, info in MODULE_STATUS.items():
        if now - info["last_check"] < 30:
            continue
        result = await _check_module_health(mod_key, info)
        info["healthy"] = result["healthy"]
        info["health_status"] = result["status"]
        info["health_error"] = result["error"]
        info["last_check"] = now

    online = sum(1 for m in MODULE_STATUS.values() if m["healthy"])
    return {
        "status": "online",
        "uptime_seconds": int(time.time() - START_TIME),
        "modules": {
            k: {
                "name": v["name"],
                "healthy": v["healthy"],
                "health_status": v.get("health_status", "unknown"),
                "health_error": v.get("health_error"),
            }
            for k, v in MODULE_STATUS.items()
        },
        "online_count": online,
        "total_count": len(MODULE_STATUS),
        "executions": EXEC_COUNTER,
    }


# --- Backup & restore (admin only) ---

class RestoreRequest(BaseModel):
    backup_path: str


@app.post("/api/v1/backup")
def api_create_backup(user: dict = Depends(require_role("admin"))):
    """Create a verified backup archive of all persistent state."""
    import backup as backup_mod
    try:
        result = backup_mod.create_backup()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")
    record_audit_event({"type": "backup_create", "user": user["username"], "file": result["path"]})
    return result


@app.post("/api/v1/backup/verify")
def api_verify_backup(req: RestoreRequest, user: dict = Depends(require_role("admin"))):
    """Verify a backup archive against its sha256 manifest."""
    import backup as backup_mod
    try:
        return backup_mod.verify_backup(req.backup_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v1/backup/restore")
def api_restore_backup(req: RestoreRequest, user: dict = Depends(require_role("admin"))):
    """Verify and restore a backup archive to the live stores."""
    import backup as backup_mod
    try:
        result = backup_mod.restore_backup(req.backup_path)
    except Exception as e:
        record_audit_event({"type": "backup_restore", "user": user["username"], "success": False, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))
    record_audit_event({"type": "backup_restore", "user": user["username"], "success": True, "file": req.backup_path})
    return result


@app.get("/api/v1/audit-log")
def get_audit_log(limit: int = 50, offset: int = 0, user: dict = Depends(require_role("admin"))):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    conn = sqlite3.connect(AUDIT_DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, timestamp, type, payload FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM events")
        total = cur.fetchone()[0]
    finally:
        conn.close()

    events = []
    for row_id, ts, ev_type, payload in rows:
        try:
            parsed_payload = json.loads(payload) if payload else None
        except (TypeError, ValueError):
            parsed_payload = None
        events.append({"id": row_id, "timestamp": ts, "type": ev_type, "payload": parsed_payload})

    return {"events": events, "total": total, "limit": limit, "offset": offset}

@app.get("/api/v1/reports")
def list_reports():
    reports = []
    for pattern in [
        os.path.join(ASGARD_ROOT, "Mjolnir", "output", "*.md"),
        os.path.join(ASGARD_ROOT, "Yggdrasil", "reports", "*.md"),
    ]:
        for filepath in sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)[:20]:
            stat = os.stat(filepath)
            reports.append({
                "filename": os.path.basename(filepath),
                "path": filepath,
                "size_bytes": stat.st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "source": "Mjolnir" if "Mjolnir" in filepath else "Yggdrasil",
            })
    return {"reports": reports}

@app.get("/api/v1/reports/read")
def read_report(path: str):
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return {"filename": os.path.basename(path), "content": content}

@app.get("/api/v1/hunt")
def threat_hunt(q: Optional[str] = ""):
    db_path = os.path.join(ASGARD_ROOT, "Fenrir", "fenrir.db")
    if not os.path.exists(db_path):
        return {"results": [], "total": 0, "message": "Fenrir database not found. Run Fenrir update first."}
    
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        if q:
            cursor.execute("""
                SELECT indicator_type, indicator, name, source, severity, date_added
                FROM iocs WHERE indicator LIKE ? OR name LIKE ? OR indicator_type LIKE ?
                ORDER BY id DESC LIMIT 100
            """, (f"%{q}%", f"%{q}%", f"%{q}%"))
        else:
            cursor.execute("""
                SELECT indicator_type, indicator, name, source, severity, date_added
                FROM iocs ORDER BY id DESC LIMIT 100
            """)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "indicator_type": r[0],
                "indicator": r[1],
                "name": r[2],
                "source": r[3],
                "severity": r[4],
                "date_added": r[5]
            })
        return {"results": results, "total": len(results)}
    except Exception as e:
        return {"results": [], "total": 0, "error": str(e)}

@app.websocket("/ws/telemetry")
async def websocket_telemetry(ws: WebSocket):
    await telemetry.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        telemetry.disconnect(ws)
    except Exception:
        telemetry.disconnect(ws)

def _build_module_command(mod: str, action: str = "default", target: str = "127.0.0.1"):
    """Return (cwd, argv, timeout) for a module invocation, or None for an
    unknown module. Shared between the real async runner and the chat
    "proposed action" preview so both describe the exact same command."""
    # Sanitize target to ensure safe IP / domain / CIDR format
    if not target or not re.match(r"^[a-zA-Z0-9\.\-_/:]+$", target):
        target = "127.0.0.1"

    if mod == "heimdall":
        path = os.path.join(ASGARD_ROOT, "Heimdall")
        return path, [sys.executable, "run_local_demo.py"], 20
    elif mod == "mjolnir":
        path = os.path.join(ASGARD_ROOT, "Mjolnir")
        return path, [sys.executable, "main.py", "triage", "--simulate"], 20
    elif mod == "bifrost":
        path = os.path.join(ASGARD_ROOT, "Bifrost")
        if action == "discover":
            return path, [sys.executable, "main.py", "discover", target], 35
        return path, [sys.executable, "main.py", "scan", target, "--enrich"], 25
    elif mod == "yggdrasil":
        path = os.path.join(ASGARD_ROOT, "Yggdrasil")
        return path, [sys.executable, "main.py", "audit"], 20
    elif mod == "fenrir":
        path = os.path.join(ASGARD_ROOT, "Fenrir")
        return path, [sys.executable, "main.py", "update"], 20
    elif mod == "sleipnir":
        path = os.path.join(ASGARD_ROOT, "Sleipnir")
        return path, [sys.executable, "main.py", "run"], 35
    return None


async def _run_module_raw(mod: str, action: str = "default", target: str = "127.0.0.1") -> str:
    """Run a module's CLI entry point asynchronously so long-running scans/
    audits (20-35s) don't block the FastAPI event loop while they execute."""
    built = _build_module_command(mod, action, target)
    if built is None:
        return f"Unknown module: {mod}"
    path, argv, timeout = built

    proc = await asyncio.create_subprocess_exec(
        *argv,
        cwd=path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except Exception:
            pass
        raise subprocess.TimeoutExpired(argv, timeout)

    stdout_text = (stdout or b"").decode("utf-8", errors="replace")
    stderr_text = (stderr or b"").decode("utf-8", errors="replace")
    return stdout_text or stderr_text

@app.post("/api/v1/execute")
async def execute_module(req: ActionRequest, user: dict = Depends(require_role("admin"))):
    mod = req.module.lower()
    await telemetry.broadcast({"type": "module_start", "module": mod, "action": req.action, "ts": time.time()})
    try:
        output = await _run_module_raw(mod, req.action or "default", req.target or "127.0.0.1")
        if mod in EXEC_COUNTER:
            EXEC_COUNTER[mod] += 1

        final_output = output
        if req.provider == "ollama" or (req.api_key and len(req.api_key) > 5):
            analyzed = query_llm("Analyze this security execution output and summarize key findings as a senior SOC engineer.", output, req.provider, req.api_key, req.model)
            final_output = f"{output}\n\n--- [AI SECURITY ANALYST REPORT ({req.provider.upper()} / {req.model})] ---\n{analyzed}"

        await telemetry.broadcast({"type": "module_complete", "module": mod, "ts": time.time(), "output_preview": (output[:200] if output else "")})
        return {"status": "success", "output": final_output}
    except subprocess.TimeoutExpired:
        await telemetry.broadcast({"type": "module_error", "module": mod, "ts": time.time(), "error": "timeout"})
        return {"status": "error", "output": f"Module {req.module} timed out. The operation took too long."}
    except Exception as e:
        await telemetry.broadcast({"type": "module_error", "module": mod, "ts": time.time(), "error": str(e)})
        return {"status": "error", "output": str(e)}

def query_llm(prompt: str, tool_output: str, provider: str, api_key: str, model: str, history: Optional[List[Dict[str, str]]] = None) -> str:
    try:
        system_prompt = (
            "You are Ragnarök, an elite AI SOC Assistant and Senior Security Engineer. "
            "You manage the Asgard Cybersecurity Suite (Heimdall HIDS, Mjolnir Triage, Bifrost Network Scanner, "
            "Yggdrasil AD Auditor, Fenrir CTI, and Sleipnir SOAR). "
            "Analyze the security telemetry and give expert, concise cybersecurity recommendations."
        )

        content = f"User Request: {prompt}\n\nTool Output:\n{tool_output}"

        if provider == "ollama":
            url = "http://localhost:11434/api/generate"
            full_prompt = f"{system_prompt}\n\n"
            if history:
                for h in history[-6:]:
                    full_prompt += f"{'User' if h.get('role') == 'user' else 'Assistant'}: {h.get('content', '')}\n\n"
            full_prompt += content
            body = {"model": model if model else "llama3", "prompt": full_prompt, "stream": False}
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "No response from local Ollama model.")
        else:
            url = "https://openrouter.ai/api/v1/chat/completions" if provider == "openrouter" else "https://api.openai.com/v1/chat/completions"
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
            if provider == "openrouter":
                headers["HTTP-Referer"] = "https://github.com/Fioru12/Asgard"
                headers["X-Title"] = "Asgard SOC"

            messages = [{"role": "system", "content": system_prompt}]
            if history:
                messages.extend(history[-6:])
            messages.append({"role": "user", "content": content})

            body = {
                "model": model if model else ("openai/gpt-4o-mini" if provider == "openrouter" else "gpt-4o-mini"),
                "messages": messages,
                "temperature": 0.3
            }
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[AI Analysis Note: LLM request skipped or failed ({e}). Showing raw execution output above.]"

@app.post("/api/v1/chat")
async def chat_orchestrator(req: ChatRequest, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    prompt = req.prompt.lower()
    triggered_module = _detect_chat_module(prompt)
    agent_used = None  # nome dell'agente specializzato usato per il contesto

    # Human-confirmation gate: an AI-identified action that would execute a
    # real module (subprocess launch) is only a *proposal* until the caller
    # resends the request with confirm=true.
    if triggered_module and not req.confirm:
        built = _build_module_command(triggered_module)
        proposed_command = " ".join(built[1]) if built else None
        await telemetry.broadcast({
            "type": "chat_action_proposed",
            "module": triggered_module,
            "ts": time.time(),
        })
        return {
            "status": "confirmation_required",
            "output": (
                f"Ho identificato l'azione '{triggered_module}'. "
                "Invia di nuovo la richiesta con confirm=true per eseguirla."
            ),
            "proposed_action": {
                "module": triggered_module,
                "command": proposed_command,
                "target": "127.0.0.1",
            },
        }

    tool_output = ""
    rag_context = ""
    session_id = getattr(req, "session_id", None)

    try:
        if triggered_module:
            tool_output = await _run_module_raw(triggered_module)
            EXEC_COUNTER[triggered_module] += 1
        else:
            # Se non c'è un modulo triggerato, prova una query RAG
            if RAG_AVAILABLE and rag_retriever and not triggered_module:
                # Rileva descrizioni di incidenti → suggerisci playbook Sleipnir
                # (solo proposta: mai esecuzione senza conferma esplicita)
                _incident_keywords = ("brute force", "bruteforce", "ransomware",
                                      "lateral movement", "movimento laterale",
                                      "malware", "attacco", "intrusione",
                                      "compromissione", "breach", "incidente",
                                      "password spraying", "crittografia file")
                if any(kw in req.prompt.lower() for kw in _incident_keywords) and rag_insights:
                    suggestion = None
                    try:
                        suggestion = rag_insights.suggest_playbook(req.prompt)
                    except Exception:
                        suggestion = None
                    if suggestion:
                        await telemetry.broadcast({
                            "type": "chat_playbook_suggested",
                            "playbook": suggestion.get("playbook"),
                            "ts": time.time(),
                        })
                        return {
                            "status": "playbook_suggested",
                            "output": (
                                f"Ho rilevato la descrizione di un possibile incidente. "
                                f"Playbook Sleipnir suggerito: '{suggestion['playbook']}' "
                                f"(pertinenza {suggestion['similarity']:.0%}). "
                                "Rivedi il playbook e conferma l'esecuzione solo dopo "
                                "verifica umana: questa è una proposta, nessuna azione è stata eseguita."
                            ),
                            "suggested_playbook": suggestion,
                        }
                # Rileva prompt che chiedono una visione d'insieme / riepilogo
                agent_used = None
                _insight_keywords = ("riepilogo", "situazione", "visione d'insieme",
                                     "panoramica", "cosa sta succedendo", "minacce princi",
                                     "resoconto", "summary", "overview", "health", "stato generale")
                if any(kw in req.prompt.lower() for kw in _insight_keywords) and rag_insights:
                    try:
                        insight_text = rag_insights.format_for_llm()
                        rag_context = insight_text
                        tool_output = "Ho analizzato lo stato complessivo della suite Asgard (analisi proattiva)."
                    except Exception:
                        tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."
                else:
                    # Routing multi-agente: se il prompt rientra nel dominio
                    # di un modulo, la ricerca è confinata alla sua collection
                    agent_used = None
                    try:
                        if rag_agents is not None:
                            agent_answer = rag_agents.answer(req.prompt, n_results=5)
                            if agent_answer.get("routed"):
                                agent_used = agent_answer["agent"]["name"]
                                rag_context = agent_answer["context"]
                                n_refs = len(agent_answer["references"])
                                tool_output = (
                                    f"Agente {agent_used} ({agent_answer['agent']['module']}): "
                                    f"{n_refs} riferimenti nel dominio."
                                )
                    except Exception:
                        agent_used = None
                    if agent_used is None:
                        try:
                            rag_results = rag_retriever.search(
                                query=req.prompt, n_results=5
                            )
                            rag_context = rag_retriever.format_for_llm(rag_results)
                            if rag_results:
                                tool_output = f"Ho trovato {len(rag_results)} riferimenti nei dati storici Asgard."
                            else:
                                tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."
                        except Exception:
                            tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."
            else:
                tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."

        if triggered_module:
            await telemetry.broadcast({"type": "chat_module_trigger", "module": triggered_module, "ts": time.time()})

        # Arricchisci il contesto con memoria conversazionale
        memory_context = ""
        if session_id and rag_memory:
            memory_context = rag_memory.get_summary(session_id)
            rag_memory.add(session_id, "user", req.prompt)

        # Costruisci il contesto completo per LLM
        full_context = tool_output
        if rag_context:
            full_context = f"{rag_context}\n\n=== OUTPUT MODULO ===\n{tool_output}"
        if memory_context:
            full_context = f"=== MEMORIA CONVERSAZIONALE ===\n{memory_context}\n\n{full_context}"

        if req.provider == "ollama" or (req.api_key and len(req.api_key) > 5):
            final_reply = query_llm(req.prompt, full_context, req.provider, req.api_key, req.model, req.history)
        else:
            final_reply = full_context if rag_context or memory_context else tool_output

        # Salva risposta nella memoria
        if session_id and rag_memory:
            rag_memory.add(session_id, "assistant", final_reply)

        return {"status": "success", "output": final_reply, "agent_used": agent_used}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "A module timed out during chat orchestration."}
    except Exception as e:
        return {"status": "error", "output": str(e)}

# ======================================================================
# RAG Dashboard
# ======================================================================

import pathlib
_DASHBOARD_DIR = pathlib.Path(__file__).parent / "dashboard"
_DASHBOARD_DIR.mkdir(exist_ok=True)
_DASHBOARD_HTML = _DASHBOARD_DIR / "index.html"

if not _DASHBOARD_HTML.exists():
    _DASHBOARD_HTML.write_text("<!DOCTYPE html><html><head><title>Asgard RAG</title>")
    _DASHBOARD_HTML.write_text("<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}</style>")
    _DASHBOARD_HTML.write_text("</head><body><h1>Asgard RAG Dashboard</h1>")
    _DASHBOARD_HTML.write_text("<div id='stats'></div>")
    _DASHBOARD_HTML.write_text("<script>fetch('/api/v1/rag/stats').then(r=>r.json()).then(s=>{")
    _DASHBOARD_HTML.write_text("document.getElementById('stats').innerHTML='<pre>'+JSON.stringify(s,null,2)+'</pre>'})")
    _DASHBOARD_HTML.write_text("</script></body></html>")

@app.get("/dashboard")
async def rag_dashboard():
    return FileResponse(str(_DASHBOARD_HTML))


@app.get("/security")
async def rag_security_dashboard():
    """Security Audit Dashboard."""
    security_html = _DASHBOARD_DIR / "security.html"
    if not security_html.exists():
        raise HTTPException(status_code=404, detail="Security dashboard non trovata")
    return FileResponse(str(security_html))


@app.get("/api/v1/rag/insights")
async def rag_insights_endpoint():
    """Analisi proattiva dei dati indicizzati (sommaria, read-only)."""
    if not RAG_AVAILABLE or rag_insights is None:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        summary = rag_insights.summary()
        return {"available": True, "insights": summary}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.get("/api/v1/rag/agents")
async def rag_agents_endpoint():
    """Elenco degli agenti specializzati (pubblico, read-only)."""
    if not RAG_AVAILABLE or rag_agents is None:
        return {"available": False, "agents": []}
    return {"available": True, "agents": rag_agents.list_agents()}


@app.post("/api/v1/rag/agents/ask")
async def rag_agents_ask(req: dict, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Domanda diretta all'agente competente (auth richiesta).

    Routing deterministico per keyword + ricerca semantica confinata alla
    collection di dominio. Nessuna esecuzione di moduli: sola lettura.
    """
    if not RAG_AVAILABLE or rag_agents is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    prompt = str(req.get("prompt", "")).strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Campo 'prompt' obbligatorio")
    try:
        answer = rag_agents.answer(prompt, n_results=int(req.get("n_results", 5)))
        if not answer.get("routed"):
            raise HTTPException(
                status_code=404,
                detail="Nessun agente competente per questo prompt",
            )
        await telemetry.broadcast({
            "type": "rag_agent_query",
            "agent": answer["agent"]["name"],
            "ts": time.time(),
            "references": len(answer["references"]),
        })
        return {"status": "success", **answer}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/timeline")
async def rag_timeline_endpoint(days: int = 30, spike_factor: float = 3.0, min_spike: int = 3):
    """Serie storica giornaliera degli alert (read-only, deterministica).

    spike_factor e min_spike permettono di tarare la sensitivity della spike
    detection; sono limitati a intervalli sicuri per evitare configurazioni
    insensate (spike_factor 1.5-10, min_spike 1-50).
    """
    if not RAG_AVAILABLE or rag_insights is None:
        return {"available": False, "error": "RAG Engine non disponibile"}
    spike_factor = min(max(spike_factor, 1.5), 10.0)
    min_spike = min(max(min_spike, 1), 50)
    try:
        from rag.timeline import TimelineEngine
        timeline = TimelineEngine(engine=rag_insights)
        return {"available": True, "timeline": timeline.summary(
            days=days, spike_factor=spike_factor, min_spike=min_spike)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.get("/api/v1/rag/timeline/export")
async def rag_timeline_export_endpoint(days: int = 30, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Export CSV della serie storica (auth: espone il profilo di attacco)."""
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.timeline import TimelineEngine
        timeline = TimelineEngine(engine=rag_insights)
        rows = timeline.daily_counts(days=days)
        lines = ["date,count,low,medium,high,critical"]
        for d in rows:
            s = d["by_severity"]
            lines.append(f"{d['date']},{d['count']},{s.get('LOW', 0)},{s.get('MEDIUM', 0)},"
                         f"{s.get('HIGH', 0)},{s.get('CRITICAL', 0)}")
        csv_text = "\n".join(lines) + "\n"
        from fastapi import Response
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="asgard_timeline_{days}d.csv"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rag/timeline/notify")
async def rag_timeline_notify_endpoint(days: int = 30, user: dict = Depends(require_role("admin", "analyst"))):
    """Rileva spike anomali e invia l'alert via Gjallarhorn (se configurato)."""
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.dispatch import send_timeline_alert
        return send_timeline_alert(timeline_kwargs={"engine": rag_insights}, days=days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/report")
async def rag_report_endpoint(save: bool = False, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report proattivo Markdown (richiede auth: contiene IP e IOC)."""
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.report import ReportExporter
        exporter = ReportExporter(engine=rag_insights)
        markdown = exporter.generate_markdown()
        result = {"status": "success", "format": "markdown", "report": markdown}
        if save:
            path = exporter.save()
            result["saved_to"] = path
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/report/pdf")
async def rag_report_pdf_endpoint(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report proattivo in formato PDF (richiede auth: contiene IP e IOC)."""
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.pdf_report import PDFReportExporter
        from rag.report import ReportExporter
        exporter = PDFReportExporter(report_exporter=ReportExporter(engine=rag_insights))
        data = exporter.generate_pdf()
        from fastapi.responses import Response
        return Response(
            content=data,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="asgard_report.pdf"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/security/history")
async def rag_security_history_endpoint(days: int = 30):
    """Storico security score (pubblico, read-only)."""
    if not RAG_AVAILABLE:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        from rag.security_history import SecurityScoreHistory
        return {"available": True, "history": SecurityScoreHistory().get_summary(days)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.get("/api/v1/rag/security/trend")
async def rag_security_trend_endpoint(days: int = 30):
    """Trend security score (pubblico, read-only)."""
    if not RAG_AVAILABLE:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        from rag.security_history import SecurityScoreHistory
        return {"available": True, "trend": SecurityScoreHistory().get_trend(days)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.post("/api/v1/rag/security/record")
async def rag_security_record_endpoint(user: dict = Depends(require_role("admin"))):
    """Registra il security score corrente nello storico (richiede auth)."""
    if not RAG_AVAILABLE or rag_security is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        audit = rag_security.run_audit()
        from rag.security_history import SecurityScoreHistory
        result = SecurityScoreHistory().record_score(
            score=audit["security_score"],
            level=audit["risk_level"],
            findings_count=len(audit["findings"]),
            recommendations_count=len(audit["recommendations"]),
        )
        return {"status": "success", "recorded": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/security/audit")
async def rag_security_dashboard_audit(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Security audit per dashboard (richiede auth)."""
    try:
        from rag.security import SecurityAuditor
        auditor = SecurityAuditor()
        return {"status": "success", "audit": auditor.run_full_audit()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/security/report")
async def rag_security_dashboard_report(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report Markdown del security audit per dashboard (richiede auth)."""
    try:
        from rag.security import SecurityAuditor
        auditor = SecurityAuditor()
        return {
            "status": "success",
            "format": "markdown",
            "report": auditor.format_report(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rag/report/notify")
async def rag_report_notify_endpoint(user: dict = Depends(require_role("admin", "analyst"))):
    """Invia il digest del report proattivo via Gjallarhorn (auth richiesta).

    Se GJALLARHORN_HUB_URL/GJALLARHORN_API_KEY non sono impostate risponde
    con sent=false, configured=false — nessun errore, nessun tentativo di rete.
    """
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag import dispatch
        result = dispatch.send_report(engine=rag_insights)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ======================================================================
# GDPR Compliance per Agenti + Raccomandazione per PMI
# ======================================================================


@app.get("/api/v1/rag/gdpr/checklist")
async def gdpr_checklist():
    """Checklist GDPR per autovalutazione (pubblica, no auth)."""
    try:
        from rag.gdpr import GDPR_CHECKLIST
        return {"status": "success", "checklist": GDPR_CHECKLIST}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rag/gdpr/evaluate")
async def gdpr_evaluate(answers: Dict[str, bool]):
    """Valuta le risposte alla checklist GDPR e restituisce score + gap analysis."""
    try:
        from rag.gdpr import GDPRComplianceChecker
        checker = GDPRComplianceChecker()
        return {"status": "success", "evaluation": checker.evaluate_checklist(answers)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/rag/gdpr/recommend")
async def gdpr_recommend(company_size: str = "small", sector: Optional[str] = None,
                         maturity: Optional[str] = None):
    """Raccomanda agenti Asgard per PMI in base a dimensione, settore e maturità."""
    try:
        from rag.gdpr import GDPRComplianceChecker
        checker = GDPRComplianceChecker()
        return {"status": "success", "recommendation": checker.recommend_agents(company_size, sector, maturity)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ======================================================================
# Auto-indexing schedulato
# ======================================================================

RAG_AUTO_INDEX_MINUTES = int(os.environ.get("RAG_AUTO_INDEX_MINUTES", "0"))
_LAST_AUTO_INDEX = {"ts": 0.0, "running": False}


def _auto_index_if_due():
    """Indicizza automaticamente se il timer è scaduto (solo se abilitato)."""
    if not RAG_AVAILABLE:
        return
    if RAG_AUTO_INDEX_MINUTES <= 0:
        return
    if _LAST_AUTO_INDEX["running"]:
        return
    now = time.time()
    if now - _LAST_AUTO_INDEX["ts"] < RAG_AUTO_INDEX_MINUTES * 60:
        return
    _LAST_AUTO_INDEX["running"] = True
    try:
        _LAST_AUTO_INDEX["ts"] = now
        results = rag_indexer.index_all()
        total = results.get("total", 0)
        if total > 0:
            print(
                f"[RAGNAROK] Auto-index completato: {total} documenti "
                f"(Heimdall={results.get('heimdall', 0)}, "
                f"Fenrir={results.get('fenrir', 0)}, "
                f"Mjolnir={results.get('mjolnir', 0)}, "
                f"Bifrost={results.get('bifrost', 0)}, "
                f"Forseti={results.get('forseti', 0)})"
            )
    except Exception as e:
        print(f"[RAGNAROK] Auto-index fallito: {e}")
    finally:
        _LAST_AUTO_INDEX["running"] = False


from fastapi import Request


@app.middleware("http")
async def rag_auto_index_middleware(request: Request, call_next):
    """Middleware che innesca l'auto-indicizzazione periodica."""
    _auto_index_if_due()
    return await call_next(request)


# ======================================================================
# Anomaly watcher: spike push via WebSocket in tempo reale
# ======================================================================

# Intervallo di controllo anomalie in minuti (0 = disabilitato, default 15)
RAG_ANOMALY_WATCH_MINUTES = int(os.environ.get("RAG_ANOMALY_WATCH_MINUTES", "15"))
_LAST_ANOMALY_CHECK: Dict[str, Any] = {"ts": 0.0, "running": False}
# Ultima data per cui un'anomalia è già stata notificata (anti-duplicati)
_NOTIFIED_ANOMALY_DATES: set = set()


def _anomaly_watch_if_due():
    """Controlla gli spike e li trasmette via WebSocket se scaduto il timer.

    A differenza dell'auto-index non fa lavoro pesante (nessuna indicizzazione):
    legge solo i metadati ChromaDB già in memoria, quindi può girare anche
    frequentemente senza impattare le latenze delle richieste.
    """
    if not RAG_AVAILABLE or rag_timeline is None:
        return
    if RAG_ANOMALY_WATCH_MINUTES <= 0:
        return
    if _LAST_ANOMALY_CHECK["running"]:
        return
    now = time.time()
    if now - _LAST_ANOMALY_CHECK["ts"] < RAG_ANOMALY_WATCH_MINUTES * 60:
        return
    _LAST_ANOMALY_CHECK["running"] = True
    try:
        _LAST_ANOMALY_CHECK["ts"] = now
        s = rag_timeline.summary(days=30)
        new_anoms = [
            a for a in s.get("anomalies", []) + s.get("severity_anomalies", [])
            if a.get("date") not in _NOTIFIED_ANOMALY_DATES
        ]
        if not new_anoms:
            return
        for a in new_anoms:
            _NOTIFIED_ANOMALY_DATES.add(a["date"])
        import asyncio

        async def _push():
            await telemetry.broadcast({
                "type": "rag_anomaly_detected",
                "ts": time.time(),
                "anomalies": new_anoms,
                "trend": s.get("trend"),
            })

        # broadcast() è async: schedula sul loop del server senza bloccare
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_push())
        except RuntimeError:
            pass  # nessun loop attivo (es. test sincroni): salta il push
    except Exception as e:
        print(f"[RAGNAROK] Anomaly watcher fallito: {e}")
    finally:
        _LAST_ANOMALY_CHECK["running"] = False


@app.middleware("http")
async def rag_anomaly_watch_middleware(request: Request, call_next):
    """Middleware che controlla gli spike e li pusha via WebSocket."""
    _anomaly_watch_if_due()
    return await call_next(request)


# ======================================================================
# Report sender schedulato: invio periodico del digest proattivo
# ======================================================================
#
# Per una PMI il report non va generato solo quando qualcuno se lo ricorda:
# con un trigger abilitato il digest del report proattivo viene inviato
# automaticamente via Gjallarhorn (Telegram/webhook/SMTP), usando lo stesso
# meccanismo middleware dei task schedulati esistenti.
#
# Due modalità (opzionali, non mutualmente esclusive):
#   RAG_REPORT_SEND_MINUTES=1440    # ogni N minuti (default 0 = disabilitato)
#   RAG_REPORT_SEND_CRON=08:00      # ogni giorno all'ora fissa locale HH:MM
#
# Se Gjallarhorn non è configurato il task è un no-op (nessun errore, nessun
# tentativo di rete): send_report() non lancia mai eccezioni.

RAG_REPORT_SEND_MINUTES = int(os.environ.get("RAG_REPORT_SEND_MINUTES", "0"))
RAG_REPORT_SEND_CRON = os.environ.get("RAG_REPORT_SEND_CRON", "").strip()
_LAST_REPORT_SEND: Dict[str, Any] = {"ts": 0.0, "running": False}
# Giorno (YYYY-MM-DD) in cui il report giornaliero (CRON) è già stato inviato.
_LAST_REPORT_CRON_DAY = ""


def _report_send_cron_parsed():
    """Ritorna (hh, mm) se RAG_REPORT_SEND_CRON è valido, altrimenti None."""
    if not RAG_REPORT_SEND_CRON:
        return None
    try:
        hh, mm = RAG_REPORT_SEND_CRON.split(":", 1)
        hh, mm = int(hh), int(mm)
    except (ValueError, AttributeError):
        return None
    if not (0 <= hh <= 23 and 0 <= mm <= 59):
        return None
    return hh, mm


def _report_send_cron_due(now):
    """True se l'orario del cron è raggiunto oggi e non è già stato inviato."""
    parsed = _report_send_cron_parsed()
    if parsed is None:
        return False
    lt = time.localtime(now)
    today = time.strftime("%Y-%m-%d", lt)
    if _LAST_REPORT_CRON_DAY == today:
        return False  # già inviato oggi
    target_min = parsed[0] * 60 + parsed[1]
    cur_min = lt.tm_hour * 60 + lt.tm_min
    return cur_min >= target_min


def _report_send_if_due():
    """Invia il digest del report proattivo se un trigger è scaduto."""
    if not RAG_AVAILABLE or rag_insights is None:
        return
    if RAG_REPORT_SEND_MINUTES <= 0 and _report_send_cron_parsed() is None:
        return
    if _LAST_REPORT_SEND["running"]:
        return
    now = time.time()
    interval_due = (
        RAG_REPORT_SEND_MINUTES > 0
        and now - _LAST_REPORT_SEND["ts"] >= RAG_REPORT_SEND_MINUTES * 60
    )
    cron_due = _report_send_cron_due(now)
    if not (interval_due or cron_due):
        return
    _LAST_REPORT_SEND["running"] = True
    try:
        _LAST_REPORT_SEND["ts"] = now
        if cron_due:
            # segna il giorno come già inviato così il cron non rispedisce oggi
            _LAST_REPORT_CRON_DAY = time.strftime("%Y-%m-%d", time.localtime(now))
        from rag import dispatch
        result = dispatch.send_report(engine=rag_insights)
        sent = result.get("sent", False)
        conf = result.get("configured", False)
        print(
            f"[RAGNAROK] Report programmato trasmesso: sent={sent} "
            f"configured={conf}"
        )
    except Exception as e:
        print(f"[RAGNAROK] Report programmato fallito: {e}")
    finally:
        _LAST_REPORT_SEND["running"] = False


@app.middleware("http")
async def rag_report_send_middleware(request: Request, call_next):
    """Middleware che innesca l'invio periodico del report proattivo."""
    _report_send_if_due()
    return await call_next(request)


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("RAGNAROK_HOST", "127.0.0.1")
    port = int(os.environ.get("RAGNAROK_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)
