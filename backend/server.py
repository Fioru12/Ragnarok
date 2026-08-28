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

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

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
RAGNAROK_API_KEY = os.getenv("RAGNAROK_API_KEY")
if not RAGNAROK_API_KEY:
    RAGNAROK_API_KEY = secrets.token_urlsafe(32)
    print("=" * 70)
    print("[RAGNAROK] RAGNAROK_API_KEY not set — generated a temporary key:")
    print(f"[RAGNAROK]   {RAGNAROK_API_KEY}")
    print("[RAGNAROK] Set RAGNAROK_API_KEY in your environment to persist it.")
    print("[RAGNAROK] Send it back as the 'X-API-Key' header on execute/chat calls.")
    print("=" * 70)


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key or x_api_key != RAGNAROK_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")
    return x_api_key

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


@app.get("/api/v1/audit-log")
def get_audit_log(limit: int = 50, offset: int = 0, _api_key: str = Depends(require_api_key)):
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
async def execute_module(req: ActionRequest, _api_key: str = Depends(require_api_key)):
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
async def chat_orchestrator(req: ChatRequest, _api_key: str = Depends(require_api_key)):
    prompt = req.prompt.lower()
    triggered_module = _detect_chat_module(prompt)

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
    try:
        if triggered_module:
            tool_output = await _run_module_raw(triggered_module)
            EXEC_COUNTER[triggered_module] += 1
        else:
            tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."

        if triggered_module:
            await telemetry.broadcast({"type": "chat_module_trigger", "module": triggered_module, "ts": time.time()})

        if req.provider == "ollama" or (req.api_key and len(req.api_key) > 5):
            final_reply = query_llm(req.prompt, tool_output, req.provider, req.api_key, req.model, req.history)
        else:
            final_reply = tool_output

        return {"status": "success", "output": final_reply}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": "A module timed out during chat orchestration."}
    except Exception as e:
        return {"status": "error", "output": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
