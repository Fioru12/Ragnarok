import sys
import os
import subprocess
import json
import glob
import time
import re
import asyncio
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = FastAPI(title="Asgard Enterprise SOC Orchestrator", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auto-detect ASGARD_ROOT relative to backend directory or fallback to environment variable
DEFAULT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ASGARD_ROOT = os.getenv("ASGARD_ROOT", DEFAULT_ROOT)
FRONTEND_DIR = os.path.join(ASGARD_ROOT, "Ragnarok", "frontend")

START_TIME = time.time()

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

@app.get("/")
def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Asgard Enterprise SOC"}

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

@app.get("/api/v1/status")
def get_status():
    now = time.time()
    for mod_key, info in MODULE_STATUS.items():
        if now - info["last_check"] < 30:
            continue
        mod_path = os.path.join(ASGARD_ROOT, info["path"])
        entry_file = os.path.join(mod_path, info["entry"])
        info["healthy"] = os.path.isfile(entry_file)
        info["last_check"] = now

    online = sum(1 for m in MODULE_STATUS.values() if m["healthy"])
    return {
        "status": "online",
        "uptime_seconds": int(time.time() - START_TIME),
        "modules": {k: {"name": v["name"], "healthy": v["healthy"]} for k, v in MODULE_STATUS.items()},
        "online_count": online,
        "total_count": len(MODULE_STATUS),
        "executions": EXEC_COUNTER,
    }

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

def _run_module_raw(mod: str, action: str = "default", target: str = "127.0.0.1") -> str:
    # Sanitize target to ensure safe IP / domain / CIDR format
    if not target or not re.match(r"^[a-zA-Z0-9\.\-_/:]+$", target):
        target = "127.0.0.1"

    if mod == "heimdall":
        path = os.path.join(ASGARD_ROOT, "Heimdall")
        res = subprocess.run([sys.executable, "run_local_demo.py"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "mjolnir":
        path = os.path.join(ASGARD_ROOT, "Mjolnir")
        res = subprocess.run([sys.executable, "main.py", "triage", "--simulate"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "bifrost":
        path = os.path.join(ASGARD_ROOT, "Bifrost")
        if action == "discover":
            res = subprocess.run([sys.executable, "main.py", "discover", target], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=35)
        else:
            res = subprocess.run([sys.executable, "main.py", "scan", target, "--enrich"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=25)
    elif mod == "yggdrasil":
        path = os.path.join(ASGARD_ROOT, "Yggdrasil")
        res = subprocess.run([sys.executable, "main.py", "audit"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "fenrir":
        path = os.path.join(ASGARD_ROOT, "Fenrir")
        res = subprocess.run([sys.executable, "main.py", "update"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "sleipnir":
        path = os.path.join(ASGARD_ROOT, "Sleipnir")
        res = subprocess.run([sys.executable, "main.py", "run"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=35)
    else:
        return f"Unknown module: {mod}"
    return res.stdout or res.stderr

@app.post("/api/v1/execute")
async def execute_module(req: ActionRequest):
    mod = req.module.lower()
    await telemetry.broadcast({"type": "module_start", "module": mod, "action": req.action, "ts": time.time()})
    try:
        output = _run_module_raw(mod, req.action or "default", req.target or "127.0.0.1")
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
async def chat_orchestrator(req: ChatRequest):
    prompt = req.prompt.lower()
    tool_output = ""
    triggered_module = None

    try:
        if "triage" in prompt or "mjolnir" in prompt:
            tool_output = _run_module_raw("mjolnir")
            EXEC_COUNTER["mjolnir"] += 1
            triggered_module = "mjolnir"
        elif "scan" in prompt or "bifrost" in prompt:
            tool_output = _run_module_raw("bifrost")
            EXEC_COUNTER["bifrost"] += 1
            triggered_module = "bifrost"
        elif "audit" in prompt or "ad" in prompt or "yggdrasil" in prompt:
            tool_output = _run_module_raw("yggdrasil")
            EXEC_COUNTER["yggdrasil"] += 1
            triggered_module = "yggdrasil"
        elif "threat" in prompt or "fenrir" in prompt:
            tool_output = _run_module_raw("fenrir")
            EXEC_COUNTER["fenrir"] += 1
            triggered_module = "fenrir"
        elif "heimdall" in prompt or "hids" in prompt:
            tool_output = _run_module_raw("heimdall")
            EXEC_COUNTER["heimdall"] += 1
            triggered_module = "heimdall"
        elif "playbook" in prompt or "soar" in prompt or "sleipnir" in prompt:
            tool_output = _run_module_raw("sleipnir")
            EXEC_COUNTER["sleipnir"] += 1
            triggered_module = "sleipnir"
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
