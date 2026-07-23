import sys
import os
import subprocess
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = FastAPI(title="Ragnarok SOC AI Orchestrator", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ASGARD_ROOT = "C:\\Progetti\\Asgard"
FRONTEND_DIR = os.path.join(ASGARD_ROOT, "Ragnarok", "frontend")

class CommandRequest(BaseModel):
    prompt: str

@app.get("/")
def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Ragnarok SOC AI Orchestrator"}

@app.post("/api/v1/orchestrate")
def orchestrate_command(req: CommandRequest):
    prompt = req.prompt.lower().strip()
    response = {"intent": "unknown", "output": "", "status": "error"}

    try:
        if "triage" in prompt or "mjolnir" in prompt:
            path = os.path.join(ASGARD_ROOT, "Mjolnir")
            res = subprocess.run([sys.executable, "main.py", "triage", "--simulate"], cwd=path, capture_output=True, text=True, timeout=15)
            response = {"intent": "triage", "output": res.stdout or res.stderr, "status": "success"}

        elif "scan" in prompt or "bifrost" in prompt:
            path = os.path.join(ASGARD_ROOT, "Bifrost")
            res = subprocess.run([sys.executable, "main.py", "scan", "127.0.0.1", "--enrich"], cwd=path, capture_output=True, text=True, timeout=15)
            response = {"intent": "scan", "output": res.stdout or res.stderr, "status": "success"}

        elif "audit" in prompt or "yggdrasil" in prompt or "active directory" in prompt:
            path = os.path.join(ASGARD_ROOT, "Yggdrasil")
            res = subprocess.run([sys.executable, "main.py", "audit"], cwd=path, capture_output=True, text=True, timeout=15)
            response = {"intent": "audit", "output": res.stdout or res.stderr, "status": "success"}

        elif "threat" in prompt or "fenrir" in prompt or "cti" in prompt:
            path = os.path.join(ASGARD_ROOT, "Fenrir")
            res = subprocess.run([sys.executable, "main.py", "update"], cwd=path, capture_output=True, text=True, timeout=15)
            response = {"intent": "threat_intel", "output": res.stdout or res.stderr, "status": "success"}

        elif "heimdall" in prompt or "simulate attack" in prompt:
            path = os.path.join(ASGARD_ROOT, "Heimdall")
            res = subprocess.run([sys.executable, "run_local_demo.py"], cwd=path, capture_output=True, text=True, timeout=15)
            response = {"intent": "hids", "output": res.stdout or res.stderr, "status": "success"}

        elif "playbook" in prompt or "soar" in prompt or "sleipnir" in prompt:
            path = os.path.join(ASGARD_Root if 'ASGARD_Root' in locals() else ASGARD_ROOT, "Sleipnir")
            res = subprocess.run([sys.executable, "main.py", "run"], cwd=path, capture_output=True, text=True, timeout=30)
            response = {"intent": "soar", "output": res.stdout or res.stderr, "status": "success"}

        else:
            response = {
                "intent": "chat",
                "output": f"Ragnarök AI: I received your request: '{req.prompt}'. You can ask me to run:\n- 'Run Mjolnir triage'\n- 'Scan ports with Bifrost'\n- 'Audit Active Directory with Yggdrasil'\n- 'Update threat intel with Fenrir'\n- 'Simulate Heimdall alert'\n- 'Run Sleipnir SOAR playbook'",
                "status": "success"
            }
    except Exception as e:
        response = {"intent": "error", "output": str(e), "status": "failed"}

    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
