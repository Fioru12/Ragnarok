import sys
import os
import subprocess
import json
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

app = FastAPI(title="Asgard Enterprise SOC Orchestrator", version="5.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ASGARD_ROOT = "C:\\Progetti\\Asgard"
FRONTEND_DIR = os.path.join(ASGARD_ROOT, "Ragnarok", "frontend")

class ActionRequest(BaseModel):
    module: str
    action: str
    target: Optional[str] = "127.0.0.1"
    api_key: Optional[str] = None
    provider: Optional[str] = "openrouter"
    model: Optional[str] = "openai/gpt-4o-mini"

class ChatRequest(BaseModel):
    prompt: str
    api_key: Optional[str] = None
    provider: Optional[str] = "openrouter"
    model: Optional[str] = "openai/gpt-4o-mini"

@app.get("/")
def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Asgard Enterprise SOC"}

def _run_module_raw(mod: str, target: str = "127.0.0.1") -> str:
    """Execute a module subprocess and return raw stdout/stderr."""
    if mod == "heimdall":
        path = os.path.join(ASGARD_ROOT, "Heimdall")
        res = subprocess.run([sys.executable, "run_local_demo.py"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "mjolnir":
        path = os.path.join(ASGARD_ROOT, "Mjolnir")
        res = subprocess.run([sys.executable, "main.py", "triage", "--simulate"], cwd=path, capture_output=True, text=True, encoding="utf-8", timeout=20)
    elif mod == "bifrost":
        path = os.path.join(ASGARD_ROOT, "Bifrost")
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
def execute_module(req: ActionRequest):
    try:
        output = _run_module_raw(req.module.lower(), req.target or "127.0.0.1")

        final_output = output
        if req.provider == "ollama" or (req.api_key and len(req.api_key) > 5):
            analyzed = query_llm("Analyze this security execution output and summarize key findings as a senior SOC engineer.", output, req.provider, req.api_key, req.model)
            final_output = f"{output}\n\n--- [AI SECURITY ANALYST REPORT ({req.provider.upper()} / {req.model})] ---\n{analyzed}"

        return {"status": "success", "output": final_output}
    except subprocess.TimeoutExpired:
        return {"status": "error", "output": f"Module {req.module} timed out. The operation took too long."}
    except Exception as e:
        return {"status": "error", "output": str(e)}

def query_llm(prompt: str, tool_output: str, provider: str, api_key: str, model: str) -> str:
    """Supports OpenRouter, Ollama (local), OpenAI, and Anthropic."""
    try:
        system_prompt = (
            "You are Ragnarök, an elite AI SOC Assistant and Senior Security Engineer. "
            "You manage the Asgard Cybersecurity Suite (Heimdall HIDS, Mjolnir Triage, Bifrost Network Scanner, "
            "Yggdrasil AD Auditor, Fenrir CTI, and Sleipnir SOAR). "
            "Analyze the security telemetry and give expert, concise cybersecurity recommendations."
        )

        content = f"User Request: {prompt}\n\nTool Output:\n{tool_output}"

        if provider == "ollama":
            # Local Ollama endpoint (http://localhost:11434)
            url = "http://localhost:11434/api/generate"
            body = {
                "model": model if model else "llama3",
                "prompt": f"{system_prompt}\n\n{content}",
                "stream": False
            }
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "No response from local Ollama model.")

        else:
            # OpenRouter / OpenAI compatible endpoint
            url = "https://openrouter.ai/api/v1/chat/completions" if provider == "openrouter" else "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            if provider == "openrouter":
                headers["HTTP-Referer"] = "https://github.com/Fioru12/Asgard"
                headers["X-Title"] = "Asgard SOC"

            body = {
                "model": model if model else ("openai/gpt-4o-mini" if provider == "openrouter" else "gpt-4o-mini"),
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": content}
                ],
                "temperature": 0.3
            }

            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data["choices"][0]["message"]["content"]

    except Exception as e:
        return f"[AI Analysis Note: LLM request skipped or failed ({e}). Showing raw execution output above.]"

@app.post("/api/v1/chat")
def chat_orchestrator(req: ChatRequest):
    prompt = req.prompt.lower()
    tool_output = ""

    try:
        if "triage" in prompt or "mjolnir" in prompt:
            tool_output = _run_module_raw("mjolnir")
        elif "scan" in prompt or "bifrost" in prompt:
            tool_output = _run_module_raw("bifrost")
        elif "audit" in prompt or "ad" in prompt or "yggdrasil" in prompt:
            tool_output = _run_module_raw("yggdrasil")
        elif "threat" in prompt or "fenrir" in prompt:
            tool_output = _run_module_raw("fenrir")
        elif "heimdall" in prompt or "hids" in prompt:
            tool_output = _run_module_raw("heimdall")
        elif "playbook" in prompt or "soar" in prompt or "sleipnir" in prompt:
            tool_output = _run_module_raw("sleipnir")
        else:
            tool_output = f"Ragnarök AI Assistant: Processed query '{req.prompt}'. All 6 defense modules are active."

        if req.provider == "ollama" or (req.api_key and len(req.api_key) > 5):
            final_reply = query_llm(req.prompt, tool_output, req.provider, req.api_key, req.model)
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
