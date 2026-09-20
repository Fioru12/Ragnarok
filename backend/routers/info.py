"""Static info endpoints — moved out of server.py to keep the orchestrator lean.

Ollama status, MITRE matrix and Bifrost topology are pure functions with no
auth, no globals and no side effects. Handlers are verbatim copies of the
originals (OllamaStatus model dropped: defined but never used anywhere).
"""
import json
import urllib.request

from fastapi import APIRouter

router = APIRouter(tags=["info"])


@router.get("/api/v1/ollama/status")
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

@router.get("/api/v1/mitre/matrix")
def get_mitre_matrix():
    """Returns the MITRE ATT&CK Matrix mapping with detected techniques across Asgard suite modules."""
    return {
        "tactics": [
            {
                "id": "TA0043",
                "name": "Reconnaissance",
                "techniques": [
                    {"id": "T1046", "name": "Network Service Discovery", "module": "Bifrost", "status": "active"},
                    {"id": "T1595", "name": "Active Scanning", "module": "Bifrost", "status": "active"}
                ]
            },
            {
                "id": "TA0001",
                "name": "Initial Access",
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "module": "Bifrost / Fenrir", "status": "monitored"}
                ]
            },
            {
                "id": "TA0006",
                "name": "Credential Access",
                "techniques": [
                    {"id": "T1110", "name": "Brute Force", "module": "Heimdall", "status": "active"},
                    {"id": "T1110.001", "name": "Password Guessing", "module": "Heimdall", "status": "active"},
                    {"id": "T1087.002", "name": "Domain Account Discovery", "module": "Yggdrasil", "status": "active"}
                ]
            },
            {
                "id": "TA0002",
                "name": "Execution",
                "techniques": [
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "module": "Mjolnir", "status": "monitored"}
                ]
            },
            {
                "id": "TA0005",
                "name": "Defense Evasion",
                "techniques": [
                    {"id": "T1070", "name": "Indicator Removal", "module": "Mjolnir", "status": "monitored"}
                ]
            }
        ]
    }

@router.get("/api/v1/bifrost/topology")
def get_bifrost_topology():
    """Returns network topology graph nodes & edges from Bifrost scanner data for interactive frontend rendering."""
    return {
        "nodes": [
            {"id": "gateway", "label": "Security Gateway / Router", "type": "router", "ip": "192.168.1.1"},
            {"id": "host-100", "label": "Web Application Server", "type": "server", "ip": "192.168.1.100", "ports": [80, 443]},
            {"id": "host-150", "label": "Active Directory DC", "type": "dc", "ip": "192.168.1.150", "ports": [53, 88, 389, 445]},
            {"id": "host-200", "label": "Linux SSH Host", "type": "server", "ip": "192.168.1.200", "ports": [22]}
        ],
        "edges": [
            {"source": "gateway", "target": "host-100"},
            {"source": "gateway", "target": "host-150"},
            {"source": "gateway", "target": "host-200"}
        ]
    }
