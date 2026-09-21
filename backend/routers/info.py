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
    """Returns the MITRE ATT&CK Matrix mapping with detected techniques across Asgard suite modules.

    Single source of truth: core.mitre.MITRE_ATTACK_MATRIX (the same data
    served by /api/v1/dashboard/mitre-matrix). Previously this endpoint
    carried a hardcoded copy that had drifted out of sync with it.
    """
    from core.mitre import MITRE_ATTACK_MATRIX, TACTIC_IDS

    by_tactic = {}
    for tech in MITRE_ATTACK_MATRIX.values():
        by_tactic.setdefault(tech["tactic"], []).append(tech)
    return {
        "tactics": [
            {
                "id": TACTIC_IDS.get(tactic, tactic),
                "name": tactic,
                "techniques": [
                    {
                        "id": t["id"],
                        "name": t["name"],
                        "module": " / ".join(t["modules"]),
                        "status": t.get("status", "monitored"),
                    }
                    for t in sorted(techs, key=lambda x: x["id"])
                ],
            }
            for tactic, techs in sorted(by_tactic.items())
        ]
    }


@router.get("/api/v1/dashboard/mitre-matrix")
def get_dashboard_mitre_matrix():
    """Dashboard variant of the MITRE matrix — same single source of truth
    (core.mitre), previously a separate inline endpoint in server.py."""
    from core.mitre import get_mitre_coverage
    return get_mitre_coverage()

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
