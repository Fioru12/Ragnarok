import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from server import app

client = TestClient(app)

def test_mitre_matrix_endpoint():
    res = client.get("/api/v1/mitre/matrix")
    assert res.status_code == 200
    data = res.json()
    assert "tactics" in data
    assert len(data["tactics"]) >= 4

def test_bifrost_topology_endpoint():
    res = client.get("/api/v1/bifrost/topology")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 3

def test_metrics_endpoint_exposes_all_metrics_the_grafana_dashboard_queries():
    # Regression test: server.py used to define /metrics TWICE. FastAPI
    # matches routes in registration order, so the first definition always
    # won and the second (which emitted the metric names the shipped
    # Grafana dashboard actually queries) was dead code - every deployed
    # dashboard would have shown "No data" on 3 of its 4 panels.
    res = client.get("/metrics")
    assert res.status_code == 200
    body = res.text
    for metric_name in (
        "asgard_uptime_seconds",
        "asgard_registered_users_total",
        "asgard_registered_agents_total",
        "asgard_active_tenants_total",
    ):
        assert metric_name in body, f"{metric_name} missing from /metrics output"


def test_reports_endpoints_require_authentication():
    # Regression test: /api/v1/reports, /reports/read and /hunt used to have
    # no auth dependency at all - reachable by any HTTP client bypassing
    # CORS, exposing AD audit / Mjolnir / Fenrir findings to anyone on the
    # network. They must now reject unauthenticated requests.
    assert client.get("/api/v1/reports").status_code == 401
    assert client.get("/api/v1/reports/read", params={"path": "x"}).status_code == 401
    assert client.get("/api/v1/hunt").status_code == 401


def test_report_read_blocks_path_traversal(monkeypatch):
    monkeypatch.setattr("auth.RAGNAROK_API_KEY", "test-key-for-traversal-check")
    headers = {"X-API-Key": "test-key-for-traversal-check"}

    # Attempt to read sensitive file outside authorized report directories
    res = client.get("/api/v1/reports/read", params={"path": "../../package_release.py"}, headers=headers)
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    # Attempt to read non-existent system file
    res = client.get("/api/v1/reports/read", params={"path": "C:\\Windows\\win.ini"}, headers=headers)
    assert res.status_code == 403


def test_agent_heartbeat_requires_the_secret_issued_at_registration(monkeypatch):
    # Regression test: /api/v1/agents/heartbeat used to accept just an
    # agent_id (no proof of possession), so anyone who knew or guessed a
    # registered agent's id could forge its status/rules_json. Registration
    # now returns a per-agent secret that heartbeat must present.
    monkeypatch.setattr("auth.RAGNAROK_API_KEY", "admin-key-for-agent-test")
    admin_headers = {"X-API-Key": "admin-key-for-agent-test"}

    token = client.post("/api/v1/agents/tokens", json={}, headers=admin_headers).json()["token"]
    reg = client.post("/api/v1/agents/register", json={
        "token": token, "agent_id": "spoof-test-agent", "name": "Test", "ip_address": "10.0.0.5",
    }).json()
    agent_secret = reg["agent_secret"]
    assert agent_secret

    # Correct secret -> accepted
    ok = client.post("/api/v1/agents/heartbeat", json={
        "agent_id": "spoof-test-agent", "agent_secret": agent_secret, "status": "active",
    })
    assert ok.status_code == 200

    # Wrong/guessed secret -> rejected, cannot spoof the agent's status
    forged = client.post("/api/v1/agents/heartbeat", json={
        "agent_id": "spoof-test-agent", "agent_secret": "guessed-wrong-secret", "status": "active",
    })
    assert forged.status_code == 401


def test_setup_persist_restricts_file_permissions(monkeypatch, tmp_path):
    # Regression test: asgard_setup.env holds plaintext integration secrets
    # (VT/OTX/Telegram/Gjallarhorn keys) and used to be written with default
    # (world-readable) permissions.
    monkeypatch.setattr("auth.RAGNAROK_API_KEY", "admin-key-for-setup-test")
    setup_path = tmp_path / "asgard_setup.env"
    monkeypatch.setattr("server.SETUP_ENV_PATH", str(setup_path))

    res = client.post(
        "/api/v1/setup",
        json={"values": {"virustotal_api_key": "vt-test-secret"}},
        headers={"X-API-Key": "admin-key-for-setup-test"},
    )
    assert res.status_code == 200
    assert setup_path.exists()

    mode = setup_path.stat().st_mode & 0o777
    if os.name != "nt":
        # POSIX: chmod is meaningful and must actually restrict access
        assert mode == 0o600
    # On Windows os.chmod only toggles the read-only bit, so this is a
    # best-effort call there - the important thing is it doesn't crash
    # or block the save (covered by the 200 assertion above).

