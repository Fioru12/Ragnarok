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


def test_report_read_blocks_path_traversal():
    # Attempt to read sensitive file outside authorized report directories
    res = client.get("/api/v1/reports/read", params={"path": "../../package_release.py"})
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    # Attempt to read non-existent system file
    res = client.get("/api/v1/reports/read", params={"path": "C:\\Windows\\win.ini"})
    assert res.status_code == 403

