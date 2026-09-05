"""Test end-to-end: indicizzazione reale, ricerca semantica, dashboard.

Run: pytest tests/test_e2e.py -v  (dalla root Ragnarok)
"""
import os
import sys
import tempfile
import sqlite3
import pathlib

os.environ.setdefault("RAGNAROK_API_KEY", "test-key-for-pytest")

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from fastapi.testclient import TestClient
import server

client = TestClient(server.app)
AUTH = {"X-API-Key": "test-key-for-pytest"}


def _make_fake_heimdall_db(asgard_root: str) -> str:
    """Crea un DB Heimdall finto con due alert reali."""
    hdir = pathlib.Path(asgard_root) / "Heimdall"
    hdir.mkdir(parents=True, exist_ok=True)
    db = hdir / "heimdall.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts ("
        "id INTEGER PRIMARY KEY, rule_title TEXT, severity TEXT, source_ip TEXT, "
        "action_taken TEXT, description TEXT, count INTEGER, timestamp TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocked_ips ("
        "id INTEGER PRIMARY KEY, ip TEXT, reason TEXT, expires_at TEXT)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO alerts VALUES (1,?,?,?,?,?,?,?)",
        ("SSH Brute Force", "HIGH", "192.168.1.100", "BLOCKED_IP",
         "Tentativi multipli di login SSH", 5, "2026-01-15 10:00:00"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO alerts VALUES (2,?,?,?,?,?,?,?)",
        ("DDoS SYN Flood", "CRITICAL", "10.0.0.50", "LOGGED",
         "Syn flood detected sulla porta 80", 1000, "2026-01-15 11:00:00"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO blocked_ips VALUES (1,?,?,?)",
        ("192.168.1.100", "SSH Brute Force", "2026-01-16 10:00:00"),
    )
    conn.commit()
    conn.close()
    return str(db)


def test_e2e_index_and_query_semantic():
    """Indicizza dati finti e verifica che la ricerca semantica li trovi."""
    tmp = tempfile.mkdtemp(prefix="asgard_e2e_")
    try:
        _make_fake_heimdall_db(tmp)
        # Punta l'indexer ai dati finti
        server.rag_indexer.asgard_root = tmp
        count = server.rag_indexer.index_heimdall()
        assert count >= 2, f"Attesi >=2 alert, indicizzati: {count}"

        stats = server.rag_indexer.get_stats()
        assert stats.get("heimdall_alerts", 0) >= 2

        # Ricerca semantica via API
        q = client.post(
            "/api/v1/rag/query",
            json={"query": "SSH brute force blocked IP", "n_results": 3},
            headers=AUTH,
        )
        assert q.status_code == 200
        data = q.json()
        assert data["status"] == "success"
        assert len(data["results"]) > 0
        top = data["results"][0]["text"]
        assert "SSH" in top or "192.168.1.100" in top

        # Stats via API
        s = client.get("/api/v1/rag/stats").json()
        assert s["available"] is True
        assert s["collections"]["heimdall_alerts"] >= 2
    finally:
        import shutil, time, gc
        time.sleep(0.3)
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)


def test_e2e_dashboard_served():
    """Dashboard HTML servita correttamente."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "Asgard RAG Dashboard" in res.text
    assert "text/html" in res.headers.get("content-type", "")


def test_e2e_chat_returns_rag_context_without_llm():
    """Chat senza LLM: con RAG attivo restituisce contesto trovato."""
    tmp = tempfile.mkdtemp(prefix="asgard_e2e_chat_")
    try:
        _make_fake_heimdall_db(tmp)
        server.rag_indexer.asgard_root = tmp
        server.rag_indexer.index_heimdall()

        # Chat generica che NON triggera un modulo ma usa RAG
        res = client.post(
            "/api/v1/chat",
            json={"prompt": "Quanti IP malevoli sono stati bloccati?", "confirm": False},
            headers=AUTH,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "CONTESTO DATI ASGARD" in data["output"] or "riferimenti" in data["output"].lower()
    finally:
        import shutil, time, gc
        time.sleep(0.3)
        gc.collect()
        shutil.rmtree(tmp, ignore_errors=True)