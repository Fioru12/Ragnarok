"""Minimal security regression tests for the Ragnarok backend.

Run with:
    pytest -v
from the Ragnarok project root (requires fastapi, httpx, pytest).
"""
import os
import sys
import tempfile
import asyncio
from unittest.mock import AsyncMock

# Make sure a deterministic API key is set BEFORE the app module is imported,
# since server.py reads RAGNAROK_API_KEY at import time.
os.environ.setdefault("RAGNAROK_API_KEY", "test-key-for-pytest")
# Il watcher anomalie resta disabilitato nei test API (i test dedicati lo
# abilitano via monkeypatch) per non iniettare eventi WebSocket nei test esistenti.
os.environ.setdefault("RAG_ANOMALY_WATCH_MINUTES", "0")
# Anche l'invio programmato del report è disabilitato di default nei test API;
# i test dedicati lo abilitano via monkeypatch, senza far partire invii reali.
os.environ.setdefault("RAG_REPORT_SEND_MINUTES", "0")

# Point the audit DB at an isolated temp file so tests never touch (or get
# polluted by) a real ragnarok_audit.db, and so the schema is created fresh.
_AUDIT_DB_FD, _AUDIT_DB_PATH = tempfile.mkstemp(prefix="ragnarok_audit_test_", suffix=".db")
os.close(_AUDIT_DB_FD)
os.environ.setdefault("RAGNAROK_AUDIT_DB_PATH", _AUDIT_DB_PATH)

# Same for the setup wizard's persisted env file: never touch a real one.
_SETUP_ENV_FD, _SETUP_ENV_PATH = tempfile.mkstemp(prefix="ragnarok_setup_test_", suffix=".env")
os.close(_SETUP_ENV_FD)
os.remove(_SETUP_ENV_PATH)  # start absent, as a fresh install would be
os.environ.setdefault("RAGNAROK_SETUP_ENV_PATH", _SETUP_ENV_PATH)

# Isolate the auth DB and use a fixed secret for deterministic tests.
_AUTH_DB_FD, _AUTH_DB_PATH = tempfile.mkstemp(prefix="ragnarok_auth_test_", suffix=".db")
os.close(_AUTH_DB_FD)
os.environ.setdefault("RAGNAROK_AUTH_DB_PATH", _AUTH_DB_PATH)
os.environ.setdefault("RAGNAROK_AUTH_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("RAGNAROK_SESSION_TTL", "3600")

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from fastapi.testclient import TestClient  # noqa: E402
import server  # noqa: E402

client = TestClient(server.app)
AUTH_HEADERS = {"X-API-Key": "test-key-for-pytest"}


class _StubIndexer:
    """Stub per AsgardIndexer — get_stats restituisce collezioni controllate."""
    def __init__(self, collections: dict):
        self._collections = collections

    def get_stats(self):
        return dict(self._collections)


def _reset_module_health_cache():
    """Force get_status() to re-run the health check instead of using its
    30s cache, so each test controls exactly what the mocked subprocess
    reports."""
    for info in server.MODULE_STATUS.values():
        info["last_check"] = 0


def _make_fake_proc(returncode=0, stdout=b"", stderr=b""):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    proc.kill = lambda: None
    proc.wait = AsyncMock(return_value=None)
    return proc


def test_execute_without_api_key_is_unauthorized():
    res = client.post(
        "/api/v1/execute",
        json={"module": "heimdall", "action": "simulate", "target": "127.0.0.1"},
    )
    assert res.status_code == 401


def test_execute_with_wrong_api_key_is_unauthorized():
    res = client.post(
        "/api/v1/execute",
        json={"module": "heimdall", "action": "simulate", "target": "127.0.0.1"},
        headers={"X-API-Key": "not-the-right-key"},
    )
    assert res.status_code == 401


def test_chat_without_api_key_is_unauthorized():
    res = client.post("/api/v1/chat", json={"prompt": "hello"})
    assert res.status_code == 401


def test_status_endpoint_does_not_require_api_key():
    res = client.get("/api/v1/status")
    assert res.status_code == 200
    assert "modules" in res.json()


# --- 1. Persistent audit log ---

def test_audit_log_without_api_key_is_unauthorized():
    res = client.get("/api/v1/audit-log")
    assert res.status_code == 401


def test_execute_persists_event_to_audit_db_readable_via_endpoint(monkeypatch):
    fake_proc = _make_fake_proc(returncode=0, stdout=b"heimdall ok")
    create_mock = AsyncMock(return_value=fake_proc)
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)

    res = client.post(
        "/api/v1/execute",
        json={"module": "heimdall", "action": "simulate", "target": "127.0.0.1"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    res = client.get("/api/v1/audit-log?limit=10&offset=0", headers=AUTH_HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    types = [e["type"] for e in body["events"]]
    assert "module_start" in types
    assert "module_complete" in types


def test_audit_log_pagination_params_are_respected():
    res = client.get("/api/v1/audit-log?limit=1&offset=0", headers=AUTH_HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert body["limit"] == 1
    assert len(body["events"]) <= 1


# --- 2. Real health check ---

def _use_fake_asgard_root(monkeypatch):
    """The health check needs each module's entry file to exist on disk
    before it will even attempt to spawn a subprocess (see
    _check_module_health). In an isolated checkout of just this repo (e.g.
    CI), the sibling module directories referenced by ASGARD_ROOT don't
    exist. Point ASGARD_ROOT at a throwaway directory with empty stand-in
    entry files so these tests exercise the subprocess-mocking behavior
    itself, independent of what else happens to be checked out alongside
    Ragnarok."""
    fake_root = tempfile.mkdtemp(prefix="ragnarok_fake_asgard_root_")
    for info in server.MODULE_STATUS.values():
        mod_dir = os.path.join(fake_root, info["path"])
        os.makedirs(mod_dir, exist_ok=True)
        open(os.path.join(mod_dir, info["entry"]), "a").close()
    monkeypatch.setattr(server, "ASGARD_ROOT", fake_root)


def test_status_reports_healthy_when_subprocess_exits_zero(monkeypatch):
    _use_fake_asgard_root(monkeypatch)
    _reset_module_health_cache()
    create_mock = AsyncMock(return_value=_make_fake_proc(returncode=0))
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)

    res = client.get("/api/v1/status")
    assert res.status_code == 200
    modules = res.json()["modules"]
    assert all(m["healthy"] is True for m in modules.values())
    assert all(m["health_status"] == "healthy" for m in modules.values())
    assert create_mock.await_count > 0


def test_status_reports_degraded_when_subprocess_exits_nonzero(monkeypatch):
    _use_fake_asgard_root(monkeypatch)
    _reset_module_health_cache()
    create_mock = AsyncMock(return_value=_make_fake_proc(returncode=1, stderr=b"boom: no --help"))
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)

    res = client.get("/api/v1/status")
    assert res.status_code == 200
    modules = res.json()["modules"]
    assert all(m["healthy"] is False for m in modules.values())
    assert all(m["health_status"] == "degraded" for m in modules.values())
    assert all("boom" in (m["health_error"] or "") for m in modules.values())


def test_status_falls_back_to_file_check_when_subprocess_cannot_spawn(monkeypatch):
    _use_fake_asgard_root(monkeypatch)
    _reset_module_health_cache()

    async def _raise(*args, **kwargs):
        raise OSError("no such interpreter")

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", _raise)

    res = client.get("/api/v1/status")
    assert res.status_code == 200
    modules = res.json()["modules"]
    # The fake entry files exist on disk, so the fallback should report
    # healthy=True even though the subprocess check itself failed.
    assert all(m["healthy"] is True for m in modules.values())


# --- 3. Async subprocess execution ---

def test_execute_module_uses_async_subprocess_not_blocking_run(monkeypatch):
    fake_proc = _make_fake_proc(returncode=0, stdout=b"bifrost scan output")
    create_mock = AsyncMock(return_value=fake_proc)
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)

    sync_run_mock = AsyncMock(side_effect=AssertionError("subprocess.run should not be called"))
    monkeypatch.setattr(server.subprocess, "run", sync_run_mock)

    res = client.post(
        "/api/v1/execute",
        json={"module": "bifrost", "action": "scan", "target": "127.0.0.1"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "bifrost scan output" in body["output"]
    sync_run_mock.assert_not_called()
    create_mock.assert_awaited()


def test_execute_module_timeout_is_reported_gracefully(monkeypatch):
    async def _timeout_proc(*args, **kwargs):
        proc = _make_fake_proc()

        async def _hang():
            raise asyncio.TimeoutError()

        proc.communicate = _hang
        return proc

    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", _timeout_proc)

    res = client.post(
        "/api/v1/execute",
        json={"module": "sleipnir", "action": "run", "target": "127.0.0.1"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "error"
    assert "timed out" in body["output"].lower()


# --- 4. Chat confirmation gate ---

def test_chat_without_confirm_proposes_action_without_executing(monkeypatch):
    create_mock = AsyncMock(return_value=_make_fake_proc(returncode=0, stdout=b"should not run"))
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)
    before = server.EXEC_COUNTER["bifrost"]

    res = client.post(
        "/api/v1/chat",
        json={"prompt": "please run a scan on the network"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "confirmation_required"
    assert "confirm=true" in body["output"]
    assert body["proposed_action"]["module"] == "bifrost"
    create_mock.assert_not_awaited()
    assert server.EXEC_COUNTER["bifrost"] == before


def test_chat_with_confirm_true_executes_the_module(monkeypatch):
    create_mock = AsyncMock(return_value=_make_fake_proc(returncode=0, stdout=b"scan complete"))
    monkeypatch.setattr(server.asyncio, "create_subprocess_exec", create_mock)
    before = server.EXEC_COUNTER["bifrost"]

    res = client.post(
        "/api/v1/chat",
        json={"prompt": "please run a scan on the network", "confirm": True},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "scan complete" in body["output"]
    create_mock.assert_awaited()
    assert server.EXEC_COUNTER["bifrost"] == before + 1


def test_chat_without_module_keyword_does_not_require_confirmation():
    res = client.post(
        "/api/v1/chat",
        json={"prompt": "hello there"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"


# --- 5. Setup wizard ---

def test_setup_requires_auth():
    res = client.get("/api/v1/setup")
    assert res.status_code == 401
    res = client.post("/api/v1/setup", json={"values": {"virustotal_api_key": "x"}})
    assert res.status_code == 401


def test_setup_rejects_unknown_field():
    res = client.post(
        "/api/v1/setup",
        json={"values": {"totally_made_up_field": "x"}},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 422


def test_setup_save_and_status_roundtrip(monkeypatch):
    for meta in server.SETUP_FIELDS.values():
        monkeypatch.delenv(meta["env"], raising=False)

    res = client.post(
        "/api/v1/setup",
        json={"values": {"virustotal_api_key": "abcd1234efgh5678"}},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    assert "VT_API_KEY" in res.json()["updated_fields"]
    # The subprocess env for the next module launch picks this up immediately.
    assert os.environ["VT_API_KEY"] == "abcd1234efgh5678"

    res = client.get("/api/v1/setup", headers=AUTH_HEADERS)
    assert res.status_code == 200
    fields = res.json()["fields"]
    assert fields["virustotal_api_key"]["configured"] is True
    # The raw secret must never be echoed back, only a masked preview.
    assert fields["virustotal_api_key"]["preview"] == "************5678"
    assert "abcd1234efgh5678" not in res.text
    assert fields["otx_api_key"]["configured"] is False


def test_setup_persists_across_reload(monkeypatch):
    for meta in server.SETUP_FIELDS.values():
        monkeypatch.delenv(meta["env"], raising=False)

    client.post(
        "/api/v1/setup",
        json={"values": {"telegram_bot_token": "tok123", "telegram_chat_id": "chat456"}},
        headers=AUTH_HEADERS,
    )
    assert os.path.isfile(server.SETUP_ENV_PATH)

    # Simulate a fresh process start: clear env, then re-run the loader that
    # server.py calls at import time.
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    server._load_setup_env(server.SETUP_ENV_PATH)
    assert os.environ["TELEGRAM_BOT_TOKEN"] == "tok123"
    assert os.environ["TELEGRAM_CHAT_ID"] == "chat456"


def test_setup_empty_value_clears_field(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "will-be-cleared")
    res = client.post(
        "/api/v1/setup",
        json={"values": {"otx_api_key": ""}},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200


# ======================================================================
# RAG API Tests
# ======================================================================


def test_rag_index_endpoint_requires_auth():
    """RAG index endpoint deve richiedere autenticazione."""
    res = client.post("/api/v1/rag/index")
    assert res.status_code == 401


def test_rag_stats_endpoint_public():
    """RAG stats endpoint è pubblico (read-only)."""
    res = client.get("/api/v1/rag/stats")
    assert res.status_code == 200
    data = res.json()
    assert "available" in data
    assert "rag_available" in data


def test_rag_stats_includes_security_score_when_rag_available(monkeypatch):
    """Se RAG è disponibile, lo stats include security_score con coverage."""
    monkeypatch.setattr(
        server, "RAG_AVAILABLE", True
    )
    monkeypatch.setattr(
        server, "rag_indexer",
        _StubIndexer({
            "heimdall_alerts": 5, "fenrir_ioc": 2,
            "mjolnir_triage": 0, "bifrost_scans": 3,
            "forseti_compliance": 1, "sleipnir_playbooks": 2,
        }),
    )
    res = client.get("/api/v1/rag/stats")
    data = res.json()
    assert data["rag_available"] is True
    score = data["security_score"]
    # 5 alert(2) + 2 ioc(2) + 3 scans(2) + 1 compliance(2) + 2 playbooks(1) + rag(1) = 10
    assert score["score"] == 10
    assert score["level"] == "high"
    assert score["coverage"]["hids"] is True
    assert score["coverage"]["soar"] is True


def test_compute_security_score_empty_collections():
    """Nessun dato indicizzato → score ≤1 (solo flag RAG), livello low."""
    score = server._compute_security_score({})
    assert score["score"] <= 1  # nessun dato: al massimo il flag RAG
    assert score["level"] == "low"
    assert score["coverage"]["hids"] is False
    assert score["coverage"]["rag"] == server.RAG_AVAILABLE


def test_compute_security_score_full_coverage(monkeypatch):
    """Tutte le collection popolate → score 9 (9 indicatori × 1 + RAG)."""
    monkeypatch.setattr(server, "RAG_AVAILABLE", True)
    cols = {"heimdall_alerts": 5, "fenrir_ioc": 2, "mjolnir_triage": 1,
            "bifrost_scans": 3, "forseti_compliance": 1, "sleipnir_playbooks": 2}
    score = server._compute_security_score(cols)
    # 2+2+0(triage non conta)+2+2+1+1(rag) = 10
    assert score["score"] == 10
    assert score["level"] == "high"
    assert score["coverage"]["soar"] is True
    assert score["coverage"]["scan"] is True


def test_rag_query_endpoint_requires_auth():
    """RAG query endpoint deve richiedere autenticazione."""
    res = client.post("/api/v1/rag/query", json={"query": "test"})
    assert res.status_code == 401


def test_rag_query_returns_context():
    """RAG query endpoint restituisce contesto anche se vuoto."""
    res = client.post(
        "/api/v1/rag/query",
        json={"query": "test query", "n_results": 3},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "context" in data
    assert "results" in data


def test_rag_index_with_auth():
    """RAG index endpoint con auth risponde correttamente."""
    res = client.post("/api/v1/rag/index", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "results" in data


def test_rag_sessions_endpoint():
    """RAG sessions endpoint restituisce lista sessioni."""
    res = client.get("/api/v1/rag/sessions")
    assert res.status_code == 200
    data = res.json()
    assert "sessions" in data

    assert "OTX_API_KEY" not in os.environ

def test_dashboard_endpoint_serves_html():
    """Dashboard endpoint restituisce HTML valido."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "Asgard RAG Dashboard" in res.text


def test_rag_auto_index_env_parsed():
    """RAG_AUTO_INDEX_MINUTES esiste e viene parsato da env."""
    assert hasattr(server, "RAG_AUTO_INDEX_MINUTES")
    assert isinstance(server.RAG_AUTO_INDEX_MINUTES, int)
    assert server.RAG_AUTO_INDEX_MINUTES >= 0


def test_rag_insights_endpoint_returns_summary():
    """L'endpoint insights restituisce tutte le sezioni dell'analisi proattiva."""
    res = client.get("/api/v1/rag/insights")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    insights = data["insights"]
    for key in ("top_ips", "severity_distribution", "top_ioc",
                "cve_references", "compliance", "playbooks", "generated_at"):
        assert key in insights


def test_chat_proactive_insight_keyword_returns_analysis(monkeypatch):
    """Chat con keyword di riepilogo restituisce l'analisi proattiva senza eseguire moduli."""
    executed = []

    async def _no_exec(module):
        executed.append(module)
        return "SHOULD NOT RUN"

    monkeypatch.setattr(server, "_run_module_raw", _no_exec)
    monkeypatch.setattr(
        server.rag_insights, "format_for_llm",
        lambda: "=== ANALISI PROATTIVA ASGARD ===\nTop IP attaccanti: 192.168.1.100 (5 alert)",
    )

    res = client.post(
        "/api/v1/chat",
        json={"prompt": "dammi un riepilogo della situazione"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    # Nessun modulo è stato eseguito: è solo analisi read-only
    assert executed == []
    output = data["output"]
    assert "ANALISI PROATTIVA ASGARD" in output
    assert "192.168.1.100" in output


def test_chat_incident_prompt_suggests_playbook(monkeypatch):
    """Chat con descrizione di incidente propone il playbook senza eseguire nulla."""
    executed = []

    async def _no_exec(module):
        executed.append(module)
        return "SHOULD NOT RUN"

    monkeypatch.setattr(server, "_run_module_raw", _no_exec)
    monkeypatch.setattr(
        server.rag_insights, "suggest_playbook",
        lambda text, min_similarity=0.4: {
            "playbook": "ransomware_containment.yaml",
            "similarity": 0.82,
            "description": "Contenimento infezione ransomware...",
        },
    )

    res = client.post(
        "/api/v1/chat",
        json={"prompt": "ho subito un attacco ransomware, i file sono cifrati"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "playbook_suggested"
    assert data["suggested_playbook"]["playbook"] == "ransomware_containment.yaml"
    # Nessun modulo eseguito: il suggerimento è read-only
    assert executed == []
    assert "nessuna azione è stata eseguita" in data["output"]


def test_chat_incident_without_matching_playbook_falls_through(monkeypatch):
    """Se nessun playbook supera la soglia, il chat prosegue con il flusso normale."""
    executed = []

    async def _no_exec(module):
        executed.append(module)
        return "SHOULD NOT RUN"

    monkeypatch.setattr(server, "_run_module_raw", _no_exec)
    monkeypatch.setattr(
        server.rag_insights, "suggest_playbook",
        lambda text, min_similarity=0.4: None,
    )

    res = client.post(
        "/api/v1/chat",
        json={"prompt": "raccontami di un attacco famoso"},
        headers=AUTH_HEADERS,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert executed == []


# ======================================================================
# Report Exporter API
# ======================================================================


def test_rag_report_endpoint_requires_auth():
    """Il report contiene IP e IOC: richiede autenticazione."""
    res = client.get("/api/v1/rag/report")
    assert res.status_code == 401


def test_rag_report_endpoint_returns_markdown(monkeypatch):
    """Con auth il report Markdown è generato correttamente."""
    monkeypatch.setattr(
        server.rag_insights, "summary",
        lambda: {
            "top_ips": [{"ip": "10.0.0.99", "count": 3, "max_severity": "CRITICAL"}],
            "severity_distribution": {"CRITICAL": 3},
            "top_ioc": [{"value": "evil.com", "count": 2, "source": "fenrir"}],
            "cve_references": [],
            "compliance": {"assessment_files": 0, "files": []},
            "playbooks": [],
            "generated_at": "2026-01-15T10:00:00",
        },
    )
    res = client.get("/api/v1/rag/report", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["format"] == "markdown"
    assert "Report Proattivo" in data["report"]
    assert "10.0.0.99" in data["report"]
    assert "Raccomandazioni" in data["report"]


def test_rag_report_endpoint_no_save_by_default(monkeypatch):
    """Il report non salva file su disco a meno che save=true."""
    called = {"save": False}

    def _fake_save():
        called["save"] = True
        return "/tmp/should-not-be-called.md"

    monkeypatch.setattr(
        server.rag_insights, "summary",
        lambda: {"top_ips": [], "severity_distribution": {}, "top_ioc": [],
                 "cve_references": [], "compliance": {"assessment_files": 0, "files": []},
                 "playbooks": [], "generated_at": "2026-01-15T10:00:00"},
    )
    from rag.report import ReportExporter
    monkeypatch.setattr(ReportExporter, "save", lambda self: _fake_save())

    res = client.get("/api/v1/rag/report", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert "saved_to" not in res.json()
    assert called["save"] is False


# ======================================================================
# Security Audit API
# ======================================================================


def test_rag_security_audit_endpoint_available():
    """L'endpoint restituisce il report di sicurezza."""
    res = client.get("/api/v1/rag/security/audit", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "audit" in data
    assert "score" in data["audit"]
    assert "grade" in data["audit"]
    assert "findings" in data["audit"]


def test_rag_security_audit_markdown_format():
    """Il formato Markdown è disponibile."""
    res = client.get("/api/v1/rag/security/report", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["format"] == "markdown"
    assert "Security Audit Report" in data["report"]


def test_rag_security_audit_findings_structure():
    """I findings hanno la struttura corretta."""
    res = client.get("/api/v1/rag/security/audit", headers=AUTH_HEADERS)
    data = res.json()
    for f in data["audit"]["findings"]:
        assert "severity" in f
        assert "category" in f
        assert "title" in f
        assert "recommendation" in f


# ======================================================================
# PDF Report API
# ======================================================================


def test_rag_report_pdf_requires_auth():
    """Il PDF contiene IP e IOC: richiede autenticazione."""
    res = client.get("/api/v1/rag/report/pdf")
    assert res.status_code == 401


def test_rag_report_pdf_returns_pdf(monkeypatch):
    """Con auth il PDF è generato e restituito come file."""
    monkeypatch.setattr(
        server.rag_insights, "summary",
        lambda: {
            "top_ips": [{"ip": "10.0.0.99", "count": 3, "max_severity": "CRITICAL"}],
            "severity_distribution": {"CRITICAL": 3},
            "top_ioc": [],
            "cve_references": [],
            "compliance": {"assessment_files": 0, "files": []},
            "playbooks": [],
            "generated_at": "2026-01-15T10:00:00",
        },
    )
    res = client.get("/api/v1/rag/report/pdf", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert len(res.content) > 0


# ======================================================================
# Security History API
# ======================================================================


def test_rag_security_history_endpoint():
    """Lo storico security score è disponibile."""
    res = client.get("/api/v1/rag/security/history")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert "history" in data


def test_rag_security_trend_endpoint():
    """Il trend security score è disponibile."""
    res = client.get("/api/v1/rag/security/trend")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert "trend" in data


def test_rag_security_record_requires_auth():
    """Registrare uno score richiede auth."""
    res = client.post("/api/v1/rag/security/record")
    assert res.status_code == 401


# ======================================================================
# Anomaly watcher (push WebSocket in tempo reale)
# ======================================================================


def test_anomaly_watch_disabled_when_zero(monkeypatch):
    """Con RAG_ANOMALY_WATCH_MINUTES=0 il watcher non fa alcun lavoro."""
    import server as srv
    monkeypatch.setattr(srv, "RAG_ANOMALY_WATCH_MINUTES", 0)
    calls = {"summary": 0}

    def _fake_summary(days=30):
        calls["summary"] += 1
        return {"anomalies": [], "severity_anomalies": []}

    monkeypatch.setattr(srv.rag_timeline, "summary", _fake_summary)
    srv._anomaly_watch_if_due()
    assert calls["summary"] == 0


def test_anomaly_watch_pushes_new_anomalies_once(monkeypatch):
    """Spike nuovo → evento WebSocket; stessa data di nuovo → nessun duplicato."""
    import server as srv
    import asyncio

    monkeypatch.setattr(srv, "RAG_ANOMALY_WATCH_MINUTES", 15)
    events = []

    async def fake_broadcast(event):
        events.append(event)

    monkeypatch.setattr(srv.telemetry, "broadcast", fake_broadcast)
    summary = {
        "anomalies": [{"date": "2026-02-01", "count": 30, "avg_baseline": 2.0,
                       "by_severity": {"CRITICAL": 30}}],
        "severity_anomalies": [],
        "trend": "up",
    }
    monkeypatch.setattr(srv.rag_timeline, "summary", lambda days=30: summary)
    srv._NOTIFIED_ANOMALY_DATES.clear()
    srv._LAST_ANOMALY_CHECK["ts"] = 0.0
    srv._LAST_ANOMALY_CHECK["running"] = False

    async def once():
        srv._anomaly_watch_if_due()
        await asyncio.sleep(0.01)  # lascia eseguire il task di broadcast

    asyncio.run(once())
    assert len(events) == 1
    assert events[0]["type"] == "rag_anomaly_detected"
    assert events[0]["anomalies"][0]["date"] == "2026-02-01"
    assert events[0]["trend"] == "up"

    # seconda esecuzione: stessa data già notificata → nessun duplicato
    srv._LAST_ANOMALY_CHECK["ts"] = 0.0
    asyncio.run(once())
    assert len(events) == 1


def test_anomaly_watch_no_anomalies_no_event(monkeypatch):
    """Nessuno spike → nessun evento broadcast."""
    import server as srv
    import asyncio

    monkeypatch.setattr(srv, "RAG_ANOMALY_WATCH_MINUTES", 15)
    events = []

    async def fake_broadcast(event):
        events.append(event)

    monkeypatch.setattr(srv.telemetry, "broadcast", fake_broadcast)
    monkeypatch.setattr(
        srv.rag_timeline, "summary",
        lambda days=30: {"anomalies": [], "severity_anomalies": [], "trend": "flat"},
    )
    srv._NOTIFIED_ANOMALY_DATES.clear()
    srv._LAST_ANOMALY_CHECK["ts"] = 0.0
    srv._LAST_ANOMALY_CHECK["running"] = False

    async def run_check():
        srv._anomaly_watch_if_due()
        await asyncio.sleep(0.01)

    asyncio.run(run_check())
    assert events == []


# ----------------------------------------------------------------------
# Report sender programmato (RAG_REPORT_SEND_MINUTES)
# ----------------------------------------------------------------------


def test_report_send_disabled_when_zero(monkeypatch):
    """Con RAG_REPORT_SEND_MINUTES=0 lo scheduler non invia alcun report."""
    import server as srv
    import rag.dispatch as dispatch
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_MINUTES", 0)
    calls = {"send": 0}

    def _fake(engine=None, **kw):
        calls["send"] += 1
        return {"sent": True, "configured": True}

    monkeypatch.setattr(dispatch, "send_report", _fake)
    srv._LAST_REPORT_SEND["ts"] = 0.0
    srv._LAST_REPORT_SEND["running"] = False
    srv._report_send_if_due()
    assert calls["send"] == 0


def test_report_send_runs_once_and_timers_release(monkeypatch):
    """Con RAG_REPORT_SEND_MINUTES>0 e timer scaduto send_report parte una volta
    e il flag running torna a False (nessuna concorrenza residua)."""
    import server as srv
    import rag.dispatch as dispatch
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_MINUTES", 30)
    calls = {"send": 0}

    def _fake(engine=None, **kw):
        calls["send"] += 1
        return {"sent": False, "configured": False, "severity": None,
                "message": "noop"}

    monkeypatch.setattr(dispatch, "send_report", _fake)
    # Gjallarhorn non configurato → il server non deve lanciare, solo no-op.
    srv._LAST_REPORT_SEND["ts"] = 0.0
    srv._LAST_REPORT_SEND["running"] = False
    srv._report_send_if_due()
    assert calls["send"] == 1
    assert srv._LAST_REPORT_SEND["ts"] > 0.0      # timer aggiornato
    assert srv._LAST_REPORT_SEND["running"] is False  # rilascio

    # seconda esecuzione subito dopo: timer non scaduto → nessun secondo invio
    srv._report_send_if_due()
    assert calls["send"] == 1


def test_report_send_noop_without_engine(monkeypatch):
    """Senza RAG disponibile lo scheduler non fa nulla (nessun crash)."""
    import server as srv
    import rag.dispatch as dispatch
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_MINUTES", 60)
    calls = {"send": 0}

    def _fake(engine=None, **kw):
        calls["send"] += 1
        return {"sent": True, "configured": True}

    monkeypatch.setattr(dispatch, "send_report", _fake)
    monkeypatch.setattr(srv, "RAG_AVAILABLE", False)
    srv._LAST_REPORT_SEND["ts"] = 0.0
    srv._LAST_REPORT_SEND["running"] = False
    srv._report_send_if_due()
    assert calls["send"] == 0


def test_report_send_cron_parses_valid_time(monkeypatch):
    """RAG_REPORT_SEND_CRON valido → restituisce (hh,mm)."""
    import server as srv
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_CRON", "08:30")
    assert srv._report_send_cron_parsed() == (8, 30)


def test_report_send_cron_invalid_returns_none(monkeypatch):
    """CRON malformato o fuori range → None (mai crash)."""
    import server as srv
    for bad in ["", "8", "25:00", "08:60", "abc", "08:xx"]:
        monkeypatch.setattr(srv, "RAG_REPORT_SEND_CRON", bad)
        assert srv._report_send_cron_parsed() is None, bad


def test_report_send_cron_due_logic(monkeypatch):
    """CRON: dovuto dopo l'orario target, non-dovuto prima, non-duplicato il giorno."""
    import server as srv
    import time as _time
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_CRON", "08:00")
    srv._LAST_REPORT_CRON_DAY = ""  # reset: nessun giorno già inviato

    early = _time.mktime(_time.strptime("2026-03-02 07:00:00", "%Y-%m-%d %H:%M:%S"))
    late = _time.mktime(_time.strptime("2026-03-02 09:00:00", "%Y-%m-%d %H:%M:%S"))
    assert srv._report_send_cron_due(early) is False  # prima delle 08:00
    assert srv._report_send_cron_due(late) is True    # dopo le 08:00

    # giŕ inviato oggi → non piů dovuto (anti-duplicato)
    srv._LAST_REPORT_CRON_DAY = "2026-03-02"
    assert srv._report_send_cron_due(late) is False


def test_report_send_cron_no_duplicate_same_day(monkeypatch):
    """Stesso giorno marcato → il cron non invia di nuovo."""
    import server as srv
    import rag.dispatch as dispatch
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_MINUTES", 0)
    monkeypatch.setattr(srv, "RAG_REPORT_SEND_CRON", "00:00")  # sempre dovuto
    calls = {"send": 0}

    def _fake(engine=None, **kw):
        calls["send"] += 1
        return {"sent": False, "configured": False, "severity": None,
                "message": "noop"}

    monkeypatch.setattr(dispatch, "send_report", _fake)
    srv._LAST_REPORT_CRON_DAY = _time_now("%Y-%m-%d")
    srv._LAST_REPORT_SEND["ts"] = 0.0
    srv._LAST_REPORT_SEND["running"] = False
    srv._report_send_if_due()
    assert calls["send"] == 0


def _time_now(fmt):
    import time
    return time.strftime(fmt)


def test_rag_timeline_endpoint_spike_params_clamped(monkeypatch):
    """API: spike_factor/min_spike fuori range sono limitati a intervalli sicuri."""
    captured = {}

    def _fake_summary(self, days=30, spike_factor=3.0, min_spike=3):
        captured["spike_factor"] = spike_factor
        captured["min_spike"] = min_spike
        return {"series": [], "total": 0}

    from rag.timeline import TimelineEngine
    monkeypatch.setattr(TimelineEngine, "summary", _fake_summary)
    # fuori range in entrambe le direzioni
    res = client.get("/api/v1/rag/timeline?spike_factor=999&min_spike=999")
    assert res.status_code == 200
    assert captured["spike_factor"] == 10.0
    assert captured["min_spike"] == 50
    res = client.get("/api/v1/rag/timeline?spike_factor=0.1&min_spike=0")
    assert res.status_code == 200
    assert captured["spike_factor"] == 1.5
    assert captured["min_spike"] == 1
    # valori di default invariati
    res = client.get("/api/v1/rag/timeline")
    assert res.status_code == 200

# ======================================================================
# Agenti specializzati (RAG routing)
# ======================================================================


def test_rag_agents_endpoint_lists_six():
    """/api/v1/rag/agents pubblica elenca i 6 agenti di dominio."""
    res = client.get("/api/v1/rag/agents")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    assert len(data["agents"]) == 6
    assert {a["name"] for a in data["agents"]} == {
        "heimdall_agent", "fenrir_agent", "bifrost_agent",
        "forseti_agent", "mjolnir_agent", "sleipnir_agent",
    }


def test_rag_agents_ask_requires_auth():
    """/api/v1/rag/agents/ask è read-only ma comunque protetto da auth."""
    res = client.post("/api/v1/rag/agents/ask", json={"prompt": "alert brute force"})
    assert res.status_code == 401


def test_rag_agents_ask_routes_and_answers(monkeypatch):
    """Prompt di dominio → risposta dell'agente con riferimenti."""
    monkeypatch.setattr(
        server.rag_agents, "answer",
        lambda prompt, n_results=5: {
            "routed": True,
            "agent": {"name": "heimdall_agent", "module": "heimdall",
                      "description": "Alert e blocchi IP"},
            "context": "=== AGENTE HEIMDALL_AGENT (HEIMDALL) ===\nAlert: SSH Brute Force",
            "references": [{"text": "Alert: SSH Brute Force",
                            "metadata": {"source": "heimdall"}, "similarity": 0.8}],
        },
    )
    res = client.post("/api/v1/rag/agents/ask",
                      json={"prompt": "alert brute force", "n_results": 3},
                      headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["agent"]["name"] == "heimdall_agent"
    assert len(data["references"]) == 1


def test_rag_agents_ask_generic_prompt_no_route(monkeypatch):
    """Prompt fuori dominio → 404 con dettaglio esplicativo (semantica REST)."""
    monkeypatch.setattr(server.rag_agents, "answer", lambda prompt, n_results=5: {
        "routed": False, "agent": None, "references": [],
        "context": "Nessun agente di dominio per questo prompt.",
    })
    res = client.post("/api/v1/rag/agents/ask",
                      json={"prompt": "come stai?"},
                      headers=AUTH_HEADERS)
    assert res.status_code == 404
    assert "Nessun agente competente" in res.json()["detail"]


# ======================================================================
# Timeline API
# ======================================================================


def test_rag_timeline_endpoint_returns_series(monkeypatch):
    """L'endpoint restituisce la serie giornaliera con il numero di giorni richiesto."""
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%dT12:00:00")
    monkeypatch.setattr(
        server.rag_insights, "_all_metadatas",
        lambda collection_name: [
            {"timestamp": today, "severity": "HIGH", "source_ip": "10.0.0.1"},
            {"timestamp": today, "severity": "CRITICAL", "source_ip": "10.0.0.2"},
        ],
    )
    res = client.get("/api/v1/rag/timeline?days=7")
    assert res.status_code == 200
    data = res.json()
    assert data["available"] is True
    t = data["timeline"]
    assert len(t["series"]) == 7
    assert t["total"] == 2
    assert t["series"][-1]["count"] == 2
    assert t["series"][-1]["by_severity"]["HIGH"] == 1
    assert t["series"][-1]["by_severity"]["CRITICAL"] == 1


def test_rag_timeline_endpoint_empty_index(monkeypatch):
    """Indice vuoto → serie tutta zeri, trend flat, nessun crash."""
    monkeypatch.setattr(
        server.rag_insights, "_all_metadatas",
        lambda collection_name: [],
    )
    res = client.get("/api/v1/rag/timeline")
    assert res.status_code == 200
    t = res.json()["timeline"]
    assert t["total"] == 0
    assert all(d["count"] == 0 for d in t["series"])
    assert t["trend"]["direction"] == "flat"


def test_rag_timeline_endpoint_invalid_days_clamped(monkeypatch):
    """days fuori range è limitato (1..365) senza errori."""
    monkeypatch.setattr(
        server.rag_insights, "_all_metadatas",
        lambda collection_name: [],
    )
    res = client.get("/api/v1/rag/timeline?days=99999")
    assert res.status_code == 200
    assert len(res.json()["timeline"]["series"]) == 365


def test_rag_timeline_endpoint_includes_severity_anomalies(monkeypatch):
    """Spike di CRITICAL oggi → l'endpoint lo espone in severity_anomalies."""
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%dT12:00:00")
    monkeypatch.setattr(
        server.rag_insights, "_all_metadatas",
        lambda collection_name: [
            {"timestamp": today, "severity": "CRITICAL", "source_ip": "10.0.0.1"},
            {"timestamp": today, "severity": "CRITICAL", "source_ip": "10.0.0.2"},
            {"timestamp": today, "severity": "CRITICAL", "source_ip": "10.0.0.3"},
        ],
    )
    res = client.get("/api/v1/rag/timeline?days=7")
    assert res.status_code == 200
    t = res.json()["timeline"]
    assert len(t["severity_anomalies"]) == 1
    a = t["severity_anomalies"][0]
    assert a["severity"] == "CRITICAL"
    assert a["count"] == 3
    assert a["date"] == today[:10]


def test_rag_timeline_export_requires_auth():
    """Il CSV espone il profilo di attacco: richiede autenticazione."""
    res = client.get("/api/v1/rag/timeline/export")
    assert res.status_code == 401


def test_rag_timeline_export_returns_csv(monkeypatch):
    """L'export CSV ha header corretti, intestazioni e righe per giorno."""
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%dT12:00:00")
    monkeypatch.setattr(
        server.rag_insights, "_all_metadatas",
        lambda collection_name: [{"timestamp": today, "severity": "HIGH"}],
    )
    res = client.get("/api/v1/rag/timeline/export?days=7", headers=AUTH_HEADERS)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    assert "attachment" in res.headers["content-disposition"]
    lines = res.text.strip().splitlines()
    assert lines[0] == "date,count,low,medium,high,critical"
    assert len(lines) == 8  # header + 7 giorni
    last = lines[-1].split(",")
    assert last[0] == datetime.now().strftime("%Y-%m-%d")
    assert last[1] == "1"
    assert last[4] == "1"  # HIGH


def test_rag_timeline_notify_requires_auth():
    """L'invio dell'alert anomalie richiede autenticazione."""
    res = client.post("/api/v1/rag/timeline/notify")
    assert res.status_code == 401


def test_rag_timeline_notify_not_configured_is_inert(monkeypatch):
    """Senza Gjallarhorn configurato → esito inerte, nessuna rete."""
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    res = client.post("/api/v1/rag/timeline/notify", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["sent"] is False
    assert data["configured"] is False


# ======================================================================
# Dispatch Gjallarhorn API
# ======================================================================


def test_rag_report_notify_requires_auth():
    """L'invio del digest richiede autenticazione."""
    res = client.post("/api/v1/rag/report/notify")
    assert res.status_code == 401


def test_rag_report_notify_not_configured_is_inert(monkeypatch):
    """Hub non configurato → sent=false, configured=false, nessun errore."""
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    res = client.post("/api/v1/rag/report/notify", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["sent"] is False
    assert data["configured"] is False


def test_rag_report_notify_sends_digest(monkeypatch):
    """Hub configurato → il digest viene inviato con la severità derivata."""
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    monkeypatch.setattr(
        server.rag_insights, "summary",
        lambda: {
            "top_ips": [{"ip": "10.0.0.50", "count": 1, "max_severity": "CRITICAL"}],
            "severity_distribution": {"CRITICAL": 1},
            "top_ioc": [], "cve_references": [],
            "compliance": {"assessment_files": 0, "files": []},
            "playbooks": [],
            "generated_at": "2026-01-15T10:00:00",
        },
    )
    calls = {}

    def fake_notify(**kwargs):
        calls.update(kwargs)
        return True

    monkeypatch.setattr("rag.notifier.notify", fake_notify)
    res = client.post("/api/v1/rag/report/notify", headers=AUTH_HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert data["sent"] is True
    assert data["configured"] is True
    assert data["severity"] == "critical"
    assert calls["source"] == "Ragnarok"
    assert "10.0.0.50" in calls["message"]


# ======================================================================
# GDPR Compliance API
# ======================================================================


def test_gdpr_checklist_endpoint():
    """Endpoint checklist GDPR: 10 item con principio e peso."""
    res = client.get("/api/v1/rag/gdpr/checklist")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert len(data["checklist"]) == 10
    assert all("principio" in item and "peso" in item for item in data["checklist"])


def test_gdpr_evaluate_endpoint_all_yes():
    """Endpoint evaluate: tutte sì → 100% ottimo."""
    res = client.post("/api/v1/rag/gdpr/evaluate", json={
        "data_inventory": True, "consent_management": True, "data_minimization": True,
        "retention_policy": True, "security_measures": True, "breach_notification": True,
        "dpo_appointed": True, "privacy_by_design": True, "data_subject_rights": True, "dpia": True
    })
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["evaluation"]["percentage"] == 100
    assert data["evaluation"]["level"] == "ottimo"


def test_gdpr_evaluate_endpoint_all_no():
    """Endpoint evaluate: tutte no → 0% critico."""
    res = client.post("/api/v1/rag/gdpr/evaluate", json={
        "data_inventory": False, "consent_management": False, "data_minimization": False,
        "retention_policy": False, "security_measures": False, "breach_notification": False,
        "dpo_appointed": False, "privacy_by_design": False, "data_subject_rights": False, "dpia": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data["evaluation"]["percentage"] == 0
    assert data["evaluation"]["level"] == "critico"


def test_gdpr_recommend_endpoint_micro():
    """Endpoint recommend: micro-impresa → agenti essenziali."""
    res = client.get("/api/v1/rag/gdpr/recommend?company_size=micro")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "heimdall_agent" in data["recommendation"]["recommended_agents"]
    assert "forseti_agent" in data["recommendation"]["recommended_agents"]


def test_gdpr_recommend_endpoint_healthcare():
    """Endpoint recommend: settore sanitario → aggiunge agenti."""
    res = client.get("/api/v1/rag/gdpr/recommend?company_size=small&sector=sanita")
    assert res.status_code == 200
    data = res.json()
    assert "fenrir_agent" in data["recommendation"]["recommended_agents"]
    assert "bifrost_agent" in data["recommendation"]["recommended_agents"]


def test_gdpr_recommend_endpoint_maturity_base():
    """Endpoint recommend: maturità base → Sleipnir opzionale."""
    res = client.get("/api/v1/rag/gdpr/recommend?company_size=medium&maturity=base")
    assert res.status_code == 200
    data = res.json()
    assert "sleipnir_agent" not in data["recommendation"]["recommended_agents"]
    assert "sleipnir_agent" in data["recommendation"]["optional_agents"]


def test_gdpr_recommend_endpoint_unknown_size_defaults():
    """Endpoint recommend: dimensione sconosciuta → fallback small."""
    res = client.get("/api/v1/rag/gdpr/recommend?company_size=gigante")
    assert res.status_code == 200
    data = res.json()
    assert "heimdall_agent" in data["recommendation"]["recommended_agents"]


# ----------------------------------------------------------------------
# Auth & RBAC tests
# ----------------------------------------------------------------------

import auth as _auth_mod
from auth import check_user, create_session, validate_session, destroy_session
from auth import list_users, create_user, set_user_role, deactivate_user

# Create deterministic test users (default admin has random password)
_test_users = {
    "analyst": _auth_mod.create_user("analyst_test", "analyst_pass", "analyst"),
    "viewer": _auth_mod.create_user("viewer_test", "viewer_pass", "viewer"),
    "admin": _auth_mod.create_user("admin_test", "admin_pass", "admin"),
}


def _login(username, password):
    res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["token"]


def _auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_success():
    for uname in _test_users:
        res = client.post("/api/v1/auth/login", json={"username": f"{uname}_test", "password": f"{uname}_pass"})
        assert res.status_code == 200
        data = res.json()
        assert "token" in data
        assert data["user"]["username"] == f"{uname}_test"
        assert data["user"]["role"] == uname


def test_login_invalid_password():
    res = client.post("/api/v1/auth/login", json={"username": "analyst_test", "password": "wrong"})
    assert res.status_code == 401


def test_login_unknown_user():
    res = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "whatever"})
    assert res.status_code == 401


def test_auth_me_with_valid_token():
    token = _login("analyst_test", "analyst_pass")
    res = client.get("/api/v1/auth/me", headers=_auth_headers(token))
    assert res.status_code == 200
    assert res.json()["user"]["username"] == "analyst_test"


def test_auth_me_without_token():
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401


def test_auth_me_with_invalid_token():
    res = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
    assert res.status_code == 401


def test_logout_invalidates_token():
    token = _login("viewer_test", "viewer_pass")
    res = client.post("/api/v1/auth/logout", headers=_auth_headers(token))
    assert res.status_code == 200
    res = client.get("/api/v1/auth/me", headers=_auth_headers(token))
    assert res.status_code == 401


def test_rbac_viewer_can_query():
    """Viewer can access read endpoints like /api/v1/rag/query."""
    token = _login("viewer_test", "viewer_pass")
    headers = _auth_headers(token)
    res = client.post("/api/v1/rag/query", json={"query": "test"}, headers=headers)
    # RAG may not be available, but auth should pass (not 401)
    assert res.status_code != 401


def test_rbac_viewer_cannot_execute():
    """Viewer cannot execute modules (admin-only)."""
    token = _login("viewer_test", "viewer_pass")
    headers = _auth_headers(token)
    res = client.post("/api/v1/execute", json={"module": "heimdall", "action": "status"}, headers=headers)
    assert res.status_code == 401


def test_rbac_analyst_cannot_execute():
    """Analyst cannot execute modules (admin-only)."""
    token = _login("analyst_test", "analyst_pass")
    headers = _auth_headers(token)
    res = client.post("/api/v1/execute", json={"module": "heimdall", "action": "status"}, headers=headers)
    assert res.status_code == 401


def test_rbac_admin_can_execute():
    """Admin can execute modules (auth passes; module may fail but not 401)."""
    token = _login("admin_test", "admin_pass")
    headers = _auth_headers(token)
    res = client.post("/api/v1/execute", json={"module": "heimdall", "action": "status"}, headers=headers)
    # Auth should pass — status may be 200 (success/error) but NOT 401
    assert res.status_code != 401


def test_rbac_viewer_cannot_view_audit_log():
    """Audit log is admin-only."""
    token = _login("viewer_test", "viewer_pass")
    headers = _auth_headers(token)
    res = client.get("/api/v1/audit-log", headers=headers)
    assert res.status_code == 401


def test_rbac_admin_can_view_audit_log():
    """Admin can view audit log."""
    token = _login("admin_test", "admin_pass")
    headers = _auth_headers(token)
    res = client.get("/api/v1/audit-log", headers=headers)
    assert res.status_code == 200


def test_user_management_requires_admin():
    """Only admin can list/create users."""
    # Viewer cannot list users
    token = _login("viewer_test", "viewer_pass")
    res = client.get("/api/v1/auth/users", headers=_auth_headers(token))
    assert res.status_code == 401

    # Analyst cannot create users
    token = _login("analyst_test", "analyst_pass")
    res = client.post("/api/v1/auth/users", json={"username": "newbie", "password": "pass123", "role": "viewer"}, headers=_auth_headers(token))
    assert res.status_code == 401


def test_admin_can_create_and_list_users():
    """Admin can create a user and see it in the list."""
    token = _login("admin_test", "admin_pass")
    headers = _auth_headers(token)

    res = client.post("/api/v1/auth/users", json={"username": "new_user", "password": "new_pass", "role": "analyst"}, headers=headers)
    assert res.status_code == 200
    assert res.json()["username"] == "new_user"

    res = client.get("/api/v1/auth/users", headers=headers)
    assert res.status_code == 200
    usernames = [u["username"] for u in res.json()["users"]]
    assert "new_user" in usernames


def test_admin_can_deactivate_user():
    """Admin can deactivate a user; deactivated user cannot login."""
    token = _login("admin_test", "admin_pass")
    headers = _auth_headers(token)

    # Create a user to deactivate
    res = client.post("/api/v1/auth/users", json={"username": "to_deactivate", "password": "pass", "role": "viewer"}, headers=headers)
    uid = res.json()["id"]

    # Deactivate
    res = client.delete(f"/api/v1/auth/users/{uid}", headers=headers)
    assert res.status_code == 200

    # Cannot login anymore
    res = client.post("/api/v1/auth/login", json={"username": "to_deactivate", "password": "pass"})
    assert res.status_code == 401


def test_api_key_still_works_for_admin_endpoints():
    """Backward compat: X-API-Key still works on admin-only endpoints."""
    res = client.get("/api/v1/audit-log", headers=AUTH_HEADERS)
    assert res.status_code == 200


def test_create_user_invalid_role():
    """Creating a user with an invalid role returns 400."""
    token = _login("admin_test", "admin_pass")
    headers = _auth_headers(token)
    res = client.post("/api/v1/auth/users", json={"username": "badrole", "password": "pass", "role": "superadmin"}, headers=headers)
    assert res.status_code == 400


def test_password_hashing_is_safe():
    """Verify password hashing produces salt:hash format and verifies correctly."""
    from auth import _hash_password, _verify_password
    h = _hash_password("mypassword")
    assert ":" in h
    assert _verify_password("mypassword", h) is True
    assert _verify_password("wrongpassword", h) is False

