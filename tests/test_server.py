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

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND_DIR))

from fastapi.testclient import TestClient  # noqa: E402
import server  # noqa: E402

client = TestClient(server.app)
AUTH_HEADERS = {"X-API-Key": "test-key-for-pytest"}


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
    assert "OTX_API_KEY" not in os.environ
