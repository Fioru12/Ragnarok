"""Root pytest fixtures — loaded before any test module is imported.

Both suites (tests/ and backend/tests/) import backend/server.py at module
scope, and server.py reads RAGNAROK_API_KEY / scheduler env vars AT IMPORT
TIME (generating a random API key when unset). Without this file, whichever
suite happens to import server first decides the key, and the other suite
sees spurious 401s — the reason CI runs the suites as separate invocations.

Setting deterministic defaults here makes combined runs (`pytest tests/
backend/tests/`) behave the same as isolated runs. Individual test modules
may still override via os.environ.setdefault (no-op when already set) or
monkeypatch for per-test isolation.
"""
import os
import tempfile

os.environ.setdefault("RAGNAROK_API_KEY", "test-key-for-pytest")
# Keep the anomaly watcher inert during API tests so no WebSocket noise
# leaks into unrelated tests (dedicated watcher tests enable it explicitly).
os.environ.setdefault("RAG_ANOMALY_WATCH_MINUTES", "0")


def _ensure_temp_path(env_name: str, prefix: str, suffix: str) -> str:
    """Point env_name at an isolated temp file unless already set.

    server.py / auth.py resolve their sqlite paths AT IMPORT TIME, so the
    first test module that imports them decides which database the whole
    session uses. Without this, test_e2e.py (which sets no DB env) binds
    auth to the real backend/ragnarok_auth.db and test_server.py's
    import-time create_user() calls then leak test users into the dev DB —
    while tests asserting on the isolated DB see an empty one, depending on
    import order and cwd. Setting deterministic isolated defaults here (this
    file loads before any test module) makes all invocation styles behave
    the same. Explicitly exported env vars are always honored.
    """
    existing = os.getenv(env_name)
    if existing:
        return existing
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(fd)
    os.environ[env_name] = path
    return path


_ensure_temp_path("RAGNAROK_AUTH_DB_PATH", "ragnarok_auth_test_", ".db")
os.environ.setdefault("RAGNAROK_AUTH_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("RAGNAROK_SESSION_TTL", "3600")
_ensure_temp_path("RAGNAROK_AUDIT_DB_PATH", "ragnarok_audit_test_", ".db")

# Same for the setup wizard's persisted env file: never touch a real one.
_setup_path = _ensure_temp_path("RAGNAROK_SETUP_ENV_PATH", "ragnarok_setup_test_", ".env")
try:
    os.remove(_setup_path)  # start absent, as a fresh install would be
except OSError:
    pass
