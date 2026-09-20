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

os.environ.setdefault("RAGNAROK_API_KEY", "test-key-for-pytest")
# Keep the anomaly watcher inert during API tests so no WebSocket noise
# leaks into unrelated tests (dedicated watcher tests enable it explicitly).
os.environ.setdefault("RAG_ANOMALY_WATCH_MINUTES", "0")
