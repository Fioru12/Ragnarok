"""Ops endpoints — backup/restore, audit log, status, health and metrics.

Moved out of server.py to keep the orchestrator lean. Handlers are verbatim
copies of the originals; server-owned state (record_audit_event,
AUDIT_DB_PATH, MODULE_STATUS, START_TIME, EXEC_COUNTER, _START_TIME,
_get_modules, RAG_AVAILABLE, rag_indexer, _check_module_health) is imported
lazily *inside* each handler — the same deferred-import pattern server.py
itself already uses — so there is no import cycle at load time, and tests
monkeypatching server.* keep working. All routes keep their exact paths.
"""
import json
import os
import sqlite3
import subprocess
import sys
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from auth import require_role

router = APIRouter(tags=["ops"])


# --- Backup & restore (admin only) ---

class RestoreRequest(BaseModel):
    backup_path: str


@router.post("/api/v1/backup")
def api_create_backup(user: dict = Depends(require_role("admin"))):
    """Create a verified backup archive of all persistent state."""
    import backup as backup_mod
    from server import record_audit_event
    try:
        result = backup_mod.create_backup()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")
    record_audit_event({"type": "backup_create", "user": user["username"], "file": result["path"]})
    return result


@router.post("/api/v1/backup/verify")
def api_verify_backup(req: RestoreRequest, user: dict = Depends(require_role("admin"))):
    """Verify a backup archive against its sha256 manifest."""
    import backup as backup_mod
    try:
        return backup_mod.verify_backup(req.backup_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/v1/backup/restore")
def api_restore_backup(req: RestoreRequest, user: dict = Depends(require_role("admin"))):
    """Verify and restore a backup archive to the live stores."""
    import backup as backup_mod
    from server import record_audit_event
    try:
        result = backup_mod.restore_backup(req.backup_path)
    except Exception as e:
        record_audit_event({"type": "backup_restore", "user": user["username"], "success": False, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))
    record_audit_event({"type": "backup_restore", "user": user["username"], "success": True, "file": req.backup_path})
    return result


@router.get("/api/v1/audit-log")
def get_audit_log(limit: int = 50, offset: int = 0, user: dict = Depends(require_role("admin"))):
    from server import AUDIT_DB_PATH
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    conn = sqlite3.connect(AUDIT_DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, timestamp, type, payload FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM events")
        total = cur.fetchone()[0]
    finally:
        conn.close()

    events = []
    for row_id, ts, ev_type, payload in rows:
        try:
            parsed_payload = json.loads(payload) if payload else None
        except (TypeError, ValueError):
            parsed_payload = None
        events.append({"id": row_id, "timestamp": ts, "type": ev_type, "payload": parsed_payload})

    return {"events": events, "total": total, "limit": limit, "offset": offset}


@router.get("/api/v1/status")
async def get_status():
    """Module health overview (public, cached 30s per module).

    Moved verbatim from server.py; server-owned MODULE_STATUS/START_TIME/
    EXEC_COUNTER/_check_module_health are imported lazily (same pattern as
    the backup handlers above), so mutations still hit the same objects.
    """
    import time as _time

    from server import MODULE_STATUS, START_TIME, EXEC_COUNTER, _check_module_health

    now = _time.time()
    for mod_key, info in MODULE_STATUS.items():
        if now - info["last_check"] < 30:
            continue
        result = await _check_module_health(mod_key, info)
        info["healthy"] = result["healthy"]
        info["health_status"] = result["status"]
        info["health_error"] = result["error"]
        info["last_check"] = now

    online = sum(1 for m in MODULE_STATUS.values() if m["healthy"])
    return {
        "status": "online",
        "uptime_seconds": int(_time.time() - START_TIME),
        "modules": {
            k: {
                "name": v["name"],
                "healthy": v["healthy"],
                "health_status": v.get("health_status", "unknown"),
                "health_error": v.get("health_error"),
            }
            for k, v in MODULE_STATUS.items()
        },
        "online_count": online,
        "total_count": len(MODULE_STATUS),
        "executions": EXEC_COUNTER,
    }


@router.get("/health")
def health():
    """Comprehensive health check for Docker/Kubernetes orchestrators.

    Returns:
        200 with component status: overall "healthy" only if ALL components are up.
        503 if any critical component is down (triggers restart in k8s).
    """
    import server as _srv

    now = time.time()
    _start = getattr(_srv, "_START_TIME", None)
    uptime_seconds = int(now - _start) if _start else 0

    components = {}

    # --- Auth DB ---
    try:
        import auth as auth_module
        auth_db_path = getattr(auth_module, 'AUTH_DB_PATH', 'backend/ragnarok_auth.db')
        conn = sqlite3.connect(auth_db_path)
        conn.execute("SELECT 1 FROM users LIMIT 1")
        conn.close()
        components["auth_db"] = {"status": "ok"}
    except Exception as e:
        components["auth_db"] = {"status": "error", "detail": str(e)}

    # --- RAG / ChromaDB ---
    try:
        if _srv.RAG_AVAILABLE and _srv.rag_indexer is not None:
            stats = _srv.rag_indexer.get_stats()
            components["rag"] = {"status": "ok", "documents": stats.get("total_documents", 0)}
        else:
            components["rag"] = {"status": "disabled"}
    except Exception as e:
        components["rag"] = {"status": "error", "detail": str(e)}

    # --- Audit DB ---
    try:
        audit_path = os.environ.get("RAGNAROK_AUDIT_DB_PATH", "backend/ragnarok_audit.db")
        if os.path.exists(audit_path):
            conn = sqlite3.connect(audit_path)
            # Check if DB is readable (table may not exist yet)
            try:
                conn.execute("SELECT 1 FROM audit_log LIMIT 1")
            except Exception:
                pass  # Table may not exist yet, that's OK
            conn.close()
            components["audit_db"] = {"status": "ok"}
        else:
            components["audit_db"] = {"status": "ok", "note": "no audit records yet"}
    except Exception as e:
        components["audit_db"] = {"status": "error", "detail": str(e)}

    # --- Modules (real check via --help) ---
    module_status = {}
    for mod_key, info in _srv._get_modules().items():
        try:
            proc = subprocess.run(
                [sys.executable, info["path"], "--help"],
                capture_output=True, timeout=10
            )
            module_status[mod_key] = "ok" if proc.returncode == 0 else "unhealthy"
        except Exception:
            module_status[mod_key] = "unreachable"
    components["modules"] = module_status

    # --- Overall status ---
    critical = ["auth_db", "audit_db"]
    overall = "healthy"
    for c in critical:
        if components.get(c, {}).get("status") == "error":
            overall = "degraded"
            break

    status_code = 200 if overall == "healthy" else 503

    return Response(
        content=json.dumps({
            "status": overall,
            "version": "1.0.0",
            "uptime_seconds": uptime_seconds,
            "components": components,
        }),
        status_code=status_code,
        media_type="application/json",
    )


@router.get("/metrics")
def metrics():
    """Prometheus-compatible metrics endpoint.

    Exposes: uptime, component health, RAG document count, auth/tenant/agent
    counts. No external dependencies — plain text format. This is the ONLY
    /metrics route (a second, shadowed duplicate used to live further down
    server.py — FastAPI matches routes in registration order, so it was
    dead code and the metric names it emitted, which the shipped Grafana
    dashboard queries, were never actually produced by a running server).
    """
    from auth import list_users, list_agents, list_tenants, AUTH_DB_PATH
    import server as _srv

    lines = []
    now = time.time()

    # Uptime
    _start = getattr(_srv, "_START_TIME", None)
    uptime = int(now - _start) if _start else 0
    lines.append("asgard_uptime_seconds %d" % uptime)

    # Component health (1=ok, 0=error)
    components = {
        "auth_db": AUTH_DB_PATH,
        "audit_db": _srv.AUDIT_DB_PATH,
    }
    for name, path in components.items():
        healthy = 1 if os.path.exists(path) else 0
        lines.append('asgard_component_healthy{component="%s"} %d' % (name, healthy))

    # RAG documents
    try:
        if _srv.rag_indexer:
            stats = _srv.rag_indexer.get_stats()
            # get_stats() returns {collection_name: count}; total = sum.
            total = sum(v for v in stats.values() if isinstance(v, int))
            lines.append("asgard_rag_documents_total %d" % total)
        else:
            lines.append("asgard_rag_documents_total 0")
    except Exception:
        lines.append("asgard_rag_documents_total 0")

    # Auth / multi-tenant / agent counts (reuse the same accessors the
    # /api/v1/tenants and /api/v1/agents endpoints already use, instead of
    # a second hand-rolled SQL query against a guessed column name).
    try:
        users = list_users()
        lines.append("asgard_registered_users_total %d" % len(users))
        lines.append("asgard_auth_active_users %d" % sum(1 for u in users if u.get("is_active")))
    except Exception:
        lines.append("asgard_registered_users_total 0")
        lines.append("asgard_auth_active_users 0")

    try:
        lines.append("asgard_registered_agents_total %d" % len(list_agents()))
    except Exception:
        lines.append("asgard_registered_agents_total 0")

    try:
        lines.append("asgard_active_tenants_total %d" % len(list_tenants()))
    except Exception:
        lines.append("asgard_active_tenants_total 0")

    # Backup status (absolute path: real backups live in <backend>/backups —
    # the old cwd-relative path never existed under Docker, so this metric
    # was silently absent in production).
    backup_dir = os.path.join(os.path.dirname(os.path.abspath(_srv.__file__)), "backups")
    if os.path.isdir(backup_dir):
        backups = sorted([f for f in os.listdir(backup_dir) if f.endswith(".zip")])
        if backups:
            latest = os.path.getmtime(os.path.join(backup_dir, backups[-1]))
            hours_ago = int((now - latest) / 3600)
            lines.append("asgard_last_backup_hours_ago %d" % hours_ago)

    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4",
    )
