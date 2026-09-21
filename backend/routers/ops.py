"""Ops endpoints — backup/restore and audit log (admin only).

Moved out of server.py to keep the orchestrator lean. Handlers are verbatim
copies of the originals; server-owned helpers (record_audit_event,
AUDIT_DB_PATH) are imported lazily inside the handlers — the same
deferred-import pattern server.py itself already uses (e.g. `import backup
as backup_mod` inside each handler) — so there is no import cycle at load
time. All routes keep their exact paths.
"""
import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
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
