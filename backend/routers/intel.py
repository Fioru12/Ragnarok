"""Threat-intel & reports endpoints — moved out of server.py.

hunt + reports list/read only depend on ASGARD_ROOT, resolved here the same
way server.py does (env override, else repo-layout default). Handlers are
verbatim copies of the originals: same paths and payloads.
"""
import glob
import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["intel"])

ASGARD_ROOT = os.getenv(
    "ASGARD_ROOT",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")),
)


@router.get("/api/v1/reports")
def list_reports():
    reports = []
    for pattern in [
        os.path.join(ASGARD_ROOT, "Mjolnir", "output", "*.md"),
        os.path.join(ASGARD_ROOT, "Yggdrasil", "reports", "*.md"),
    ]:
        for filepath in sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)[:20]:
            stat = os.stat(filepath)
            reports.append({
                "filename": os.path.basename(filepath),
                "path": filepath,
                "size_bytes": stat.st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "source": "Mjolnir" if "Mjolnir" in filepath else "Yggdrasil",
            })
    return {"reports": reports}

@router.get("/api/v1/reports/read")
def read_report(path: str):
    allowed_dirs = [
        os.path.realpath(os.path.join(ASGARD_ROOT, "Mjolnir", "output")),
        os.path.realpath(os.path.join(ASGARD_ROOT, "Yggdrasil", "reports")),
        os.path.realpath(os.path.join(ASGARD_ROOT, "reports")),
        os.path.realpath(os.path.join(ASGARD_ROOT, "output")),
    ]
    resolved_path = os.path.realpath(os.path.abspath(path))

    # Path traversal protection: ensure path is strictly inside one of the allowed report directories
    is_safe = False
    for ad in allowed_dirs:
        try:
            if os.path.commonpath([resolved_path, ad]) == ad:
                is_safe = True
                break
        except ValueError:
            continue

    if not is_safe:
        raise HTTPException(status_code=403, detail="Access denied: report path must be inside authorized report directories")

    if not os.path.isfile(resolved_path):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return {"filename": os.path.basename(resolved_path), "content": content}

@router.get("/api/v1/hunt")
def threat_hunt(q: Optional[str] = ""):
    db_path = os.path.join(ASGARD_ROOT, "Fenrir", "fenrir.db")
    if not os.path.exists(db_path):
        return {"results": [], "total": 0, "message": "Fenrir database not found. Run Fenrir update first."}

    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        if q:
            cursor.execute("""
                SELECT indicator_type, indicator, name, source, severity, date_added
                FROM iocs WHERE indicator LIKE ? OR name LIKE ? OR indicator_type LIKE ?
                ORDER BY id DESC LIMIT 100
            """, (f"%{q}%", f"%{q}%", f"%{q}%"))
        else:
            cursor.execute("""
                SELECT indicator_type, indicator, name, source, severity, date_added
                FROM iocs ORDER BY id DESC LIMIT 100
            """)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            results.append({
                "indicator_type": r[0],
                "indicator": r[1],
                "name": r[2],
                "source": r[3],
                "severity": r[4],
                "date_added": r[5]
            })
        return {"results": results, "total": len(results)}
    except Exception as e:
        return {"results": [], "total": 0, "error": str(e)}
