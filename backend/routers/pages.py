"""Static pages — moved out of server.py to keep the orchestrator lean.

Serves the frontend shell (fallback JSON when no build is present) and the
RAG/security dashboards. Handlers are verbatim copies of the originals with
one fix: the first-run placeholder used repeated Path.write_text() calls,
each of which truncates the file, so only the last fragment survived — now
a single write. server-owned FRONTEND_DIR is imported lazily inside the
handler (same deferred-import pattern as routers/ops.py and routers/rag.py),
so there is no import cycle. All routes keep their exact paths.
"""
import os
import pathlib

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response

router = APIRouter(tags=["pages"])

# Anchored to backend/ (this file lives in backend/routers/), matching the
# original location in server.py so existing dashboards keep being served.
_DASHBOARD_DIR = pathlib.Path(__file__).parent.parent / "dashboard"
_DASHBOARD_DIR.mkdir(exist_ok=True)
_DASHBOARD_HTML = _DASHBOARD_DIR / "index.html"

if not _DASHBOARD_HTML.exists():
    _DASHBOARD_HTML.write_text(
        "<!DOCTYPE html><html><head><title>Asgard RAG</title>"
        "<style>body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}</style>"
        "</head><body><h1>Asgard RAG Dashboard</h1>"
        "<div id='stats'></div>"
        "<script>fetch('/api/v1/rag/stats').then(r=>r.json()).then(s=>{"
        "document.getElementById('stats').innerHTML='<pre>'+JSON.stringify(s,null,2)+'</pre>'})"
        "</script></body></html>"
    )


@router.get("/")
def serve_frontend():
    from server import FRONTEND_DIR
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "online", "system": "Asgard Enterprise SOC"}


@router.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@router.get("/dashboard")
async def rag_dashboard():
    return FileResponse(str(_DASHBOARD_HTML))


@router.get("/security")
async def rag_security_dashboard():
    """Security Audit Dashboard."""
    security_html = _DASHBOARD_DIR / "security.html"
    if not security_html.exists():
        raise HTTPException(status_code=404, detail="Security dashboard non trovata")
    return FileResponse(str(security_html))
