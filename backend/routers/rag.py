"""RAG API endpoints — moved out of server.py to keep the orchestrator lean.

All 19 /api/v1/rag/* handlers live here with verbatim bodies. server-owned
globals (RAG_AVAILABLE, rag_* engine handles, telemetry,
_compute_security_score) are imported lazily *inside* each handler — the
same deferred-import pattern server.py itself already uses — so there is no
import cycle at load time, and tests monkeypatching server.* keep working
because the names are re-read on every call. All routes keep their exact
paths; response models moved here too (no test imports them from server).
"""
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from auth import require_role

router = APIRouter(tags=["rag"])


class RAGIndexResponse(BaseModel):
    status: str
    results: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class RAGQueryRequest(BaseModel):
    query: str
    n_results: int = 5
    sources: Optional[List[str]] = None
    session_id: Optional[str] = None


class RAGQueryResponse(BaseModel):
    status: str
    context: str
    results: List[Dict[str, Any]]
    answer: Optional[str] = None


@router.post("/api/v1/rag/index", response_model=RAGIndexResponse)
async def rag_index_data(user: dict = Depends(require_role("admin"))):
    """Forza re-indicizzazione di tutti i dati Asgard."""
    from server import RAG_AVAILABLE, rag_indexer
    if not RAG_AVAILABLE or rag_indexer is None:
        raise HTTPException(503, "RAG Engine non disponibile")
    try:
        results = rag_indexer.index_all()
        return RAGIndexResponse(status="success", results=results)
    except Exception as e:
        return RAGIndexResponse(status="error", error=str(e))


@router.get("/api/v1/rag/stats")
async def rag_stats():
    """Statistiche dell'indice RAG + Security Score."""
    from server import RAG_AVAILABLE, rag_indexer, _compute_security_score
    if not RAG_AVAILABLE:
        return {"available": False, "rag_available": False, "collections": {}}
    try:
        stats = rag_indexer.get_stats()
        score = _compute_security_score(stats)
        return {
            "available": True,
            "rag_available": True,
            "collections": stats,
            "security_score": score,
        }
    except Exception as e:
        return {"available": False, "rag_available": False, "error": str(e)}


@router.post("/api/v1/rag/query", response_model=RAGQueryResponse)
async def rag_query(req: RAGQueryRequest, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Query semantica sui dati Asgard indicizzati."""
    from server import RAG_AVAILABLE, rag_retriever, rag_memory
    if not RAG_AVAILABLE or rag_retriever is None:
        raise HTTPException(503, "RAG Engine non disponibile")

    try:
        # Esegui ricerca semantica
        results = rag_retriever.search(
            query=req.query,
            n_results=req.n_results,
            sources=req.sources,
        )

        # Formatta contesto per LLM
        context = rag_retriever.format_for_llm(results)

        # Salva nella memoria conversazionale
        if req.session_id and rag_memory:
            rag_memory.add(req.session_id, "user", req.query)
            rag_memory.add(
                req.session_id, "system",
                f"[RAG context: {len(results)} results found]"
            )

        return RAGQueryResponse(
            status="success",
            context=context,
            results=results,
        )
    except Exception as e:
        raise HTTPException(500, f"RAG query failed: {e}")


@router.get("/api/v1/rag/sessions")
async def rag_sessions():
    """Lista sessioni conversazionali attive."""
    from server import RAG_AVAILABLE, rag_memory
    if not RAG_AVAILABLE or rag_memory is None:
        return {"sessions": []}
    try:
        sessions = rag_memory.get_all_sessions()
        return {"sessions": sessions}
    except Exception as e:
        return {"sessions": [], "error": str(e)}


@router.get("/api/v1/rag/insights")
async def rag_insights_endpoint():
    """Analisi proattiva dei dati indicizzati (sommaria, read-only)."""
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        summary = rag_insights.summary()
        return {"available": True, "insights": summary}
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.get("/api/v1/rag/agents")
async def rag_agents_endpoint():
    """Elenco degli agenti specializzati (pubblico, read-only)."""
    from server import RAG_AVAILABLE, rag_agents
    if not RAG_AVAILABLE or rag_agents is None:
        return {"available": False, "agents": []}
    return {"available": True, "agents": rag_agents.list_agents()}


@router.post("/api/v1/rag/agents/ask")
async def rag_agents_ask(req: dict, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Domanda diretta all'agente competente (auth richiesta).

    Routing deterministico per keyword + ricerca semantica confinata alla
    collection di dominio. Nessuna esecuzione di moduli: sola lettura.
    """
    from server import RAG_AVAILABLE, rag_agents, telemetry
    if not RAG_AVAILABLE or rag_agents is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    prompt = str(req.get("prompt", "")).strip()
    if not prompt:
        raise HTTPException(status_code=422, detail="Campo 'prompt' obbligatorio")
    try:
        answer = rag_agents.answer(prompt, n_results=int(req.get("n_results", 5)))
        if not answer.get("routed"):
            raise HTTPException(
                status_code=404,
                detail="Nessun agente competente per questo prompt",
            )
        await telemetry.broadcast({
            "type": "rag_agent_query",
            "agent": answer["agent"]["name"],
            "ts": time.time(),
            "references": len(answer["references"]),
        })
        return {"status": "success", **answer}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/timeline")
async def rag_timeline_endpoint(days: int = 30, spike_factor: float = 3.0, min_spike: int = 3):
    """Serie storica giornaliera degli alert (read-only, deterministica).

    spike_factor e min_spike permettono di tarare la sensitivity della spike
    detection; sono limitati a intervalli sicuri per evitare configurazioni
    insensate (spike_factor 1.5-10, min_spike 1-50).
    """
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        return {"available": False, "error": "RAG Engine non disponibile"}
    spike_factor = min(max(spike_factor, 1.5), 10.0)
    min_spike = min(max(min_spike, 1), 50)
    try:
        from rag.timeline import TimelineEngine
        timeline = TimelineEngine(engine=rag_insights)
        return {"available": True, "timeline": timeline.summary(
            days=days, spike_factor=spike_factor, min_spike=min_spike)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.get("/api/v1/rag/timeline/export")
async def rag_timeline_export_endpoint(days: int = 30, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Export CSV della serie storica (auth: espone il profilo di attacco)."""
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.timeline import TimelineEngine
        timeline = TimelineEngine(engine=rag_insights)
        rows = timeline.daily_counts(days=days)
        lines = ["date,count,low,medium,high,critical"]
        for d in rows:
            s = d["by_severity"]
            lines.append(f"{d['date']},{d['count']},{s.get('LOW', 0)},{s.get('MEDIUM', 0)},"
                         f"{s.get('HIGH', 0)},{s.get('CRITICAL', 0)}")
        csv_text = "\n".join(lines) + "\n"
        from fastapi import Response
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="asgard_timeline_{days}d.csv"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/rag/timeline/notify")
async def rag_timeline_notify_endpoint(days: int = 30, user: dict = Depends(require_role("admin", "analyst"))):
    """Rileva spike anomali e invia l'alert via Gjallarhorn (se configurato)."""
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.dispatch import send_timeline_alert
        return send_timeline_alert(timeline_kwargs={"engine": rag_insights}, days=days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/report")
async def rag_report_endpoint(save: bool = False, user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report proattivo Markdown (richiede auth: contiene IP e IOC)."""
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.report import ReportExporter
        exporter = ReportExporter(engine=rag_insights)
        markdown = exporter.generate_markdown()
        result = {"status": "success", "format": "markdown", "report": markdown}
        if save:
            path = exporter.save()
            result["saved_to"] = path
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/report/pdf")
async def rag_report_pdf_endpoint(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report proattivo in formato PDF (richiede auth: contiene IP e IOC)."""
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag.pdf_report import PDFReportExporter
        from rag.report import ReportExporter
        exporter = PDFReportExporter(report_exporter=ReportExporter(engine=rag_insights))
        data = exporter.generate_pdf()
        from fastapi.responses import Response
        return Response(
            content=data,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="asgard_report.pdf"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/security/history")
async def rag_security_history_endpoint(days: int = 30):
    """Storico security score (pubblico, read-only)."""
    from server import RAG_AVAILABLE
    if not RAG_AVAILABLE:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        from rag.security_history import SecurityScoreHistory
        return {"available": True, "history": SecurityScoreHistory().get_summary(days)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.get("/api/v1/rag/security/trend")
async def rag_security_trend_endpoint(days: int = 30):
    """Trend security score (pubblico, read-only)."""
    from server import RAG_AVAILABLE
    if not RAG_AVAILABLE:
        return {"available": False, "error": "RAG Engine non disponibile"}
    try:
        from rag.security_history import SecurityScoreHistory
        return {"available": True, "trend": SecurityScoreHistory().get_trend(days)}
    except Exception as e:
        return {"available": False, "error": str(e)}


@router.post("/api/v1/rag/security/record")
async def rag_security_record_endpoint(user: dict = Depends(require_role("admin"))):
    """Registra il security score corrente nello storico (richiede auth).

    Uses SecurityAuditor (same as /security/audit and /security/report,
    neither of which gates on RAG_AVAILABLE - this check independently
    audits Asgard's own configuration, it doesn't read the RAG index).
    """
    try:
        from rag.security import SecurityAuditor
        from rag.security_history import SecurityScoreHistory
        audit = SecurityAuditor().run_full_audit()
        result = SecurityScoreHistory().record_score(
            score=audit["score"],
            level=audit["grade"],
            findings_count=audit["total_findings"],
        )
        return {"status": "success", "recorded": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/security/audit")
async def rag_security_dashboard_audit(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Security audit per dashboard (richiede auth)."""
    try:
        from rag.security import SecurityAuditor
        auditor = SecurityAuditor()
        return {"status": "success", "audit": auditor.run_full_audit()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/rag/security/report")
async def rag_security_dashboard_report(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Report Markdown del security audit per dashboard (richiede auth)."""
    try:
        from rag.security import SecurityAuditor
        auditor = SecurityAuditor()
        return {
            "status": "success",
            "format": "markdown",
            "report": auditor.format_report(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/v1/rag/report/notify")
async def rag_report_notify_endpoint(user: dict = Depends(require_role("admin", "analyst"))):
    """Invia il digest del report proattivo via Gjallarhorn (auth richiesta).

    Se GJALLARHORN_HUB_URL/GJALLARHORN_API_KEY non sono impostate risponde
    con sent=false, configured=false — nessun errore, nessun tentativo di rete.
    """
    from server import RAG_AVAILABLE, rag_insights
    if not RAG_AVAILABLE or rag_insights is None:
        raise HTTPException(status_code=503, detail="RAG Engine non disponibile")
    try:
        from rag import dispatch
        result = dispatch.send_report(engine=rag_insights)
        return {"status": "success", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
