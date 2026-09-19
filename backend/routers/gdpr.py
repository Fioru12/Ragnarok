"""GDPR endpoints — moved out of server.py to keep the orchestrator lean.

Routes are mounted with prefix /api/v1/rag/gdpr (see server.py include_router).
Handlers are verbatim copies of the originals: same paths, same payloads.
"""
from typing import Dict, Optional

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/rag/gdpr", tags=["gdpr"])


@router.get("/checklist")
async def gdpr_checklist():
    """Checklist GDPR per autovalutazione (pubblica, no auth)."""
    try:
        from rag.gdpr import GDPR_CHECKLIST
        return {"status": "success", "checklist": GDPR_CHECKLIST}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/evaluate")
async def gdpr_evaluate(answers: Dict[str, bool]):
    """Valuta le risposte alla checklist GDPR e restituisce score + gap analysis."""
    try:
        from rag.gdpr import GDPRComplianceChecker
        checker = GDPRComplianceChecker()
        return {"status": "success", "evaluation": checker.evaluate_checklist(answers)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recommend")
async def gdpr_recommend(company_size: str = "small", sector: Optional[str] = None,
                         maturity: Optional[str] = None):
    """Raccomanda agenti Asgard per PMI in base a dimensione, settore e maturità."""
    try:
        from rag.gdpr import GDPRComplianceChecker
        checker = GDPRComplianceChecker()
        return {"status": "success", "recommendation": checker.recommend_agents(company_size, sector, maturity)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
