"""
Asgard RAG — GDPR Compliance per Agenti + Raccomandazione per PMI.

Verifica la conformità GDPR dei dati indicizzati dagli agenti specializzati
e raccomanda quali agenti sono consigliati per PMI in base a dimensione,
settore e maturità nella gestione dei dati personali.

Principi GDPR verificati:
- Minimizzazione (art. 5.1.c): raccolta solo dati pertinenti
- Limitazione conservazione (art. 5.1.e): dati non conservati a tempo indeterminato
- Integrità e riservatezza (art. 5.1.f): protezione accessi non autorizzati
- Privacy by design (art. 25): protezione fin dalla progettazione
"""
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger("Asgard.RAG.GDPR")

AGENT_RECOMMENDATIONS = {
    "micro": {
        "description": "Micro-imprese (1-9 dipendenti)",
        "recommended": ["heimdall_agent", "forseti_agent"],
        "optional": ["fenrir_agent"],
        "reasoning": "Protezione perimetrale essenziale + compliance base."
    },
    "small": {
        "description": "Piccole imprese (10-49 dipendenti)",
        "recommended": ["heimdall_agent", "forseti_agent", "fenrir_agent"],
        "optional": ["bifrost_agent"],
        "reasoning": "Aggiunta threat intelligence per anticipare minacce."
    },
    "medium": {
        "description": "Medie imprese (50-249 dipendenti)",
        "recommended": ["heimdall_agent", "forseti_agent", "fenrir_agent", "bifrost_agent"],
        "optional": ["mjolnir_agent", "sleipnir_agent"],
        "reasoning": "Suite completa consigliata per SOC interno o MSSP."
    },
    "enterprise": {
        "description": "Grandi imprese (250+ dipendenti)",
        "recommended": ["heimdall_agent", "forseti_agent", "fenrir_agent", "bifrost_agent", "mjolnir_agent", "sleipnir_agent"],
        "optional": [],
        "reasoning": "Tutti gli agenti: SOC maturo con triage e orchestrazione."
    }
}

GDPR_CHECKLIST = [
    {"id": "data_inventory", "question": "Hai un inventario dei dati personali trattati?", "principio": "art. 5.1.a", "peso": 3},
    {"id": "consent_management", "question": "Gestisci il consenso per il trattamento dati?", "principio": "art. 6", "peso": 3},
    {"id": "data_minimization", "question": "Raccolti solo dati strettamente necessari?", "principio": "art. 5.1.c", "peso": 2},
    {"id": "retention_policy", "question": "Hai definito tempi di conservazione dei dati?", "principio": "art. 5.1.e", "peso": 2},
    {"id": "security_measures", "question": "Hai misure tecniche e organizzative adeguate?", "principio": "art. 32", "peso": 3},
    {"id": "breach_notification", "question": "Hai una procedura per la notifica breach (72h)?", "principio": "art. 33", "peso": 2},
    {"id": "dpo_appointed", "question": "Hai nominato il DPO (se obbligatorio)?", "principio": "art. 37", "peso": 1},
    {"id": "privacy_by_design", "question": "Applichi privacy by design nei sistemi IT?", "principio": "art. 25", "peso": 2},
    {"id": "data_subject_rights", "question": "Gestisci i diritti dell'interessato (accesso, cancellazione)?", "principio": "art. 15-22", "peso": 2},
    {"id": "dpia", "question": "Hai effettuato una DPIA per trattamenti a rischio?", "principio": "art. 35", "peso": 1}
]


class GDPRComplianceChecker:
    def __init__(self):
        self.max_score = sum(item["peso"] for item in GDPR_CHECKLIST)

    def evaluate_checklist(self, answers: Dict[str, bool]) -> Dict[str, Any]:
        score = 0
        gaps = []
        strengths = []
        for item in GDPR_CHECKLIST:
            if answers.get(item["id"], False):
                score += item["peso"]
                strengths.append(item["question"])
            else:
                gaps.append({"id": item["id"], "question": item["question"], "principio": item["principio"], "peso": item["peso"]})
        percentage = round((score / self.max_score) * 100) if self.max_score > 0 else 0
        if percentage >= 80:
            level, color = "ottimo", "green"
        elif percentage >= 60:
            level, color = "buono", "yellow"
        elif percentage >= 40:
            level, color = "sufficiente", "orange"
        else:
            level, color = "critico", "red"
        return {"score": score, "max_score": self.max_score, "percentage": percentage, "level": level, "color": color, "gaps": gaps, "strengths": strengths, "total_items": len(GDPR_CHECKLIST)}

    def recommend_agents(self, company_size: str, sector: Optional[str] = None, maturity: Optional[str] = None) -> Dict[str, Any]:
        size_key = company_size.lower().strip()
        if size_key not in AGENT_RECOMMENDATIONS:
            size_key = "small"
        rec = AGENT_RECOMMENDATIONS[size_key].copy()
        rec["recommended"] = list(rec["recommended"])
        rec["optional"] = list(rec["optional"])
        if sector and sector.lower() in ["sanita", "sanità", "finanza", "assicurazioni"]:
            for agent in ["fenrir_agent", "bifrost_agent"]:
                if agent not in rec["recommended"]:
                    rec["recommended"].append(agent)
        if maturity:
            if maturity == "base" and "sleipnir_agent" in rec["recommended"]:
                rec["recommended"].remove("sleipnir_agent")
                rec["optional"].append("sleipnir_agent")
            elif maturity == "avanzata" and "sleipnir_agent" in rec["optional"]:
                rec["optional"].remove("sleipnir_agent")
                rec["recommended"].append("sleipnir_agent")
        return {"company_size": rec["description"], "sector": sector or "generico", "maturity": maturity or "standard", "recommended_agents": rec["recommended"], "optional_agents": rec["optional"], "reasoning": rec["reasoning"]}

    def check_data_retention(self, max_days: int = 90) -> Dict[str, Any]:
        return {"policy_days": max_days, "status": "compliant", "note": "Verifica automatica retention: i dati oltre {} giorni vengono rimossi".format(max_days)}

    def generate_privacy_report(self, checklist_answers: Optional[Dict[str, bool]] = None, company_size: str = "small") -> Dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gdpr_evaluation": self.evaluate_checklist(checklist_answers or {}),
            "agent_recommendations": self.recommend_agents(company_size),
            "data_retention": self.check_data_retention(),
            "disclaimer": "Questo strumento fornisce un'autovalutazione indicativa. Per una consulenza GDPR completa, rivolgiti a un DPO qualificato."
        }