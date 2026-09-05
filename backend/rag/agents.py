"""
Asgard RAG — Agenti Specializzati per Modulo.

Ogni agente conosce il proprio dominio (modulo + collection ChromaDB) e le
keyword che lo attivano. Il routing è deterministico (match keyword, primo
match vince — l'ordine della lista è parte del contratto), la ricerca è
semantica e confinata alla collection di competenza: nessuna allucinazione
sulla fonte, l'analista vede sempre da quale modulo arriva il contesto.
"""
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger("Asgard.RAG.Agents")


class ModuleAgent:
    """Agente specializzato su un modulo della suite."""

    def __init__(self, name: str, module: str, collection: str,
                 keywords: List[str], description: str):
        self.name = name
        self.module = module
        self.collection = collection
        self.keywords = [k.lower() for k in keywords]
        self.description = description

    def matches(self, prompt_lower: str) -> bool:
        return any(kw in prompt_lower for kw in self.keywords)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "module": self.module,
            "collection": self.collection,
            "description": self.description,
            "keywords": self.keywords,
        }


AGENTS: List[ModuleAgent] = [
    ModuleAgent(
        name="heimdall_agent",
        module="Heimdall",
        collection="heimdall_alerts",
        keywords=["alert", "brute force", "bruteforce", "ssh", "ip bloccat",
                  "bloccato", "attacco", "intrusion", "failed password", "hids"],
        description="Analisi alert, brute-force e IP bloccati (HIDS).",
    ),
    ModuleAgent(
        name="fenrir_agent",
        module="Fenrir",
        collection="fenrir_ioc",
        keywords=["ioc", "cve", "malware", "hash", "threat intel",
                  "indicatori", "compromission", "vulnerabilit"],
        description="Threat intelligence: IOC, CVE e indicatori.",
    ),
    ModuleAgent(
        name="bifrost_agent",
        module="Bifrost",
        collection="bifrost_scans",
        keywords=["scan", "scansione", "porta", "rete", "host attiv",
                  "servizio", "nmap", "rete interna"],
        description="Report di scansione rete e superfici esposte.",
    ),
    ModuleAgent(
        name="forseti_agent",
        module="Forseti",
        collection="forseti_compliance",
        keywords=["gdpr", "nis2", "compliance", "conformit", "privacy",
                  "audit", "autovalutazione", "regolamento"],
        description="Autovalutazione GDPR/NIS2 e gap di conformità.",
    ),
    ModuleAgent(
        name="mjolnir_agent",
        module="Mjolnir",
        collection="mjolnir_triage",
        keywords=["triage", "forense", "processo sospett", "virus total",
                  "virustotal", "analisi processo", " Incident response"],
        description="Triage forense e analisi processi sospetti.",
    ),
    ModuleAgent(
        name="sleipnir_agent",
        module="Sleipnir",
        collection="sleipnir_playbooks",
        keywords=["playbook", "soar", "automazion", "orchestrazion",
                  "risposta automatica"],
        description="Playbook SOAR disponibili e loro contenuto.",
    ),
]


def route(prompt: str) -> Optional[ModuleAgent]:
    """Restituisce l'agente competente per il prompt, o None.

    Deterministico: primo match in ordine di dichiarazione.
    """
    p = (prompt or "").lower()
    for agent in AGENTS:
        if agent.matches(p):
            return agent
    return None


class AgentRouter:
    """Orchestra gli agenti: routing deterministico + ricerca confinata."""

    def __init__(self, retriever=None):
        self.retriever = retriever

    def list_agents(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in AGENTS]

    def answer(self, prompt: str, n_results: int = 5) -> Dict[str, Any]:
        """Risposta dell'agente competente: ricerca semantica confinata
        alla collection di dominio. Funziona anche senza LLM: il contesto
        restituito è la base fattuale deterministica per l'arricchimento."""
        agent = route(prompt)
        if agent is None:
            return {"agent": None, "routed": False, "references": [], "context": ""}
        references = []
        if self.retriever is not None:
            try:
                references = self.retriever.search_collection(
                    agent.collection, prompt, n_results=n_results
                )
            except Exception as e:
                logger.warning(f"Ricerca agente {agent.name} fallita: {e}")
        lines = [
            f"=== AGENTE {agent.name.upper()} ({agent.module}) ===",
            f"Dominio: {agent.description}",
        ]
        for i, r in enumerate(references, 1):
            lines.append(
                f"[{i}] Source: {agent.module} | "
                f"Relevance: {r['similarity']:.0%}"
            )
            lines.append("    " + r["text"][:300])
        context = "\n".join(lines) if references else \
            f"(Nessun dato nel dominio {agent.module} per questa query.)"
        return {
            "agent": agent.to_dict(),
            "routed": True,
            "references": references,
            "context": context,
        }