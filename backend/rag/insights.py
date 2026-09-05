"""
Asgard RAG — Insights Engine (Analisi Proattiva).

Analizza i dati indicizzati in ChromaDB e produce riepiloghi azionabili:
  - IP più colpiti / attaccanti ricorrenti
  - Distribuzione severità alert
  - CVE e threat actor con più IOC correlati
  - Gap di conformità evidenziati da Forseti
  - Playbook disponibili per un tipo di incidente

L'IA di Ragnarök usa questi insight per suggerire azioni proattive,
senza aspettare domande esplicite dell'analista.
"""
import os
import logging
from collections import Counter
from typing import Dict, Any, List, Optional

from .retriever import AsgardRetriever

logger = logging.getLogger("Asgard.RAG.Insights")


class InsightsEngine:
    """Produce analisi proattive dai dati Asgard indicizzati."""

    def __init__(self, db_path: Optional[str] = None):
        self.retriever = AsgardRetriever(db_path=db_path)

    def _all_metadatas(self, collection_name: str) -> List[Dict[str, Any]]:
        """Recupera tutti i metadati di una collection (senza embedding)."""
        try:
            col = self.retriever.client.get_collection(name=collection_name)
            result = col.get(include=["metadatas"])
            return result.get("metadatas", []) or []
        except Exception:
            return []

    def top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """IP sorgente più frequenti negli alert Heimdall."""
        metas = self._all_metadatas("heimdall_alerts")
        counter = Counter()
        max_sev = {}
        for m in metas:
            ip = m.get("source_ip", "N/A")
            if not ip or ip == "N/A":
                continue
            counter[ip] += 1
            sev = m.get("severity", "LOW")
            if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                sev = "LOW"
            if ip not in max_sev or sev > max_sev[ip]:
                max_sev[ip] = sev
        return [
            {"ip": ip, "count": n, "max_severity": max_sev.get(ip, "LOW")}
            for ip, n in counter.most_common(limit)
        ]

    def severity_distribution(self) -> Dict[str, int]:
        """Distribuzione severità degli alert."""
        metas = self._all_metadatas("heimdall_alerts")
        return dict(Counter(m.get("severity", "UNKNOWN") for m in metas))

    def top_ioc_references(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Valori IOC più frequenti (IP/domain/hash) in Fenrir."""
        metas = self._all_metadatas("fenrir_ioc")
        counter = Counter((m.get("ioc_value") or m.get("value") or "?") for m in metas)
        return [
            {"value": val, "count": n, "source": "fenrir"}
            for val, n in counter.most_common(limit)
        ]

    def cve_references(self, limit: int = 5) -> List[Dict[str, Any]]:
        """CVE citate negli IOC Fenrir."""
        metas = self._all_metadatas("fenrir_ioc")
        cves = [m.get("cve_id") for m in metas if m.get("cve_id") and m["cve_id"] != "N/A"]
        return [
            {"cve": cve, "count": n}
            for cve, n in Counter(cves).most_common(limit)
        ]

    def compliance_summary(self) -> Dict[str, Any]:
        """Riepilogo compliance: report Forseti disponibili."""
        files = [m.get("filename", "?") for m in self._all_metadatas("forseti_compliance")]
        return {
            "assessment_files": len(files),
            "files": files[:5],
            "note": "Usa la ricerca semantica per dettagli sui gap specifici.",
        }

    def available_playbooks(self) -> List[Dict[str, Any]]:
        """Playbook Sleipnir disponibili per l'orchestrazione."""
        metas = self._all_metadatas("sleipnir_playbooks")
        return [{"playbook": m.get("filename", "?"), "type": m.get("type", "playbook")} for m in metas]

    def suggest_playbook(self, incident_text: str, min_similarity: float = 0.4) -> Optional[Dict[str, Any]]:
        """Dato un testo che descrive un incidente, suggerisce il playbook Sleipnir
        più pertinente usando ricerca semantica. Restituisce None sotto soglia."""
        results = self.retriever.search_collection("sleipnir_playbooks", incident_text, n_results=1)
        if not results:
            return None
        best = results[0]
        if best["similarity"] < min_similarity:
            logger.debug(f"Playbook scartato: sim {best['similarity']} < {min_similarity}")
            return None
        meta = best.get("metadata", {})
        return {
            "playbook": meta.get("filename", "?"),
            "similarity": best["similarity"],
            "description": best["text"][:200],
        }

    def summary(self) -> Dict[str, Any]:
        """Riepilogo completo con tutti gli insight."""
        import datetime
        return {
            "top_ips": self.top_ips(),
            "severity_distribution": self.severity_distribution(),
            "top_ioc": self.top_ioc_references(),
            "cve_references": self.cve_references(),
            "compliance": self.compliance_summary(),
            "playbooks": self.available_playbooks(),
            "generated_at": datetime.datetime.now().isoformat(),
        }

    def format_for_llm(self) -> str:
        """Formatta gli insight come contesto proattivo per l'LLM."""
        s = self.summary()
        lines = ["=== ANALISI PROATTIVA ASGARD ==="]

        if s["top_ips"]:
            lines.append("Top IP attaccanti:")
            for ip in s["top_ips"]:
                lines.append(f"  - {ip['ip']}: {ip['count']} alert (severità max: {ip['max_severity']})")
        else:
            lines.append("Nessun alert indicizzato.")

        if s["severity_distribution"]:
            sev = ", ".join(f"{k}={v}" for k, v in s["severity_distribution"].items())
            lines.append(f"Distribuzione severità: {sev}")

        if s["cve_references"]:
            cves = ", ".join(f"{c['cve']} (x{c['count']})" for c in s["cve_references"])
            lines.append(f"CVE rilevate: {cves}")

        if s["playbooks"]:
            pbs = ", ".join(p["playbook"] for p in s["playbooks"])
            lines.append(f"Playbook disponibili: {pbs}")

        if s["compliance"]["assessment_files"]:
            lines.append(f"Report compliance presenti: {s['compliance']['assessment_files']}")

        lines.append("Suggerimento: usa questi dati per proporre azioni proattive "
                     "all'analista senza attendere domande esplicite.")
        return "\n".join(lines)