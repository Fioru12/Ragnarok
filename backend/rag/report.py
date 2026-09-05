"""
Asgard RAG — Report Exporter.

Genera un report Markdown del riepilogo proattivo a partire dai dati
indicizzati, con raccomandazioni automatiche determinate da regole
euristiche deterministiche (nessuna allucinazione LLM).

Il report è pensato per essere condiviso con il management o archiviato
come evidenza periodica dello stato di sicurezza.
"""
import os
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from .insights import InsightsEngine

logger = logging.getLogger("Asgard.RAG.Report")

# Soglie delle raccomandazioni euristiche
HIGH_ALERTS_THRESHOLD = 5  # >=5 alert HIGH sullo stesso IP → triage


class ReportExporter:
    """Genera report Markdown dal riepilogo proattivo degli insight."""

    def __init__(self, engine: Optional[InsightsEngine] = None,
                 engine_kwargs: Optional[Dict[str, Any]] = None):
        self.engine = engine if engine is not None else InsightsEngine(**(engine_kwargs or {}))

    def build_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Raccomandazioni azionabili da regole deterministiche sui dati."""
        recs: List[str] = []

        top_ips = summary.get("top_ips", [])
        if not top_ips and not summary.get("top_ioc"):
            recs.append(
                "Nessun dato indicizzato: esegui l'indicizzazione "
                "(`POST /api/v1/rag/index` o `python -m rag.cli index`) "
                "per generare analisi significative."
            )
            return recs

        for entry in top_ips:
            if entry.get("max_severity") == "CRITICAL":
                recs.append(
                    f"Verifica immediatamente l'IP {entry['ip']} "
                    f"({entry['count']} alert, severità CRITICAL): valuta il "
                    "blocco e il triage forense."
                )
            elif (entry.get("max_severity") == "HIGH"
                  and entry.get("count", 0) >= HIGH_ALERTS_THRESHOLD):
                recs.append(
                    f"Investiga l'IP {entry['ip']} con Mjolnir "
                    f"({entry['count']} alert HIGH ricorrenti)."
                )

        cves = summary.get("cve_references", [])
        if cves:
            cve_list = ", ".join(c["cve"] for c in cves[:3])
            recs.append(
                f"CVE rilevate negli IOC ({cve_list}): verifica l'applicazione "
                "delle patch sui sistemi esposti."
            )

        compliance = summary.get("compliance", {})
        if compliance.get("assessment_files", 0) == 0:
            recs.append(
                "Nessun report di compliance presente: esegui Forseti per "
                "l'autovalutazione GDPR/NIS2."
            )

        if not recs:
            recs.append(
                "Nessuna anomalia critica rilevata: mantenere il monitoraggio periodico."
            )
        return recs

    def generate_markdown(self, summary: Optional[Dict[str, Any]] = None) -> str:
        """Genera il report Markdown completo."""
        s = summary if summary is not None else self.engine.summary()
        lines: List[str] = []
        lines.append("# 🛡️ Asgard — Report Proattivo di Sicurezza")
        lines.append("")
        lines.append(f"*Generato il {s.get('generated_at', datetime.now().isoformat())}*")
        lines.append("")

        lines.append("## 🎯 Top IP Attaccanti")
        lines.append("")
        top_ips = s.get("top_ips", [])
        if top_ips:
            lines.append("| IP | Alert | Severità massima |")
            lines.append("|----|-------|------------------|")
            for e in top_ips:
                lines.append(f"| `{e['ip']}` | {e['count']} | {e['max_severity']} |")
        else:
            lines.append("*Nessun alert indicizzato.*")
        lines.append("")

        lines.append("## 📊 Distribuzione Severità")
        lines.append("")
        sev = s.get("severity_distribution", {})
        if sev:
            lines.append("| Severità | Alert |")
            lines.append("|----------|-------|")
            for k in sorted(sev):
                lines.append(f"| {k} | {sev[k]} |")
        else:
            lines.append("*Nessun dato.*")
        lines.append("")

        lines.append("## 🦠 IOC Ricorrenti (Fenrir)")
        lines.append("")
        iocs = s.get("top_ioc", [])
        if iocs:
            lines.append("| Valore | Occorrenze |")
            lines.append("|--------|------------|")
            for e in iocs:
                lines.append(f"| `{e['value']}` | {e['count']} |")
        else:
            lines.append("*Nessun IOC indicizzato.*")
        lines.append("")

        lines.append("## 🔓 CVE Correlate")
        lines.append("")
        cves = s.get("cve_references", [])
        if cves:
            for c in cves:
                lines.append(f"- **{c['cve']}** (x{c['count']})")
        else:
            lines.append("*Nessuna CVE rilevata.*")
        lines.append("")

        comp = s.get("compliance", {})
        lines.append("## ✅ Compliance")
        lines.append("")
        lines.append(f"- Report Forseti indicizzati: **{comp.get('assessment_files', 0)}**")
        lines.append("")

        lines.append("## 📜 Playbook Sleipnir Disponibili")
        lines.append("")
        pbs = s.get("playbooks", [])
        if pbs:
            for p in pbs:
                lines.append(f"- `{p['playbook']}`")
        else:
            lines.append("*Nessun playbook indicizzato.*")
        lines.append("")

        lines.append("## 💡 Raccomandazioni")
        lines.append("")
        for r in self.build_recommendations(s):
            lines.append(f"- {r}")
        lines.append("")

        lines.append("---")
        lines.append("*Report generato automaticamente dal RAG Engine di Ragnarök. "
                     "Le raccomandazioni sono euristiche: la decisione finale "
                     "spetta all'analista.*")
        return "\n".join(lines)

    def save(self, output_dir: Optional[str] = None) -> str:
        """Genera e salva il report; restituisce il percorso del file."""
        if output_dir is None:
            output_dir = os.environ.get(
                "ASGARD_REPORT_DIR",
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "output", "reports"),
            )
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(output_dir, f"asgard_report_{ts}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate_markdown())
        logger.info(f"Report salvato: {path}")
        return path