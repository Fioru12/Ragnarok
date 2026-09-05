"""
Asgard RAG — Security Auditor.

Controlla la configurazione di sicurezza degli agenti e della suite,
verificando: autenticazione API, crittografia, data retention, e best
practice. Genera un report con findings e raccomandazioni prioritarie.
"""
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("Asgard.RAG.Security")

# Severità dei findings
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"


class SecurityAuditor:
    """Auditor di sicurezza per la configurazione Asgard."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings: List[Dict[str, Any]] = []

    def _add(self, severity: str, category: str, title: str,
             description: str, recommendation: str):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })

    def audit_authentication(self) -> List[Dict[str, Any]]:
        """Verifica che l'autenticazione sia configurata correttamente."""
        # Ragnarok API Key
        ragnarok_key = os.getenv("RAGNAROK_API_KEY")
        if not ragnarok_key:
            self._add(
                CRITICAL, "authentication",
                "RAGNAROK_API_KEY non configurata",
                "Il backend Ragnarok non ha una API key impostata. "
                "Verrà generata una chiave temporanea ad ogni riavvio, "
                "rendendo inaccessibili i dati storici.",
                "Imposta RAGNAROK_API_KEY come variabile d'ambiente con "
                "un valore casuale lungo (es. `secrets.token_urlsafe(32)`)."
            )
        elif len(ragnarok_key) < 16:
            self._add(
                HIGH, "authentication",
                "RAGNAROK_API_KEY troppo corta",
                f"La API key ha solo {len(ragnarok_key)} caratteri. "
                "Chiavi corte sono vulnerabili a brute-force.",
                "Usa una key di almeno 32 caratteri."
            )

        # Gjallarhorn API Key
        gjallarhorn_key = os.getenv("GJALLARHORN_API_KEY")
        if not gjallarhorn_key:
            self._add(
                MEDIUM, "authentication",
                "GJALLARHORN_API_KEY non configurata",
                "Le notifiche Gjallarhorn non sono autenticabili.",
                "Imposta GJALLARHORN_API_KEY per proteggere l'hub notifiche."
            )

        # Bifrost API Key
        bifrost_key = os.getenv("BIFROST_API_KEY")
        if not bifrost_key:
            self._add(
                HIGH, "authentication",
                "BIFROST_API_KEY non configurata",
                "Lo scanner di rete è accessibile senza autenticazione.",
                "Imposta BIFROST_API_KEY per proteggere l'endpoint."
            )

        return []

    def audit_encryption(self) -> List[Dict[str, Any]]:
        """Verifica la crittografia dei dati a riposo e in transito."""
        db_path = self.config.get("db_path", "")
        if db_path and os.path.isfile(db_path):
            self._add(
                MEDIUM, "encryption",
                "Database SQLite non cifrato",
                "I database locali usano SQLite standard senza "
                "crittografia a riposo.",
                "Valuta SQLCipher o filesystem cifrato (LUKS/BitLocker)."
            )

        use_tls = os.getenv("ASGARD_TLS", "false").lower() in ("true", "1", "yes")
        if not use_tls:
            self._add(
                HIGH, "encryption",
                "TLS non abilitato",
                "Le comunicazioni non sono cifrate. Dati sensibili "
                "viaggiano in chiaro sulla rete.",
                "Abilita TLS con ASGARD_TLS=true e fornisci certificati validi."
            )

        return []

    def audit_data_retention(self) -> List[Dict[str, Any]]:
        """Verifica le policy di retention dei dati."""
        retention_days = os.getenv("ASGARD_RETENTION_DAYS", "0")
        if retention_days == "0":
            self._add(
                MEDIUM, "data_retention",
                "Nessuna policy di retention configurata",
                "I dati vengono conservati indefinitamente. Questo può "
                "violare il principio di data minimization del GDPR.",
                "Imposta ASGARD_RETENTION_DAYS (es. 90)."
            )
        else:
            try:
                days = int(retention_days)
                if days > 365:
                    self._add(
                        LOW, "data_retention",
                        "Retention molto lunga",
                        f"La retention è di {days} giorni.",
                        "Valuta una retention più breve per dati sensibili."
                    )
            except ValueError:
                self._add(
                    MEDIUM, "data_retention",
                    "ASGARD_RETENTION_DAYS non valido",
                    f"Valore non numerico: '{retention_days}'.",
                    "Imposta un numero intero di giorni."
                )

        return []

    def audit_network_exposure(self) -> List[Dict[str, Any]]:
        """Verifica l'esposizione di rete dei servizi."""
        bind_addr = os.getenv("ASGARD_BIND_ADDRESS", "127.0.0.1")
        if bind_addr == "0.0.0.0":
            self._add(
                HIGH, "network",
                "Servizi esposti su tutte le interfacce",
                "I servizi sono in ascolto su 0.0.0.0 — accessibili da "
                "qualsiasi rete.",
                "Usa 127.0.0.1 per accesso locale o configura un firewall."
            )

        return []

    def run_full_audit(self) -> Dict[str, Any]:
        """Esegue tutti gli audit e restituisce il report."""
        self.findings = []

        self.audit_authentication()
        self.audit_encryption()
        self.audit_data_retention()
        self.audit_network_exposure()

        # Calcolo score (0-100)
        score = 100
        severity_penalties = {
            CRITICAL: 25,
            HIGH: 15,
            MEDIUM: 8,
            LOW: 3,
            INFO: 0,
        }
        for f in self.findings:
            score -= severity_penalties.get(f["severity"], 0)
        score = max(0, score)

        # Raggruppa per severità
        by_severity = {}
        for f in self.findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "score": score,
            "grade": self._grade(score),
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "findings": sorted(self.findings,
                               key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])),
        }

    def _grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def format_report(self, audit: Optional[Dict[str, Any]] = None) -> str:
        """Genera un report Markdown leggibile."""
        a = audit or self.run_full_audit()
        lines = [
            "# 🔒 Asgard — Security Audit Report",
            "",
            f"**Data:** {a['timestamp']}",
            f"**Security Score:** {a['score']}/100 (Grade: {a['grade']})",
            f"**Findings totali:** {a['total_findings']}",
            "",
            "## Riepilogo per severità",
            "",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = a["by_severity"].get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev}:** {count}")

        lines.append("")
        lines.append("## Findings dettagliati")
        lines.append("")

        for i, f in enumerate(a["findings"], 1):
            lines.append(f"### {i}. [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f"**Categoria:** {f['category']}")
            lines.append("")
            lines.append(f"**Descrizione:** {f['description']}")
            lines.append("")
            lines.append(f"**Raccomandazione:** {f['recommendation']}")
            lines.append("")

        lines.append("---")
        lines.append("*Audit generato automaticamente dal Security Auditor di Ragnarök.*")
        return "\n".join(lines)