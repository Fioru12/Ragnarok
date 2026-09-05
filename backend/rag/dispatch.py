"""
Asgard RAG — Dispatch del report proattivo via Gjallarhorn.

Invia il riepilogo proattivo all'hub Gjallarhorn (che lo instrada su
Telegram/email/webhook). Segue le convenzioni della suite:

- Configurazione via env: GJALLARHORN_HUB_URL + GJALLARHORN_API_KEY
- Se l'URL non è impostato, nessun tentativo di rete (comportamento inerte)
- notify() non solleva mai: errori loggati, mai crash
- La severità è derivata dai dati: CRITICAL presente → critical,
  altrimenti HIGH presente → high, altrimenti low (o medium se ≥5 HIGH)
"""
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from .insights import InsightsEngine
from .report import ReportExporter

logger = logging.getLogger("Asgard.RAG.Notify")

REPORT_SOURCE = "Ragnarok"


def derive_severity(summary: Dict[str, Any]) -> str:
    """Severità della notifica derivata deterministicamente dai dati."""
    top_ips = summary.get("top_ips", [])
    severities = {e.get("max_severity") for e in top_ips}
    if "CRITICAL" in severities:
        return "critical"
    if "HIGH" in severities:
        high_counts = [e.get("count", 0) for e in top_ips if e.get("max_severity") == "HIGH"]
        return "medium" if max(high_counts, default=0) >= 5 else "high"
    return "low"


def build_digest_message(summary: Dict[str, Any]) -> str:
    """Messaggio compatto (Telegram-friendly) dal summary."""
    lines = []
    top_ips = summary.get("top_ips", [])
    if top_ips:
        parts = [f"{e['ip']} ({e['count']}x {e['max_severity']})" for e in top_ips[:5]]
        lines.append("Top IP: " + ", ".join(parts))
    sev = summary.get("severity_distribution", {})
    if sev:
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(sev.items()))
        lines.append(f"Severità: {sev_str}")
    cves = summary.get("cve_references", [])
    if cves:
        lines.append("CVE: " + ", ".join(c["cve"] for c in cves[:5]))
    comp = summary.get("compliance", {})
    if comp.get("assessment_files", 0) == 0:
        lines.append("Compliance: nessun report Forseti eseguito")
    return "\n".join(lines) if lines else "Nessun dato indicizzato da segnalare."


def is_configured() -> Tuple[bool, str, str]:
    """Ritorna (configurato, hub_url, api_key) dalle variabili d'ambiente."""
    hub_url = os.environ.get("GJALLARHORN_HUB_URL", "").strip()
    api_key = os.environ.get("GJALLARHORN_API_KEY", "").strip()
    return bool(hub_url and api_key), hub_url, api_key


def send_report(engine: Optional[InsightsEngine] = None,
                engine_kwargs: Optional[Dict[str, Any]] = None,
                channels: Optional[list] = None) -> Dict[str, Any]:
    """Genera il digest del report e lo invia a Gjallarhorn.

    Ritorna un dict di esito (mai eccezioni):
      {"sent": bool, "configured": bool, "severity": str, "message": str}
    """
    ok_cfg, hub_url, api_key = is_configured()
    if not ok_cfg:
        logger.info("Gjallarhorn non configurato (GJALLARHORN_HUB_URL/GJALLARHORN_API_KEY): nessun invio.")
        return {"sent": False, "configured": False,
                "severity": None, "message": "Gjallarhorn non configurato: nessun invio effettuato."}

    eng = engine if engine is not None else InsightsEngine(**(engine_kwargs or {}))
    summary = eng.summary()
    severity = derive_severity(summary)
    digest = build_digest_message(summary)
    title = f"Asgard Report Proattivo [{severity.upper()}] - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    from .notifier import notify
    sent = notify(
        hub_url=hub_url,
        api_key=api_key,
        source=REPORT_SOURCE,
        severity=severity,
        title=title,
        message=digest,
        channels=channels,
    )
    return {"sent": sent, "configured": True, "severity": severity, "message": digest,
            "title": title}


def export_and_notify(output_dir: Optional[str] = None,
                      engine: Optional[InsightsEngine] = None) -> Dict[str, Any]:
    """Salva il report Markdown completo e invia il digest via Gjallarhorn."""
    eng = engine if engine is not None else InsightsEngine()
    path = ReportExporter(engine=eng).save(output_dir=output_dir)
    result = send_report(engine=eng)
    result["report_path"] = path
    return result


def derive_anomaly_severity(anomalies) -> str:
    """Severità dell'alert anomalie: CRITICAL presente → critical, altrimenti high."""
    for a in anomalies:
        if (a.get("by_severity") or {}).get("CRITICAL", 0) > 0:
            return "critical"
    return "high"


def build_anomaly_message(anomalies, playbook_hints: Optional[Dict[str, Any]] = None) -> str:
    """Messaggio compatto (Telegram-friendly) per gli spike rilevati.

    playbook_hints: mappa opzionale date → suggerimento playbook (sola proposta).
    """
    hints = playbook_hints or {}
    lines = ["Spike di alert rilevati:"]
    for a in anomalies[:5]:
        sev = a.get("by_severity") or {}
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(sev.items()) if v)
        lines.append(f"- {a['date']}: {a['count']} alert (media {a['avg_baseline']}/giorno"
                     + (f"; {sev_str}" if sev_str else "") + ")")
        hint = hints.get(a["date"])
        if hint:
            lines.append(f"  Playbook suggerito: {hint['playbook']} "
                         f"(pertinenza {hint['similarity']:.0%}) — sola proposta, "
                         "nessuna esecuzione automatica.")
    return "\n".join(lines)


def _collect_playbook_hints(timeline_engine, anomalies) -> Dict[str, Any]:
    """Suggerimenti playbook per ogni anomalia (fail-safe, mai eccezioni)."""
    hints: Dict[str, Any] = {}
    suggest = getattr(timeline_engine, "suggest_playbook_for_anomaly", None)
    if not callable(suggest):
        return hints
    for a in anomalies:
        try:
            sugg = suggest(a)
        except Exception as e:
            logger.debug("Suggerimento playbook fallito per %s: %s", a.get("date"), e)
            continue
        if sugg:
            hints[a["date"]] = sugg
    return hints


def send_timeline_alert(timeline_engine=None,
                        timeline_kwargs: Optional[Dict[str, Any]] = None,
                        days: int = 30,
                        channels: Optional[list] = None,
                        suggest_playbooks: bool = True) -> Dict[str, Any]:
    """Rileva spike anomali e invia l'alert via Gjallarhorn.

    Nessuna anomalia → nessun invio (evita rumore). Comportamento inerte
    senza configurazione, come send_report().
    """
    ok_cfg, hub_url, api_key = is_configured()
    if not ok_cfg:
        logger.info("Gjallarhorn non configurato: nessun alert anomalie inviato.")
        return {"sent": False, "configured": False, "anomalies": 0,
                "message": "Gjallarhorn non configurato: nessun invio effettuato."}

    from .timeline import TimelineEngine
    tl = timeline_engine if timeline_engine is not None else TimelineEngine(**(timeline_kwargs or {}))
    anomalies = tl.detect_anomalies(days=days)
    if not anomalies:
        logger.info("Nessuna anomalia rilevata negli ultimi %d giorni.", days)
        return {"sent": False, "configured": True, "anomalies": 0,
                "message": "Nessuna anomalia rilevata: nessun alert inviato."}

    severity = derive_anomaly_severity(anomalies)
    playbook_hints = _collect_playbook_hints(tl, anomalies) if suggest_playbooks else {}
    message = build_anomaly_message(anomalies, playbook_hints)
    title = (f"Asgard Anomalia Alert [{severity.upper()}] - "
             f"{datetime.now().strftime('%Y-%m-%d %H:%M')}")

    from .notifier import notify
    sent = notify(
        hub_url=hub_url,
        api_key=api_key,
        source=REPORT_SOURCE,
        severity=severity,
        title=title,
        message=message,
        channels=channels,
    )
    return {"sent": sent, "configured": True, "anomalies": len(anomalies),
            "severity": severity, "message": message, "title": title,
            "playbook_hints": playbook_hints}