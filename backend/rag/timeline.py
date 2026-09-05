"""
Asgard RAG — Timeline Engine (Storico Temporale).

Analizza i timestamp degli alert Heimdall indicizzati e produce la serie
storica giornaliera (alert per giorno, con distribuzione per severità),
più il trend di confronto (settimana corrente vs precedente).

Tutti i calcoli sono deterministici: nessun intervento LLM.
"""
import logging
from datetime import datetime, timedelta
from collections import Counter
from typing import Dict, Any, List, Optional

from .insights import InsightsEngine

logger = logging.getLogger("Asgard.RAG.Timeline")

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
TREND_THRESHOLD = 0.2  # ±20% considerato "stabile"


def _parse_timestamp(raw: Any) -> Optional[datetime]:
    """Parsa timestamp nei formati usati dalla suite (ISO, ISO+Z, data sola).

    Restituisce None se non interpretabile: l'alert viene escluso dalla serie
    ma non provoca errori.
    """
    if not raw or not isinstance(raw, str):
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo is None else dt.replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M", "%d/%m/%Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


class TimelineEngine:
    """Serie storica giornaliera degli alert a partire dai dati indicizzati."""

    def __init__(self, engine: Optional[InsightsEngine] = None,
                 engine_kwargs: Optional[Dict[str, Any]] = None):
        self.engine = engine if engine is not None else InsightsEngine(**(engine_kwargs or {}))

    def daily_counts(self, days: int = 30) -> List[Dict[str, Any]]:
        """Alert per giorno degli ultimi N giorni (giorni senza alert = 0).

        Ordine: dal più vecchio al più recente.
        """
        days = max(1, min(int(days), 365))
        metas = self.engine._all_metadatas("heimdall_alerts")

        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=days - 1)
        buckets: Dict[str, Dict[str, Any]] = {}
        for i in range(days):
            day = start + timedelta(days=i)
            key = day.strftime("%Y-%m-%d")
            buckets[key] = {"date": key, "count": 0,
                            "by_severity": {s: 0 for s in SEVERITIES}}

        for m in metas:
            dt = _parse_timestamp(m.get("timestamp"))
            if dt is None:
                continue
            key = dt.strftime("%Y-%m-%d")
            bucket = buckets.get(key)
            if bucket is None:
                continue  # alert fuori dalla finestra richiesta
            bucket["count"] += 1
            sev = m.get("severity", "LOW")
            if sev not in SEVERITIES:
                sev = "LOW"
            bucket["by_severity"][sev] += 1

        return [buckets[(start + timedelta(days=i)).strftime("%Y-%m-%d")]
                for i in range(days)]

    def summary(self, days: int = 30, spike_factor: float = 3.0,
                min_spike: int = 3) -> Dict[str, Any]:
        """Riepilogo della serie: totali, giorno di picco, trend settimanale."""
        return self.summary_from_series(self.daily_counts(days), days=days,
                                        spike_factor=spike_factor, min_spike=min_spike)

    def summary_from_series(self, series: List[Dict[str, Any]], days: int = 30,
                            spike_factor: float = 3.0, min_spike: int = 3
                            ) -> Dict[str, Any]:
        """Riepilogo a partire da una serie già calcolata (usabile nei test)."""
        total = sum(d["count"] for d in series)
        peak = max(series, key=lambda d: d["count"]) if series else None

        sev_totals = Counter()
        for d in series:
            for s, n in d["by_severity"].items():
                sev_totals[s] += n

        # Trend: ultima settimana vs settimana precedente (sovrapposta alla finestra)
        last7 = sum(d["count"] for d in series[-7:])
        prev7 = sum(d["count"] for d in series[-14:-7]) if len(series) >= 14 else 0
        if prev7 == 0:
            trend, delta = ("up" if last7 > 0 else "flat"), None
        else:
            ratio = (last7 - prev7) / prev7
            if ratio > TREND_THRESHOLD:
                trend = "up"
            elif ratio < -TREND_THRESHOLD:
                trend = "down"
            else:
                trend = "flat"
            delta = round(ratio * 100, 1)

        anomalies = self.detect_anomalies(series=series, spike_factor=spike_factor,
                                          min_spike=min_spike)
        severity_anomalies = self.detect_severity_anomalies(series=series, spike_factor=spike_factor)
        return {
            "days": days,
            "total": total,
            "series": series,
            "peak": {"date": peak["date"], "count": peak["count"]} if peak and peak["count"] else None,
            "by_severity": dict(sev_totals),
            "trend": {"last7": last7, "prev7": prev7, "direction": trend, "delta_pct": delta},
            "anomalies": anomalies,
            "severity_anomalies": severity_anomalies,
        }

    def _adaptive_baselines(self, values: List[float], window: int = 14) -> List[float]:
        """Baseline adattiva: media mobile pesata dei `window` giorni precedenti.

        I giorni recenti pesano di più (pesi lineari crescenti verso il presente)
        e il giorno stesso è sempre escluso dalla sua baseline. Nei primi giorni,
        senza storia sufficiente, si usa la media globale dell'intera serie
        (comportamento precedente).
        """
        n = len(values)
        if n == 0:
            return []
        global_avg = sum(values) / n
        baselines = []
        for i in range(n):
            prev = values[max(0, i - window):i]
            if not prev:
                baselines.append(global_avg)
                continue
            weights = list(range(1, len(prev) + 1))  # il giorno più recente pesa di più
            total_w = sum(weights)
            baselines.append(
                sum(v * w for v, w in zip(prev, weights)) / total_w
            )
        return baselines

    def detect_anomalies(self, series: Optional[List[Dict[str, Any]]] = None,
                         days: int = 30, spike_factor: float = 3.0,
                         min_spike: int = 3, adaptive: bool = True
                         ) -> List[Dict[str, Any]]:
        """Giorni con spike anomalo di alert (regola deterministica).

        Con adaptive=True (default) la baseline è una media mobile pesata dei
        14 giorni precedenti: uno spike vecchio non maschera quelli nuovi e gli
        incrementi graduali non generano falsi positivi. Con adaptive=False si
        usa la media globale della finestra (comportamento storico).

        In entrambi i casi: count >= max(spike_factor * baseline, min_spike).
        min_spike evita falsi positivi su basi di traffico quasi nulle.
        """
        if series is None:
            series = self.daily_counts(days)
        if not series:
            return []
        counts = [d["count"] for d in series]
        if adaptive:
            baselines = self._adaptive_baselines(counts)
            baseline_type = "adaptive"
        else:
            avg = sum(counts) / len(series)
            baselines = [avg] * len(series)
            baseline_type = "global"
        anomalies = []
        for d, baseline in zip(series, baselines):
            threshold = max(spike_factor * baseline, float(min_spike))
            if d["count"] >= threshold:
                anomalies.append({
                    "date": d["date"],
                    "count": d["count"],
                    "avg_baseline": round(baseline, 2),
                    "baseline_type": baseline_type,
                    "by_severity": dict(d["by_severity"]),
                })
        return anomalies

    def detect_severity_anomalies(self, series: Optional[List[Dict[str, Any]]] = None,
                                  days: int = 30, spike_factor: float = 3.0,
                                  critical_min: int = 2, high_min: int = 3
                                  ) -> List[Dict[str, Any]]:
        """Spike di severità (regola deterministica, più fine di detect_anomalies).

        Monitora solo CRITICAL e HIGH (MEDIUM/LOW sono rumore di fondo):
          - CRITICAL: count >= max(spike_factor * media CRITICAL, critical_min)
          - HIGH:     count >= max(spike_factor * media HIGH, high_min)
        CRITICAL ha soglia minima più bassa: anche pochi alert critici nello
        stesso giorno sono un segnale rilevante.
        """
        if series is None:
            series = self.daily_counts(days)
        if not series:
            return []
        anomalies = []
        for sev, floor in (("CRITICAL", critical_min), ("HIGH", high_min)):
            values = [d["by_severity"].get(sev, 0) for d in series]
            baselines = self._adaptive_baselines(values)
            for d, baseline in zip(series, baselines):
                count = d["by_severity"].get(sev, 0)
                threshold = max(spike_factor * baseline, float(floor))
                if count >= threshold:
                    anomalies.append({
                        "date": d["date"],
                        "severity": sev,
                        "count": count,
                        "avg_baseline": round(baseline, 2),
                    })
        anomalies.sort(key=lambda a: (a["date"], a["severity"]))
        return anomalies

    def _day_alert_context(self, date_str: str) -> Dict[str, Counter]:
        """Regole dominanti e severità degli alert di un giorno specifico.

        Legge documenti e metadati di heimdall_alerts (i rule title sono nel
        testo del documento, non nei metadati) e filtra per data.
        """
        ctx = {"rule_titles": Counter(), "severities": Counter()}
        try:
            col = self.engine.retriever.client.get_collection(name="heimdall_alerts")
            res = col.get(include=["documents", "metadatas"])
        except Exception as e:
            logger.debug("Lettura heimdall_alerts per %s fallita: %s", date_str, e)
            return ctx
        for doc, meta in zip(res.get("documents") or [], res.get("metadatas") or []):
            dt = _parse_timestamp(meta.get("timestamp"))
            if dt is None or dt.strftime("%Y-%m-%d") != date_str:
                continue
            if isinstance(doc, str) and doc.startswith("Alert: "):
                title = doc.split(". Severity:")[0][len("Alert: "):].strip()
                if title and title.lower() != "unknown":
                    ctx["rule_titles"][title] += 1
            sev = meta.get("severity", "LOW")
            ctx["severities"][sev if sev in SEVERITIES else "LOW"] += 1
        return ctx

    def suggest_playbook_for_anomaly(self, anomaly: Dict[str, Any],
                                     min_similarity: float = 0.4) -> Optional[Dict[str, Any]]:
        """Suggerisce il playbook Sleipnir per un'anomalia rilevata (read-only).

        Costruisce la descrizione dell'incidente dalle regole dominanti del
        giorno anomalo e usa la ricerca semantica sui playbook. Restituisce
        None se nessun playbook supera la soglia di pertinenza.
        """
        ctx = self._day_alert_context(anomaly.get("date", ""))
        top_rules = [t for t, _ in ctx["rule_titles"].most_common(2)]
        if not top_rules:
            return None
        desc = f"Picco anomalo di alert: {top_rules[0]}"
        if len(top_rules) > 1:
            desc += f" e {top_rules[1]}"
        try:
            suggestion = self.engine.suggest_playbook(desc, min_similarity=min_similarity)
        except Exception as e:
            logger.debug("Suggerimento playbook per anomalia fallito: %s", e)
            return None
        if suggestion:
            suggestion["context"] = desc
        return suggestion