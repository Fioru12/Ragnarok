"""
Asgard RAG — Security Score History.

Salva e traccia il security score nel tempo per mostrare il trend
di miglioramento (o deterioramento) della configurazione.
"""
import os
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger("Asgard.RAG.SecurityHistory")

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output", "security_history.db")


class SecurityScoreHistory:
    """Gestisce lo storico dei punteggi di sicurezza."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("ASGARD_SECURITY_HISTORY_DB", DEFAULT_DB_PATH)
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Crea la tabella dello storico."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    findings_count INTEGER,
                    recommendations_count INTEGER
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_scores_timestamp
                ON security_scores(timestamp)
            """)

    def record_score(self, score: int, level: str, findings_count: int = 0,
                     recommendations_count: int = 0) -> Dict[str, Any]:
        """Salva un punteggio corrente."""
        ts = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO security_scores (timestamp, score, level, findings_count, recommendations_count) VALUES (?, ?, ?, ?, ?)",
                (ts, score, level, findings_count, recommendations_count)
            )
        logger.info(f"Security score salvato: {score}/100 ({level})")
        return {"timestamp": ts, "score": score, "level": level}

    def get_history(self, days: int = 90) -> List[Dict[str, Any]]:
        """Recupera lo storico degli ultimi `days` giorni."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT * FROM security_scores WHERE timestamp >= ? ORDER BY timestamp",
                (cutoff,)
            )
            return [dict(row) for row in cur.fetchall()]

    def get_trend(self, days: int = 30) -> Dict[str, Any]:
        """Calcola il trend del security score."""
        history = self.get_history(days)
        if len(history) < 2:
            return {
                "trend": "insufficient_data",
                "current_score": history[-1]["score"] if history else 0,
                "data_points": len(history),
                "message": "Servono almeno 2 misurazioni per calcolare il trend."
            }

        first_score = history[0]["score"]
        last_score = history[-1]["score"]
        diff = last_score - first_score

        if diff > 10:
            trend = "improving"
        elif diff < -10:
            trend = "worsening"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "current_score": last_score,
            "previous_score": first_score,
            "difference": diff,
            "data_points": len(history),
            "period_days": days,
            "history": history
        }

    def get_summary(self, days: int = 30) -> Dict[str, Any]:
        """Riepilogo completo dello storico."""
        history = self.get_history(days)
        if not history:
            return {
                "available": False,
                "message": "Nessun dato storico. Esegui 'python -m rag.cli security' per registrare il primo punteggio."
            }

        scores = [h["score"] for h in history]
        trend_data = self.get_trend(days)

        return {
            "available": True,
            "period_days": days,
            "current_score": scores[-1],
            "min_score": min(scores),
            "max_score": max(scores),
            "avg_score": round(sum(scores) / len(scores), 1),
            "data_points": len(scores),
            "trend": trend_data["trend"],
            "trend_difference": trend_data.get("difference", 0),
            "history": history
        }