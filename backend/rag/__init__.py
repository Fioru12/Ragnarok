"""
Asgard RAG Engine — Retrieval-Augmented Generation per Ragnarök.

Indicizza tutti i dati prodotti dai moduli Asgard (alert, IOC, report, log)
in un vector database (ChromaDB) e permette query semantiche via embedding ONNX.

Questo dà all'IA di Ragnarök:
  - Memoria storica di tutto ciò che i moduli hanno rilevato
  - Contesto sulla rete/azienda dell'utente
  - Capacità di rispondere a domande complesse cross-modulo
"""
import os
import logging

logger = logging.getLogger("Asgard.RAG")

# Percorso di default del database vettoriale (dentro il backend)
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", ".asgard-suite-repo", "rag_db")


def get_db_path() -> str:
    return os.environ.get("ASGARD_RAG_DB_PATH", _DEFAULT_DB_PATH)
