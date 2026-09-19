# Ragnarök — AI-Powered SOC Orchestrator (backend)
# Build:  docker compose build
# Run:    docker compose up -d
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /asgard/Ragnarok

# libgomp1: chromadb/fastembed (onnxruntime) need it on slim images
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt backend/requirements-rag.txt ./backend/
RUN pip install --upgrade pip \
    && pip install -r backend/requirements.txt -r backend/requirements-rag.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Layout mirrors a checkout (/asgard/Ragnarok/...) so ASGARD_ROOT
# auto-detection and FRONTEND_DIR resolution keep working unchanged.
# All persistent state is redirected to /state (see docker-compose.yml):
#   - RAGNAROK_AUDIT_DB_PATH  audit trail (SQLite)
#   - RAGNAROK_AUTH_DB_PATH   users + sessions (SQLite)
#   - ASGARD_RAG_DB_PATH      ChromaDB vector index + conversation memory
ENV RAGNAROK_HOST=0.0.0.0 \
    RAGNAROK_PORT=8080 \
    RAGNAROK_AUDIT_DB_PATH=/state/ragnarok_audit.db \
    RAGNAROK_AUTH_DB_PATH=/state/ragnarok_auth.db \
    ASGARD_RAG_DB_PATH=/state/rag_db

EXPOSE 8080

# /health returns 200 when healthy, 503 when degraded (triggers restart)
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"

CMD ["python", "backend/server.py"]
