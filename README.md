<div align="center">

# Ragnarök

### **The Asgard Suite — AI-Powered SOC Orchestrator**

![Tauri](https://img.shields.io/badge/Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![RAG](https://img.shields.io/badge/RAG-ChromaDB%20%2B%20FastEmbed-8B5CF6?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

</div>

> **Ragnarök** is the crown jewel of the Asgard Suite. It is an AI-powered desktop SOC Orchestrator built with **Tauri** (Rust + web frontend) and a **Python FastAPI** backend. It unifies all 5 Asgard security tools (Heimdall, Mjolnir, Bifrost, Yggdrasil, Fenrir) into a single command center where analysts can chat with an AI assistant to monitor, orchestrate, and control defensive security operations in real-time.

---

## Architecture

```
                 +-----------------------------------+
                 |      Ragnarök Desktop App         |
                 |  (Tauri Shell + Tailwind UI)      |
                 +-----------------+-----------------+
                                   |
                                   v (HTTP / WebSockets)
                 +-----------------------------------+
                 |     Python FastAPI Orchestrator   |
                 |     (AI Intent Parser & Router)   |
                 +-----------------+-----------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
   +--------------+         +--------------+         +--------------+
   |   HEIMDALL   |         |   MJOLNIR    |         |   BIFROST    |
   |    (HIDS)    |         |   (Triage)   |         |  (Scanner)   |
   +--------------+         +--------------+         +--------------+
         |                         |
         v                         v
   +--------------+         +--------------+
   |  YGGDRASIL   |         |    FENRIR    |
   |  (AD Audit)  |         |  (Threat Intel) |
   +--------------+         +--------------+
```

---

## Quick Start (Running the Orchestrator)

```bash
# 1. Clone repository
cd C:\Progetti\Asgard\Ragnarok

# 2. Install Python backend dependencies
cd backend
pip install -r requirements.txt  # (fastapi, uvicorn, pydantic)
cd ..

# 3. Install Node/Tauri CLI dependencies
npm install

# 4. Launch the desktop app (dev mode)
npm run tauri dev
```

`npm run tauri dev` builds and opens the Tauri desktop shell, which loads
`frontend/index.html` directly (no bundler/dev server involved — it's plain
HTML/JS). Tauri's `beforeDevCommand` (configured in
`src-tauri/tauri.conf.json`) automatically starts the Python backend
(`python ../backend/server.py`) for you before the window opens, so you do
not need to start it manually. If you prefer to run the backend yourself
(e.g. to set `RAGNAROK_API_KEY` or watch its logs separately), start it first
with `python backend/server.py` and it will keep running when Tauri launches.

For a production build:

```bash
npm run tauri build
```

You can also open `frontend/index.html` directly in a regular browser
against a manually-started backend, without Tauri, for quick UI iteration.

---

## RAG Engine — Memoria e Ricerca Semantica

Ragnarök include un **RAG Engine** integrato che dà all'IA una memoria storica reale dei dati prodotti dai moduli Asgard:

- **Indicizza**: alert Heimdall, IOC Fenrir, report triage Mjolnir, scan Bifrost, assessment Forseti
- **Cerca semanticamente**: query in linguaggio naturale su tutto lo storico
- **Correla cross-modulo**: lo stesso IP rilevato da più moduli viene trovato insieme
- **Memoria conversazionale**: le sessioni ricordano il contesto tra le interazioni

### API RAG

| Endpoint | Metodo | Auth | Descrizione |
|----------|--------|------|-------------|
| `/api/v1/rag/index` | POST | ✅ | Forza re-indicizzazione |
| `/api/v1/rag/stats` | GET | — | Statistiche indice |
| `/api/v1/rag/query` | POST | ✅ | Query semantica |
| `/api/v1/rag/sessions` | GET | — | Sessioni attive |
| `/dashboard` | GET | — | Dashboard HTML interattiva |

### Auto-indexing

Imposta `RAG_AUTO_INDEX_MINUTES` (minuti) per indicizzare automaticamente i dati a intervalli regolari. Default: disabilitato.

```bash
# Windows
$env:RAG_AUTO_INDEX_MINUTES = "60"   # ogni ora
python server.py

# Linux/macOS
export RAG_AUTO_INDEX_MINUTES=60
python server.py
```

### Requisiti aggiuntivi

```bash
pip install chromadb fastembed numpy
```

Il modello embedding (`BAAI/bge-small-en-v1.5`, ~90MB ONNX) viene scaricato automaticamente al primo utilizzo e cachato in locale — nessuna dipendenza cloud.

---

## Security configuration

### CORS

The backend only accepts cross-origin requests from a fixed allow-list of
local development origins (Tauri dev server / built webview). It does **not**
use `allow_origins=["*"]`, since combining a wildcard origin with
`allow_credentials=True` would let any web page open in the user's browser
call this local API (which can trigger scans/audits on the host machine).
If you serve the frontend from a different host/port, update
`ALLOWED_ORIGINS` in `backend/server.py`.

### API key for action endpoints

Endpoints that execute modules or trigger scans/audits (`POST /api/v1/execute`,
`POST /api/v1/chat`) require an `X-API-Key` header. Status/health/report-reading
endpoints remain open since they are read-only.

- Set the `RAGNAROK_API_KEY` environment variable before starting the backend
  to choose your own key:

  ```bash
  # Windows (PowerShell)
  $env:RAGNAROK_API_KEY = "your-long-random-key"
  python server.py

  # macOS/Linux
  export RAGNAROK_API_KEY="your-long-random-key"
  python server.py
  ```

- If `RAGNAROK_API_KEY` is not set, the backend generates a random key on
  startup and prints it to the console — copy it from there.
- In the frontend, open **LLM & Settings** and paste the key into
  **"Ragnarök Backend API Key"**. It is sent as the `X-API-Key` header on
  every `/execute` and `/chat` call.

---

## Authentication & RBAC

Ragnarök now supports **multi-user authentication with role-based access control (RBAC)**, in addition to the legacy `X-API-Key` header for backward compatibility.

### Roles (least privilege)

| Role | Permissions |
|------|-------------|
| `admin` | Full access: execute modules, manage users, re-index, view audit log, everything |
| `analyst` | Read / query / export / notify (no module execution, no index management) |
| `viewer` | Read / query / export only (no execute, no index, no notify) |

### How it works

- **Sessions** are stored in a local SQLite database (`ragnarok_auth.db`) with hashed passwords and expiring tokens.
- **Usernames are encrypted at rest** (Fernet, key derived from `RAGNAROK_AUTH_SECRET`); the DB stores only an HMAC lookup key and the encrypted value, so the raw DB file leaks no usernames. Pre-encryption databases are migrated automatically on startup.
- **Bearer tokens** are obtained via `POST /api/v1/auth/login` and sent as `Authorization: Bearer <token>`.
- **API key** (`X-API-Key`) still works on all protected endpoints for non-interactive scripts. When a Bearer token is present, it takes precedence.
- A **default admin** is created on first startup (random password printed to console).
- **Brute-force protection**: after 5 failed attempts (configurable) the account is locked for 5 minutes (configurable). The counter resets on a successful login and decays after the lockout window. Locked logins return HTTP 429 with a `retry_after_seconds` hint.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RAGNAROK_AUTH_DB_PATH` | `backend/ragnarok_auth.db` | Path to the auth database |
| `RAGNAROK_AUTH_SECRET` | auto-generated (printed once) | Secret for signing session tokens — **set this in production** to persist sessions across restarts |
| `RAGNAROK_SESSION_TTL` | `28800` (8h) | Session lifetime in seconds |
| `RAGNAROK_LOGIN_MAX_ATTEMPTS` | `5` | Failed login attempts before account lockout |
| `RAGNAROK_LOCKOUT_SECONDS` | `300` (5m) | Lockout duration after too many failures |

### API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/auth/login` | POST | — | Authenticate, returns `{token, user}` |
| `/api/v1/auth/logout` | POST | Bearer | Invalidate current session |
| `/api/v1/auth/me` | GET | Bearer | Get current user info |
| `/api/v1/auth/users` | GET | Admin | List all users |
| `/api/v1/auth/users` | POST | Admin | Create a user (`{username, password, role}`) |
| `/api/v1/auth/users/{id}` | DELETE | Admin | Deactivate a user |
| `/api/v1/audit-log` | GET | Admin | View audit trail |
| `/api/v1/backup` | POST | Admin | Create a verified backup of all persistent state |
| `/api/v1/backup/verify` | POST | Admin | Verify a backup archive against its sha256 manifest |
| `/api/v1/backup/restore` | POST | Admin | Verify + restore a backup to the live stores |

### Backup & restore

Every persistent store (auth DB, audit trail, RAG vector index, conversation memory, security score history) can be backed up to a single zip archive containing a `manifest.json` with the sha256 of each entry. Restores are refused unless the archive verifies against the manifest — a corrupted backup can never silently overwrite live data. Archives are saved to `backend/backups/`. After a restore, restart the backend so live connections pick up the restored data.

### Audit log

Every authenticated action (login, query, export, execute, user management) is recorded with: user, action, timestamp, success/failure. Query via `GET /api/v1/audit-log` (admin-only).

---

<div align="center">

**Built by [Fioru12](https://github.com/Fioru12)** — The Ultimate Asgard Suite Crown Jewel.

</div>
