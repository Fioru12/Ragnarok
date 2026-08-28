<div align="center">

# RAGNARÖK

### **The Asgard Suite — AI-Powered SOC Orchestrator**

![Tauri](https://img.shields.io/badge/Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38BDF8?style=for-the-badge&logo=tailwind-css&logoColor=white)
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

<div align="center">

**Built by [Fioru12](https://github.com/Fioru12)** — The Ultimate Asgard Suite Crown Jewel.

</div>
