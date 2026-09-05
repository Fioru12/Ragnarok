# Changelog — Ragnarök & Gjallarhorn (sessione PMI-ready)

Tutti i cambiamenti di questa sessione mirano a trasformare Asgard da toolkit tecnico a **prodotto
usabile quotidianamente da una PMI**: report pronti, automazione, notifiche, dashboard
omnicomprensiva, integrazioni.

## Riepilogo aree toccate

| Area | Prima | Dopo |
|------|-------|------|
| Report/export pronti | Terminale/API manuale | Dashboard "Report ed Export" one-click |
| Notifiche | Solo manuali | Manuali + invio automatico (intervallo e orario fisso) |
| Automazione | Solo auto-index e watcher | + scheduler report (2 modalità testate) |
| Dashboard | KPI/score/timeline | + sezione export, fix chiave API condivisa |
| Integrazioni (Gjallarhorn) | Telegram, Webhook, SMTP | + Teams, Jira, ServiceNow |

---

## Ragnarök

### Nuovo: sezione "Report ed Export" nella dashboard
- `backend/dashboard/index.html` — pulsanti one-click per:
  - Report PDF (`GET /api/v1/rag/report/pdf`)
  - Report Markdown (`GET /api/v1/rag/report`)
  - Timeline CSV (`GET /api/v1/rag/timeline/export`)
  - Security Audit (`GET /api/v1/rag/security/report`)
  - Invia digest report (`POST /api/v1/rag/report/notify`)
  - Invia alert timeline (`POST /api/v1/rag/timeline/notify`)
- Download con header `X-API-Key`; messaggio chiaro se chiave assente.
- Fix coerenza chiave API: legge sia `rag_key` (dashboard) sia `asgard_ragnarok_key`
  (frontend Tauri ufficiale) → la sezione funziona subito senza riconfigurazioni.

### Nuovo: invio programmato del report (automazione)
- `backend/server.py` — due task schedulati, coerenti con quelli esistenti:
  - `RAG_REPORT_SEND_MINUTES` — invio ogni N minuti (default 0 = disabilitato)
  - `RAG_REPORT_SEND_CRON=HH:MM` — invio una volta al giorno all'ora fissa locale
    (anti-duplicato per giorno, validazione formato, no-op senza RAG)
- `docker-compose.yml` — `RAG_REPORT_SEND_MINUTES` esposto (default 1440 = digest
  giornaliero) + esempio `RAG_REPORT_SEND_CRON: "08:00"`.

### Fix: endpoint report PDF
- `backend/server.py` — `/api/v1/rag/report/pdf` ora serve i **bytes in memoria**
  (`Response(content=data, media_type="application/pdf")`) invece di `FileResponse(path=bytes)`.
- `backend/rag/pdf_report.py` — ripristinati contratti attesi dai test
  (`_clean_markdown`, `_parse_md_to_structured`, `__init__` con `report_exporter=`,
  `generate_pdf` duplice bytes/path) + conversione `bytes(pdf.output())`.
- `backend/rag/cli.py` — `report --pdf` usa `pdf_exporter.save()`.
- `backend/requirements-rag.txt` — aggiunto `fpdf2>=2.7`.

### Documentazione
- `backend/rag/README.md` — sezione "Export PDF" + "Invio programmato del report
  (automazione PMI)" + "Report ed Export dalla Dashboard (uso quotidiano PMI)".

---

## Gjallarhorn

### Nuovi canali di notifica (6 canali totali)
- `core/channels/teams.py` — Microsoft Teams (payload `MessageCard`, colori per severità).
- `core/channels/jira.py` — Jira Cloud (crea issue via REST API, Basic auth, severity→priority).
- `core/channels/servicenow.py` — ServiceNow (crea incident via Table API, severity→urgency).
- Tutti: pattern `is_configured()`/`send()` invariato, **mai raise** (non-2xx/network error → False).

### Configurazione
- `core/channels/__init__.py` — registrati in `build_channels` e `__all__`.
- `core/config.py` — default + env override per ogni canale.
- `config.yaml.example` + `.env.example` — documentati.

### Documentazione
- `README.md` — diagramma, tabella canali, conteggio test aggiornati.

---

## Verifica (tutto verde)

| Suite | Test | Esito |
|-------|------|-------|
| Ragnarök `tests/` | 82 | ✅ |
| Ragnarök `backend/tests/test_rag.py` | 93 | ✅ |
| Gjallarhorn `tests/` | 50 | ✅ |
| **Totale** | **225** | ✅ 0 failure |

---

## Note operative
- Il rebuild Docker (`docker compose build ragnarok`) va fatto quando Docker è attivo,
  perché l'immagine `asgard-suite:latest` non include le ultime modifiche a
  `pdf_report.py` / `server.py`.
- I nuovi canali Gjallarhorn sono **non-breaking**: se non configurati, sono no-op.
- I nuovi scheduler Ragnarök sono **inerti di default** (`RAG_REPORT_SEND_MINUTES=0`).
