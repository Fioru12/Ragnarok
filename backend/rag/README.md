# Asgard RAG Engine — Retrieval-Augmented Generation

Modulo di intelligenza artificiale per **Ragnarök** che aggiunge memoria storica e ricerca semantica a tutti i dati prodotti dalla suite Asgard.

## Cos'è

Il sistema RAG (Retrieval-Augmented Generation) permette all'IA di Ragnarök di:

- **Ricordare** tutto ciò che i moduli Asgard hanno rilevato (alert, IOC, report, assessment)
- **Cercare semanticamente** usando linguaggio naturale ("Quali IP malevoli sono stati rilevati?")
- **Correlare dati** tra moduli diversi (es. lo stesso IP in Heimdall e Fenrir)
- **Mantenere memoria conversazionale** tra sessioni diverse

## Architettura

```
Ragnarok/backend/rag/
├── __init__.py          # Configurazione path DB vettoriale
├── indexer.py           # Indicizzazione dati in ChromaDB
├── retriever.py         # Query semantiche con FastEmbed
├── insights.py          # Analisi proattiva (IP top, CVE, compliance)
├── cli.py               # CLI: index / query / insights / report / notify / anomalies / security / security-history / gdpr / stats
└── memory.py            # Memoria conversazionale SQLite
```

## Dati Indicizzati

| Modulo | Fonte | Collection ChromaDB |
|--------|-------|---------------------|
| Heimdall | SQLite `alerts`, `blocked_ips` | `heimdall_alerts` |
| Fenrir | SQLite `ioc` | `fenrir_ioc` |
| Mjolnir | Markdown `output/*.md` | `mjolnir_triage` |
| Bifrost | Markdown `output/*.md` | `bifrost_scans` |
| Forseti | Markdown `output/*.md` | `forseti_compliance` |

## Come Funziona

### Indicizzazione

Il sistema legge i dati dai moduli Asgard e li converte in vettori usando embedding semantici:

```
Dato grezzo → Embedding (384 float) → ChromaDB (indice HNSW)
```

### Ricerca Semantica

```
Query utente → Embedding → Similarità coseno → Top K risultati
```

## API Endpoints

| Endpoint | Metodo | Auth | Descrizione |
|----------|--------|------|-------------|
| `/api/v1/rag/index` | POST | ✅ | Forza re-indicizzazione |
| `/api/v1/rag/stats` | GET | ❌ | Statistiche indice |
| `/api/v1/rag/query` | POST | ✅ | Query semantica |
| `/api/v1/rag/insights` | GET | ❌ | Analisi proattiva read-only |
| `/api/v1/rag/sessions` | GET | ❌ | Sessioni attive |
| `/dashboard` | GET | ❌ | Dashboard HTML |

## Analisi Proattiva (Insights)

Il modulo `insights.py` analizza i dati indicizzati e produce riepiloghi azionabili:

- **Top IP attaccanti**: IP più frequenti negli alert Heimdall con severità massima
- **Distribuzione severità**: HIGH/CRITICAL/MEDIUM/LOW degli alert
- **IOC ricorrenti**: valori più frequenti in Fenrir (IP, domain, hash)
- **CVE correlate**: vulnerabilità citate negli IOC con conteggio
- **Compliance**: report Forseti disponibili
- **Playbook**: playbook Sleipnir disponibili per orchestrazione

L'IA di Ragnarök usa questi insight in modo **proattivo**: quando l'analista chiede
un "riepilogo", "panoramica" o "cosa sta succedendo", il chat restituisce
l'analisi dello stato complessivo **senza eseguire alcun modulo** (read-only).

## Push Real-Time Anomalie (WebSocket)

`RAG_ANOMALY_WATCH_MINUTES` (default 15, 0 = disabilitato) attiva un watcher che:

1. Controlla gli spike (totali + per severità) sulla timeline 30 giorni
2. Trasmette l'evento `rag_anomaly_detected` via WebSocket `/ws/telemetry`
3. La dashboard mostra un **toast** con data, livello e baseline e aggiorna il grafico automaticamente (senza refresh)
4. **Anti-duplicati**: ogni data anomala viene notificata una sola volta per avvio server
5. **Leggero**: legge solo metadati ChromaDB già in memoria — nessun impatto sulle latenze
6. **Resiliente**: la dashboard riconnette con backoff esponenziale (max 60s) al restart del backend

```bash
# Abilita il controllo anomalie ogni 10 minuti
set RAG_ANOMALY_WATCH_MINUTES=10
python backend/server.py
```
# Disabilita il watcher
set RAG_ANOMALY_WATCH_MINUTES=0

# Controllo ogni 5 minuti
set RAG_ANOMALY_WATCH_MINUTES=5
```

### Architettura Modulo

```
rag/
├── __init__.py    # path DB vettoriale
├── indexer.py     # 6 collection ChromaDB (FastEmbed bge-small-en)
├── retriever.py   # ricerca semantica globale e per-collection
├── agents.py      # 6 agenti specializzati (routing + ricerca confinata)
├── insights.py    # analisi proattiva + suggest_playbook
├── timeline.py    # serie storica, trend, baseline adattiva, spike detection
├── report.py      # report Markdown con raccomandazioni deterministiche
├── dispatch.py    # alert Gjallarhorn (report + anomalie + playbook hint)
├── memory.py      # memoria conversazionale SQLite
├── cli.py         # index / query / insights / report / notify / anomalies / security / security-history / gdpr / stats
```

Principi trasversali:

- **Deterministico dove conta** (soglie, severità, raccomandazioni) — zero allucinazioni LLM
- **Semantico dove serve** (match playbook, ricerca, routing agenti)
- **Mai esecutivo**: ogni azione proposta richiede conferma umana
- **Locale-first**: embedding ONNX locali, nessun dato lascia la macchina
- **Inerte senza configurazione**: Gjallarhorn non configurato → nessuna rete, exit pulito

## Suggerimento Playbook (Incident → SOAR)

Quando l'analista descrive un incidente nel chat (es. *"sto subendo un brute force
SSH"*, *"i file sono cifrati da un ransomware"*), il sistema:

1. Rileva le keyword di incidente (brute force, ransomware, lateral movement, ecc.)
2. Cerca semanticamente il playbook Sleipnir più pertinente (`suggest_playbook()`)
3. Restituisce una **proposta** con status `playbook_suggested` e pertinenza stimata
4. **Non esegue nulla**: l'analista deve sempre verificare e confermare manualmente

Sotto una soglia minima di pertinenza (`min_similarity=0.4`) nessun playbook
viene suggerito, per evitare falsi consigli.

### CLI

```bash
cd Ragnarok/backend

python -m rag.cli index                 # Indicizza i dati dei moduli
python -m rag.cli query "quali IP?"     # Ricerca semantica
python -m rag.cli insights              # Analisi proattiva
python -m rag.cli report                # Report Markdown a video
python -m rag.cli report --save         # Report salvato in output/reports/
python -m rag.cli stats                 # Statistiche indice
```

## Agenti Specializzati (Multi-Agente)

`rag/agents.py` implementa 6 agenti di dominio, uno per modulo, con **routing deterministico per keyword** e **ricerca semantica confinata** alla collection del proprio dominio (un agente non vede i dati degli altri).

| Agente | Modulo | Collection | Parole chiave |
|--------|--------|------------|---------------|
| `heimdall_agent` | HIDS | `heimdall_alerts` | alert, brute force, ssh, login, blocco, ip |
| `fenrir_agent` | Threat Intel | `fenrir_ioc` | ioc, cve, vulnerabilità, minaccia, malware hash |
| `bifrost_agent` | Network | `bifrost_scans` | scan, porta, rete, servizio, host |
| `forseti_agent` | Compliance | `forseti_compliance` | gdpr, nis2, compliance, conformità |
| `mjolnir_agent` | Forensics | `mjolnir_triage` | triage, processo, forense, sospetto |
| `sleipnir_agent` | SOAR | `sleipnir_playbooks` | playbook, orchestr, automat, workflow |

Garanzie:
- **Read-only**: nessun agente esegue moduli o playbook, solo ricerca nei dati indicizzati
- **Deterministico**: stesso prompt → stesso agente (primo match nella lista di dichiarazione)
- **Fail-safe**: prompt fuori dominio → nessun routing; collection vuota → contesto informativo, mai crash
- Telemetria: ogni query genera un evento `rag_agent_query` via WebSocket

API:
```
GET  /api/v1/rag/agents       → elenco agenti (pubblico)
POST /api/v1/rag/agents/ask   → domanda all'agente competente (auth; 404 se fuori dominio)
```

Uso programmatico:
```python
from rag.agents import route, AgentRouter
agent = route("ci sono attacchi brute force?")   # -> heimdall_agent
router = AgentRouter()
answer = router.answer("ci sono attacchi brute force?")
# {"routed": True, "agent": {...}, "context": "...", "references": [...]}
```

## Export Report Proattivo

`rag/report.py` genera un report Markdown condivisibile con il management:

- Tutte le sezioni dell'analisi (IP, severità, IOC, CVE, compliance, playbook)
- **Raccomandazioni automatiche** da regole euristiche deterministiche (no LLM):
  - Alert CRITICAL → verifica immediata e valutazione blocco
  - ≥5 alert HIGH sullo stesso IP → triage con Mjolnir
  - CVE presenti → verifica patch sui sistemi esposti
  - Nessun report compliance → eseguire autovalutazione Forseti
- API: `GET /api/v1/rag/report` (richiede auth), con `?save=true` salva su disco
- Directory di salvataggio configurabile con `ASGARD_REPORT_DIR`

### Export PDF

La CLI e il server possono generare un **PDF formale per il management** con il modulo
`rag/pdf_report.py` (basato su `fpdf2`). Contratto di `PDFReportExporter.generate_pdf()`:

- con `output_path` (o env `ASGARD_REPORT_DIR` impostato) → **salva su disco e ritorna il `path`**
- senza `output_path` e senza env → ritorna i **`bytes`** del PDF (nessun file)

API:
- CLI: `python -m rag.cli report --pdf [--out DIR]`
- HTTP: `GET /api/v1/rag/report/pdf` (richiede auth — il PDF contiene IP e IOC)

Dipendenza: `fpdf2>=2.7` (in `requirements-rag.txt`).

Nota sul font: il PDF usa il font **Helvetica built-in** di fpdf2 (zero dipendenze
di sistema, set **latin-1**). I caratteri Unicode fuori dal latin-1 (trattino em,
virgolette inglesi, bullet `•`, ecc.) vengono normalizzati da `PDFReportExporter._clean()`:
trattini e virgolette sono sostituiti con i corrispettivi ASCII e il bullet con `-`,
così il testo resta leggibile senza richiedere un font TTF esterno.

### Report ed Export dalla Dashboard (uso quotidiano PMI)

La dashboard (`GET /dashboard`) include una sezione **"Report ed Export"** pensata
per l'uso quotidiano di una PMI: un clic e si scaricano i report pronti o si invia
il digest, senza aprire un terminale.

- **Report PDF formale** → `GET /api/v1/rag/report/pdf`
- **Report proattivo Markdown** → `GET /api/v1/rag/report`
- **Timeline in CSV** (ultimi 30 giorni) → `GET /api/v1/rag/timeline/export?days=30`
- **Security audit in Markdown** → `GET /api/v1/rag/security/report`
- **Invia digest report** via Gjallarhorn → `POST /api/v1/rag/report/notify`
- **Invia alert timeline** via Gjallarhorn → `POST /api/v1/rag/timeline/notify?days=30`

I pulsanti si autenticano con la stessa API key salvata dal frontend Tauri
(`localStorage['asgard_ragnarok_key']` o `rag_key`), inviata come header
`X-API-Key`; se non c'è una chiave configurata lo segnalano senza crash. Gli
endpoint di notifica rispondono `configured:false` quando Gjallarhorn non è
configurato, senza errori né tentativi di rete.

### Invio programmato del report (automazione PMI)

Il report non va generato solo quando qualcuno se lo ricorda. Con due variabili
d'ambiente il server invia automaticamente il digest del report proattivo via
Gjallarhorn, usando lo stesso meccanismo middleware dei task schedulati esistenti
(auto-index e anomaly watcher):

```bash
# Modalità 1 — ogni N minuti (default 0 = disabilitato)
RAG_REPORT_SEND_MINUTES=1440   # 1 volta al giorno
RAG_REPORT_SEND_MINUTES=60     # ogni ora

# Modalità 2 — una volta al giorno all'ora fissa locale (più tipica per una PMI)
RAG_REPORT_SEND_CRON=08:00     # ogni mattina alle 08:00
```

- Le due modalità sono **opzionali e non esclusive**; in `docker-compose.yml` il
  default è `RAG_REPORT_SEND_MINUTES=1440` (un digest al giorno).
- Se Gjallarhorn non è configurato (`GJALLARHORN_HUB_URL`/`GJALLARHORN_API_KEY`
  assenti) il task è un **no-op**: nessun errore, nessun tentativo di rete.
- `RAG_REPORT_SEND_CRON` viene validato (HH:MM, 0-23/0-59): se malformato è
  ignorato senza crash. Il cron invia **una volta al giorno** (anti-duplicato:
  memorizza il giorno già inviato) e si attiva alla prima richiesta dopo l'orario
  target.
- I timer sono in-memory: si resettano al riavvio del server. I task sono
  ritardanti (mai concorrenti: un invio in corso salta la finestra successiva).

## Storico Temporale (Timeline)

`rag/timeline.py` produce la serie storica giornaliera degli alert:

- `TimelineEngine.daily_counts(days)` — alert per giorno (giorni vuoti = 0), con ripartizione per severità
- `TimelineEngine.summary(days)` — totale, giorno di picco, trend (ultima settimana vs precedente, ±20% = stabile)
- Timestamp multi-formato supportati (ISO, ISO+Z, data sola); non interpretabili sono esclusi senza crash
- Finestra limitata a 1..365 giorni
- API: `GET /api/v1/rag/timeline?days=30` (pubblica, read-only, deterministica)
- Dashboard: grafico a barre puro CSS (zero librerie esterne, locale-first) con tooltip per giorno e trend colorato
- Dashboard: selettore periodo 7/30/90 giorni e banner rosso per gli spike anomali
- Export CSV: `GET /api/v1/rag/timeline/export?days=30` (auth, `date,count,low,medium,high,critical`)

## Rilevamento Anomalie (Spike Detection)

`TimelineEngine.detect_anomalies()` usa una **baseline adattiva**: media mobile
pesata dei 14 giorni precedenti (i giorni recenti pesano di più, il giorno stesso
è escluso dalla sua baseline). Vantaggi rispetto alla media globale:

- uno spike vecchio (fuori dalla finestra) non maschera gli spike nuovi
- gli incrementi graduali del traffico non generano falsi positivi

Regola: `count >= max(3 × baseline_adattiva, 3)`. Con `adaptive=False` si ripristina
la media globale dell'intera finestra (comportamento storico). Ogni anomalia riporta
`baseline_type: "adaptive" | "global"`.

`detect_severity_anomalies()` monitora separatamente CRITICAL (soglia min 2) e
HIGH (soglia min 3) con la stessa baseline adattiva.

Con `suggest_playbooks=True`, `dispatch.send_timeline_alert()` arricchisce ogni
anomalia con il playbook Sleipnir più pertinente (soglia 0.4), sempre come
**sola proposta**: nessuna esecuzione automatica.

## Baseline adattiva vs globale

| Scenario | Media globale | Baseline adattiva |
|----------|--------------|-------------------|
| Spike vecchio + spike recente | spike recente mascherato | ✅ rilevato |
| Incremento graduale del traffico | falsi positivi persistenti | ✅ baseline segue il traffico |
| Traffico costante | equivalente | equivalente |

## Parametri di detection configurabili

La sensitivity della spike detection è tarabile via API (con clamping sicuro):

```
GET /api/v1/rag/timeline?spike_factor=2.0&min_spike=5
```

- `spike_factor`: 1.5–10 (default 3.0) — quante volte la baseline deve essere superata
- `min_spike`: 1–50 (default 3) — soglia minima assoluta di alert per parlare di spike

Valori fuori range sono limitati agli intervalli sopra; i default restano invariati
se i parametri non sono passati.

## Grafico con barre impilate per severità

Nella dashboard ogni barra giornaliera è segmentata per severità
(CRITICAL rosso, HIGH arancio, MEDIUM giallo, LOW blu) con legenda e tooltip
per severità. Nessuna libreria esterna: solo CSS flexbox, coerente con la
filosofia locale-first della suite.

Oltre allo spike totale, `TimelineEngine.detect_severity_anomalies()` monitora
spike **per severità** (solo CRITICAL e HIGH; MEDIUM/LOW sono rumore):
- CRITICAL: soglia `max(3 × media CRITICAL, 2)` — pochi alert critici nello stesso giorno bastano
- HIGH: soglia `max(3 × media HIGH, 3)`

## Anomalia → Playbook Suggerito (read-only)

`TimelineEngine.suggest_playbook_for_anomaly(anomaly)` estrae le regole dominanti
del giorno anomalo dai documenti indicizzati e usa la ricerca semantica per
proporre il playbook Sleipnir più pertinente (sopra soglia 0.4). Il messaggio
di alert Gjallarhorn (`send_timeline_alert`) include il suggerimento con la
dicitura esplicita "sola proposta, nessuna esecuzione automatica" — la decisione
resta sempre all'analista.

`TimelineEngine.detect_anomalies()` — regola deterministica, zero LLM:

- Un giorno è anomalo se `count >= max(3 × media giornaliera, 3 alert)`
- `min_spike` evita falsi positivi su basi di traffico quasi nulle
- Le anomalie sono incluse in `GET /api/v1/rag/timeline` e mostrate nella dashboard
- Alert via Gjallarhorn:
  - API: `POST /api/v1/rag/timeline/notify` (auth)
  - CLI: `python -m rag.cli anomalies [--days 30]`
  - Nessuna anomalia → nessun invio (evita rumore)
  - Severità: CRITICAL presente nel giorno anomalo → `critical`, altrimenti `high`

## Notifica via Gjallarhorn

`rag/dispatch.py` invia il digest del report proattivo all'hub centralizzato Gjallarhorn
(che lo instrada su Telegram/email/webhook), seguendo le convenzioni della suite:

- Configurazione via env: `GJALLARHORN_HUB_URL` + `GJALLARHORN_API_KEY`
- Hub non configurato → **nessun tentativo di rete**, esito inerte (`sent=false, configured=false`)
- `notify()` non solleva mai eccezioni: hub irraggiungibile → log warning, mai crash
- **Severità derivata deterministicamente dai dati** (no LLM):
  - Presenza di alert CRITICAL → `critical`
  - Alert HIGH con ≥5 occorrenze sullo stesso IP → `medium` (flood)
  - Alert HIGH isolati → `high`
  - Nessun alert → `low`

### Uso

```bash
# CLI
python -m rag.cli notify            # invia il digest via Gjallarhorn
python -m rag.cli notify --save     # salva anche il report Markdown completo

# API
curl -X POST http://localhost:8080/api/v1/rag/report/notify \
  -H "X-API-Key: your-key"
```

```python
from rag.dispatch import send_report, export_and_notify
send_report()                          # solo digest
export_and_notify()                    # report Markdown completo + digest
```

## Utilizzo

### Indicizza i dati

```bash
curl -X POST http://localhost:8080/api/v1/rag/index \
  -H "X-API-Key: your-key"
```

### Query semantica

```bash
curl -X POST http://localhost:8080/api/v1/rag/query \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"query": "Quali minacce sono state rilevate?", "n_results": 5}'
```

### Chat con contesto RAG

```bash
curl -X POST http://localhost:8080/api/v1/chat \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Come è la situazione della rete?", "session_id": "analyst-1"}'
```

## Configurazione

Variabili d'ambiente opzionali:

| Variabile | Default | Descrizione |
|-----------|---------|-------------|
| `ASGARD_ROOT` | `../../..` | Path radice della suite Asgard |
| `ASGARD_RAG_DB_PATH` | `.asgard-suite-repo/rag_db` | Path database vettoriale |

## Test

```bash
# Test modulo RAG
cd Ragnarok/backend
python -m pytest tests/test_rag.py -v

# Test API server (incluse API RAG)
cd Ragnarok
python -m pytest tests/test_server.py -v
```

## Dipendenze

```
chromadb>=1.0.0      # Vector database
fastembed>=0.8.0     # Embedding ONNX (leggero, no PyTorch)
numpy>=1.24.0        # Operazioni numeriche
```

## Sicurezza

- Endpoint di scrittura (`/index`, `/query`) richiedono `X-API-Key`
- Endpoint di lettura (`/stats`, `/sessions`) sono pubblici
- La dashboard è servita solo in locale (127.0.0.1)
- Nessun dato viene inviato a servizi esterni (tutto locale)

## Security Dashboard

Dashboard HTML dedicata al security audit della configurazione (`/security`).

**Endpoint:**
```
GET /api/v1/rag/security/audit    → audit completo (auth, JSON)
GET /api/v1/rag/security/report   → report Markdown (auth, download)
```

**Verificate:**
- Autenticazione API (RAGNAROK, Gjallarhorn, Bifrost)
- Crittografia database a riposo
- Data retention configurata
- Esposizione di rete (0.0.0.0 vs 127.0.0.1)

**Output:** Security Score 0-100 con grade (A-F), findings per severità (CRITICAL/HIGH/MEDIUM/LOW/INFO), raccomandazioni azionabili.

## GDPR Compliance per Agenti + Raccomandazione per PMI

`rag/gdpr.py` offre due funzionalità complementari per le PMI italiane:

### 1. Autovalutazione GDPR (Checklist)

Checklist basata sugli articoli GDPR più rilevanti per PMI, con punteggio pesato:

| Articolo | Principio | Peso |
|----------|-----------|------|
| art. 5.1.a | Inventario dati personali | 3 |
| art. 6 | Gestione consenso | 3 |
| art. 5.1.c | Minimizzazione dati | 2 |
| art. 5.1.e | Limitazione conservazione | 2 |
| art. 32 | Misure di sicurezza | 3 |
| art. 33 | Notifica breach (72h) | 2 |
| art. 37 | Nomina DPO | 1 |
| art. 25 | Privacy by design | 2 |
| art. 15-22 | Diritti interessato | 2 |
| art. 35 | DPIA | 1 |

**Livelli:** critico (<40%), sufficiente (40-59%), buono (60-79%), ottimo (≥80%)

**Endpoint:**
```
POST /api/v1/rag/gdpr/checklist   → valuta le risposte (auth richiesta)
```

### 2. Raccomandazione Agenti per PMI

Suggerisce quali agenti Asgard attivare in base a:
- **Dimensione:** micro (1-9), small (10-49), medium (50-249), enterprise (250+)
- **Settore:** sanità/finanza/assicurazioni → aggiunge threat intelligence e scan di rete
- **Maturità:** base → disabilita orchestrazione (Sleipnir), avanzata → la include

| Dimensione | Consigliati | Opzionali |
|------------|-------------|-----------|
| Micro | Heimdall, Forseti | Fenrir |
| Small | Heimdall, Forseti, Fenrir | Bifrost |
| Medium | + Bifrost | Mjolnir, Sleipnir |
| Enterprise | Tutti e 6 | — |

**Endpoint:**
```
GET /api/v1/rag/gdpr/recommend?size=micro&sector=sanita&maturity=base
```

### Report Completo

```bash
python -m rag.cli gdpr report --size medium --sector finanza --maturity avanzata
```

Genera un report unificato: autovalutazione + raccomandazione agenti + retention policy + disclaimer legale.

**Nota:** Questo strumento fornisce un'autovalutazione indicativa. Per una consulenza GDPR completa, rivolgiti a un DPO qualificato.

## Note Tecniche

- **Modello embedding**: `BAAI/bge-small-en-v1.5` (384 dimensioni, ~90MB)
- **Similarità**: Coseno (HNSW index)
- **Chunking**: Max 4000 caratteri per documento
- **Deduplicazione**: Re-indicizzazione resetta le collection (no duplicati)
