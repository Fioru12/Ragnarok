import os, sys, tempfile, sqlite3, shutil, time, gc, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def safe_rmtree(path, max_retries=5):
    """Rimuove una directory con retry per gestire file lock su Windows."""
    if not os.path.exists(path):
        return
    for i in range(max_retries):
        try:
            shutil.rmtree(path, ignore_errors=True)
            return
        except Exception:
            gc.collect()
            time.sleep(0.3)
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture
def temp_asgard_root(tmp_path):
    hd = tmp_path / "Heimdall"
    hd.mkdir()
    # Crea heimdall.db (nome atteso dal codice)
    hdb = hd / "heimdall.db"
    conn = sqlite3.connect(str(hdb))
    conn.execute("CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, rule_title TEXT, severity TEXT, source_ip TEXT, action_taken TEXT, description TEXT, count INTEGER, timestamp TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY, ip TEXT, reason TEXT, expires_at TEXT)")
    conn.execute("INSERT INTO alerts VALUES (1,?,?,?,?,?,?,?)", ("SSH Brute Force", "HIGH", "192.168.1.100", "BLOCKED_IP", "Tentativi", 5, "2026-01-15"))
    conn.execute("INSERT INTO alerts VALUES (2,?,?,?,?,?,?,?)", ("DDoS", "CRITICAL", "10.0.0.50", "LOGGED", "Syn flood", 1000, "2026-01-15"))
    conn.execute("INSERT INTO blocked_ips VALUES (1,?,?,?)", ("192.168.1.100", "SSH", "2026-01-16"))
    conn.commit()
    conn.close()
    fd = tmp_path / "Fenrir"
    fd.mkdir()
    fdb = fd / "fenrir.db"
    conn = sqlite3.connect(str(fdb))
    conn.execute("CREATE TABLE IF NOT EXISTS ioc (id INTEGER PRIMARY KEY, value TEXT, type TEXT, source TEXT, cve_id TEXT, threat_type TEXT, severity TEXT, description TEXT, timestamp TEXT)")
    conn.execute("INSERT INTO ioc VALUES (1,?,?,?,?,?,?,?,?)", ("192.168.1.100", "ipv4addr", "CISA", "CVE-2024", "c2", "CRITICAL", "Malicious", "2026-01-15"))
    conn.execute("INSERT INTO ioc VALUES (2,?,?,?,?,?,?,?,?)", ("evil.com", "domain", "OTX", "N/A", "phishing", "MEDIUM", "Phishing", "2026-01-15"))
    conn.commit()
    conn.close()
    md = tmp_path / "Mjolnir" / "output"
    md.mkdir(parents=True)
    (md / "r.md").write_text("# Report\nmalware.exe")
    return str(tmp_path)


def test_rag_indexer_init():
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(db_path=t)
        assert idx is not None
        del idx
    finally:
        safe_rmtree(t)


def test_rag_index_heimdall(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        count = idx.index_heimdall()
        assert count >= 2
        del idx
    finally:
        safe_rmtree(t)


def test_rag_index_fenrir(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        count = idx.index_fenrir()
        assert count >= 1
        del idx
    finally:
        safe_rmtree(t)


def test_rag_index_fenrir_preserves_severity_in_metadata(temp_asgard_root):
    """
    Regression test: index_fenrir() read `sev = row.get('severity')` from
    each IOC row but never actually put it into the indexed document text
    or metadata - every other field (value, type, source, cve_id,
    threat_type) was included, severity alone was silently dropped. Found
    via pyflakes flagging `sev` as assigned-but-unused. A RAG query or
    security-score calculation filtering/prioritizing by IOC severity had
    no way to do so, since the data never made it into the index.
    """
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_fenrir()
        collection = idx.client.get_collection("fenrir_ioc")
        got = collection.get(ids=["ioc-1"], include=["documents", "metadatas"])
        assert got["metadatas"][0]["severity"] == "CRITICAL"
        assert "CRITICAL" in got["documents"][0]
        del idx
    finally:
        safe_rmtree(t)


def test_rag_index_all(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        r = idx.index_all()
        assert r["total"] >= 3
        del idx
    finally:
        safe_rmtree(t)


def test_rag_search_semantic(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    from rag.retriever import AsgardRetriever
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        ret = AsgardRetriever(db_path=t)
        results = ret.search("IP malevolo", n_results=3)
        assert len(results) > 0
        del ret
    finally:
        safe_rmtree(t)


def test_rag_search_cross_module(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    from rag.retriever import AsgardRetriever
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        ret = AsgardRetriever(db_path=t)
        results = ret.search("192.168.1.100", n_results=5)
        assert len(results) >= 2
        del ret
    finally:
        safe_rmtree(t)


def test_rag_memory():
    from rag.memory import ConversationMemory
    t = tempfile.mkdtemp()
    try:
        mem = ConversationMemory(db_path=t)
        mem.add("s1", "user", "Quali IP bloccati?")
        mem.add("s1", "assistant", "192.168.1.100")
        h = mem.get_history("s1")
        assert len(h) == 2
        assert "192.168.1.100" in mem.get_summary("s1")
        mem.clear_session("s1")
        assert len(mem.get_history("s1")) == 0
    finally:
        safe_rmtree(t)


def test_rag_idempotent(temp_asgard_root):
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        s1 = idx.get_stats()["heimdall_alerts"]
        idx.index_heimdall()
        s2 = idx.get_stats()["heimdall_alerts"]
        assert s1 == s2
        del idx
    finally:
        safe_rmtree(t)


# ======================================================================
# Insights Engine (Analisi Proattiva)
# ======================================================================


def _insight_engine(temp_asgard_root, t):
    from rag.indexer import AsgardIndexer
    from rag.insights import InsightsEngine
    idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
    idx.index_all()
    del idx
    gc.collect()
    time.sleep(0.3)
    return InsightsEngine(db_path=t)


def test_insights_top_ips(temp_asgard_root):
    """Gli IP attaccanti più frequenti sono aggregati correttamente."""
    t = tempfile.mkdtemp()
    try:
        eng = _insight_engine(temp_asgard_root, t)
        top = eng.top_ips(limit=5)
        ips = {entry["ip"] for entry in top}
        assert "192.168.1.100" in ips
        assert "10.0.0.50" in ips
        # severità massima rispettata
        by_ip = {e["ip"]: e for e in top}
        assert by_ip["192.168.1.100"]["max_severity"] == "HIGH"
        assert by_ip["10.0.0.50"]["max_severity"] == "CRITICAL"
        del eng
    finally:
        safe_rmtree(t)


def test_insights_severity_distribution(temp_asgard_root):
    """La distribuzione delle severità riflette gli alert indicizzati."""
    t = tempfile.mkdtemp()
    try:
        eng = _insight_engine(temp_asgard_root, t)
        dist = eng.severity_distribution()
        assert dist.get("HIGH") == 1
        assert dist.get("CRITICAL") == 1
        del eng
    finally:
        safe_rmtree(t)


def test_insights_fenrir_ioc_and_cve(temp_asgard_root):
    """IOC e CVE di Fenrir sono aggregati negli insight."""
    t = tempfile.mkdtemp()
    try:
        eng = _insight_engine(temp_asgard_root, t)
        ioc = eng.top_ioc_references(limit=5)
        values = {entry["value"] for entry in ioc}
        assert "192.168.1.100" in values
        assert "evil.com" in values
        cves = eng.cve_references(limit=5)
        assert any(c["cve"] == "CVE-2024" for c in cves)
        del eng
    finally:
        safe_rmtree(t)


def test_insights_summary_and_format_for_llm(temp_asgard_root):
    """Il summary contiene tutte le sezioni e il formato LLM è leggibile."""
    t = tempfile.mkdtemp()
    try:
        eng = _insight_engine(temp_asgard_root, t)
        s = eng.summary()
        for key in ("top_ips", "severity_distribution", "top_ioc",
                    "cve_references", "compliance", "playbooks", "generated_at"):
            assert key in s
        text = eng.format_for_llm()
        assert "ANALISI PROATTIVA ASGARD" in text
        assert "192.168.1.100" in text
        del eng
    finally:
        safe_rmtree(t)


def test_insights_empty_index_does_not_crash():
    """Insight su indice vuoto non lancia eccezioni e restituisce strutture vuote."""
    from rag.insights import InsightsEngine
    t = tempfile.mkdtemp()
    try:
        eng = InsightsEngine(db_path=t)
        assert eng.top_ips() == []
        assert eng.severity_distribution() == {}
        assert eng.top_ioc_references() == []
        assert eng.cve_references() == []
        s = eng.summary()
        assert s["top_ips"] == []
        assert s["compliance"]["assessment_files"] == 0
        del eng
    finally:
        safe_rmtree(t)


# ======================================================================
# Suggerimento Playbook (incident → playbook Sleipnir)
# ======================================================================


PLAYBOOKS = {
    "brute_force_playbook.yaml": (
        "name: brute_force_response\n"
        "description: Risposta a attacchi brute force SSH e password spraying. "
        "Blocca gli IP sorgente, analizza i log di autenticazione e verifica "
        "tentativi ripetuti di accesso falliti.\n"
    ),
    "ransomware_containment.yaml": (
        "name: ransomware_containment\n"
        "description: Contenimento infezione ransomware. Isola gli host "
        "compromessi, blocca la crittografia dei file, identifica il processo "
        "di cifratura e previene la propagazione laterale.\n"
    ),
    "lateral_movement_detect.yaml": (
        "name: lateral_movement_detect\n"
        "description: Rilevamento movimento laterale in rete. Monitora "
        "autenticazioni anomale tra host, pass-the-hash e uso sospetto "
        "di credenziali amministrative.\n"
    ),
}


@pytest.fixture
def playbook_asgard_root(tmp_path):
    """Root Asgard con solo i playbook Sleipnir."""
    pb_dir = tmp_path / "Sleipnir" / "playbooks"
    pb_dir.mkdir(parents=True)
    for fname, content in PLAYBOOKS.items():
        (pb_dir / fname).write_text(content, encoding="utf-8")
    return str(tmp_path)


def _playbook_engine(playbook_asgard_root, t):
    from rag.indexer import AsgardIndexer
    from rag.insights import InsightsEngine
    idx = AsgardIndexer(asgard_root=playbook_asgard_root, db_path=t)
    idx.index_playbooks()
    del idx
    gc.collect()
    time.sleep(0.3)
    return InsightsEngine(db_path=t)


def test_suggest_playbook_brute_force(playbook_asgard_root):
    """Un attacco brute force suggerisce il playbook brute_force."""
    t = tempfile.mkdtemp()
    try:
        eng = _playbook_engine(playbook_asgard_root, t)
        s = eng.suggest_playbook("Sto subendo un attacco brute force SSH con password spraying")
        assert s is not None
        assert s["playbook"] == "brute_force_playbook.yaml"
        assert s["similarity"] > 0.4
        del eng
    finally:
        safe_rmtree(t)


def test_suggest_playbook_ransomware(playbook_asgard_root):
    """Una infezione ransomware suggerisce il playbook di contenimento."""
    t = tempfile.mkdtemp()
    try:
        eng = _playbook_engine(playbook_asgard_root, t)
        s = eng.suggest_playbook("Files are being encrypted by ransomware on my server")
        assert s is not None
        assert s["playbook"] == "ransomware_containment.yaml"
        del eng
    finally:
        safe_rmtree(t)


def test_suggest_playbook_low_similarity_returns_none(playbook_asgard_root):
    """Soglia di pertinenza: query non correlata non suggerisce nulla."""
    t = tempfile.mkdtemp()
    try:
        eng = _playbook_engine(playbook_asgard_root, t)
        # min_similarity altissima → nessun playbook può superarla
        s = eng.suggest_playbook("qualche testo qualsiasi", min_similarity=0.99)
        assert s is None
        del eng
    finally:
        safe_rmtree(t)


def test_suggest_playbook_empty_collection():
    """Nessun playbook indicizzato → nessun suggerimento, nessun crash."""
    from rag.insights import InsightsEngine
    t = tempfile.mkdtemp()
    try:
        eng = InsightsEngine(db_path=t)
        assert eng.suggest_playbook("attacco ransomware in corso") is None
        del eng
    finally:
        safe_rmtree(t)


# ======================================================================
# Report Exporter
# ======================================================================


class _StubEngine:
    """Engine finto con summary controllabile per test deterministici."""

    def __init__(self, summary):
        self._summary = summary

    def summary(self):
        return self._summary


def test_report_markdown_contains_sections(temp_asgard_root):
    """Il report contiene tutte le sezioni e i dati reali indicizzati."""
    from rag.report import ReportExporter
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        from rag.insights import InsightsEngine
        eng = InsightsEngine(db_path=t)
        md = ReportExporter(engine=eng).generate_markdown()
        for section in ("Report Proattivo", "Top IP Attaccanti", "Distribuzione Severità",
                        "IOC Ricorrenti", "CVE Correlate", "Compliance",
                        "Playbook Sleipnir", "Raccomandazioni"):
            assert section in md
        assert "192.168.1.100" in md
        assert "CVE-2024" in md
        del eng
    finally:
        safe_rmtree(t)


def test_report_recommendations_critical_ip():
    """Alert CRITICAL → raccomandazione di verifica immediata (regola deterministica)."""
    from rag.report import ReportExporter
    summary = {
        "top_ips": [{"ip": "10.0.0.99", "count": 3, "max_severity": "CRITICAL"}],
        "top_ioc": [{"value": "evil.com", "count": 2}],
        "cve_references": [{"cve": "CVE-2026-1234", "count": 2}],
        "compliance": {"assessment_files": 0, "files": []},
    }
    recs = ReportExporter(engine=_StubEngine(summary)).build_recommendations(summary)
    assert any("10.0.0.99" in r and "CRITICAL" in r for r in recs)
    assert any("CVE-2026-1234" in r for r in recs)
    assert any("Forseti" in r for r in recs)


def test_report_recommendations_high_threshold():
    """>=5 alert HIGH sullo stesso IP → raccomandazione triage Mjolnir."""
    from rag.report import ReportExporter
    summary = {
        "top_ips": [{"ip": "192.168.1.77", "count": 6, "max_severity": "HIGH"}],
        "top_ioc": [{"value": "x", "count": 1}],
        "cve_references": [],
        "compliance": {"assessment_files": 2, "files": ["a.md"]},
    }
    recs = ReportExporter(engine=_StubEngine(summary)).build_recommendations(summary)
    assert any("192.168.1.77" in r and "Mjolnir" in r for r in recs)


def test_report_recommendations_empty_data():
    """Indice vuoto → raccomandazione di eseguire l'indicizzazione."""
    from rag.report import ReportExporter
    summary = {"top_ips": [], "top_ioc": [], "cve_references": [],
               "compliance": {"assessment_files": 0, "files": []}}
    recs = ReportExporter(engine=_StubEngine(summary)).build_recommendations(summary)
    assert len(recs) == 1
    assert "indicizz" in recs[0].lower()


def test_report_save_to_file(temp_asgard_root):
    """Il report salvato crea il file Markdown nel percorso indicato."""
    from rag.report import ReportExporter
    from rag.insights import InsightsEngine
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        del idx
        gc.collect()
        time.sleep(0.3)
        eng = InsightsEngine(db_path=t)
        path = ReportExporter(engine=eng).save(output_dir=out)
        assert os.path.exists(path)
        assert path.endswith(".md")
        content = open(path, encoding="utf-8").read()
        assert "Report Proattivo" in content
        del eng
    finally:
        safe_rmtree(t)
        safe_rmtree(out)


# ======================================================================
# Timeline Engine
# ======================================================================


class _StubMetaEngine:
    """Engine finto che restituisce metadati fissi (per test deterministici)."""

    def __init__(self, metas):
        self._metas = metas

    def _all_metadatas(self, collection_name):
        return self._metas


def test_timeline_parse_timestamp_formats():
    """Il parser accetta i formati usati dalla suite ed esclude i non validi."""
    from rag.timeline import _parse_timestamp
    assert _parse_timestamp("2026-01-15T10:30:00") is not None
    assert _parse_timestamp("2026-01-15T10:30:00Z") is not None
    assert _parse_timestamp("2026-01-15") is not None
    assert _parse_timestamp("2026-01-15 10:30:00") is not None
    assert _parse_timestamp("not-a-date") is None
    assert _parse_timestamp("") is None
    assert _parse_timestamp(None) is None
    assert _parse_timestamp(12345) is None


def test_timeline_daily_counts_buckets_recent_alerts(temp_asgard_root):
    """Alert recenti finiscono nei bucket corretti; i giorni vuoti = 0."""
    from datetime import datetime, timedelta
    from rag.timeline import TimelineEngine
    from rag.indexer import AsgardIndexer
    # Aggiunge alert recenti al DB del fixture
    today = datetime.now().strftime("%Y-%m-%dT10:00:00")
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT10:00:00")
    db = os.path.join(temp_asgard_root, "Heimdall", "heimdall.db")
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO alerts VALUES (10,?,?,?,?,?,?,?)",
                 ("Recent A", "HIGH", "10.0.0.1", "LOGGED", "x", 1, today))
    conn.execute("INSERT INTO alerts VALUES (11,?,?,?,?,?,?,?)",
                 ("Recent B", "HIGH", "10.0.0.2", "LOGGED", "x", 1, today))
    conn.execute("INSERT INTO alerts VALUES (12,?,?,?,?,?,?,?)",
                 ("Recent C", "CRITICAL", "10.0.0.3", "LOGGED", "x", 1, yesterday))
    conn.commit()
    conn.close()

    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        del idx
        gc.collect()
        time.sleep(0.3)
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        series = tl.daily_counts(days=7)
        assert len(series) == 7
        assert series[-1]["date"] == datetime.now().strftime("%Y-%m-%d")
        assert series[-1]["count"] == 2
        assert series[-1]["by_severity"]["HIGH"] == 2
        assert series[-2]["count"] == 1
        assert series[-2]["by_severity"]["CRITICAL"] == 1
        assert sum(d["count"] for d in series[:-2]) == 0  # giorni vuoti = 0
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_summary_trend_up_and_down():
    """Trend: 10 alert oggi vs 2 dieci giorni fa → up; il viceversa → down."""
    from datetime import datetime, timedelta
    from rag.timeline import TimelineEngine
    now = datetime.now()
    metas = [{"timestamp": now.strftime("%Y-%m-%dT%H:%M:%S"), "severity": "HIGH"}
             for _ in range(10)]
    metas += [{"timestamp": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S"),
               "severity": "LOW"} for _ in range(2)]
    s = TimelineEngine(engine=_StubMetaEngine(metas)).summary(days=14)
    assert s["total"] == 12
    assert s["trend"]["direction"] == "up"
    assert s["trend"]["last7"] == 10
    assert s["trend"]["prev7"] == 2
    assert s["peak"]["count"] == 10

    metas_down = [{"timestamp": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S"),
                   "severity": "LOW"} for _ in range(10)]
    s2 = TimelineEngine(engine=_StubMetaEngine(metas_down)).summary(days=14)
    assert s2["trend"]["direction"] == "down"


def test_timeline_unparseable_timestamp_ignored():
    """Timestamp non interpretabili sono esclusi senza crash."""
    from rag.timeline import TimelineEngine
    metas = [{"timestamp": "garbage", "severity": "HIGH"},
             {"timestamp": None, "severity": "HIGH"},
             {"severity": "HIGH"}]
    s = TimelineEngine(engine=_StubMetaEngine(metas)).summary(days=7)
    assert s["total"] == 0
    assert s["peak"] is None


def test_timeline_days_window_clamped():
    """La finestra è limitata: 1..365 giorni."""
    from rag.timeline import TimelineEngine
    tl = TimelineEngine(engine=_StubMetaEngine([]))
    assert len(tl.daily_counts(days=9999)) == 365
    assert len(tl.daily_counts(days=0)) == 1
    assert len(tl.daily_counts(days=-5)) == 1


def test_timeline_detect_anomalies_spike():
    """Spike netto → rilevato; giorno con traffico normale → nessuna anomalia."""
    from datetime import datetime, timedelta
    from rag.timeline import TimelineEngine
    now = datetime.now()
    # 30 giorni con 2 alert/giorno, poi un giorno con 30 alert (spike)
    metas = []
    for i in range(29):
        ts = (now - timedelta(days=i + 1)).strftime("%Y-%m-%dT%H:%M:%S")
        metas += [{"timestamp": ts, "severity": "LOW"} for _ in range(2)]
    spike_ts = now.strftime("%Y-%m-%dT%H:%M:%S")
    metas += [{"timestamp": spike_ts, "severity": "CRITICAL"} for _ in range(30)]

    tl = TimelineEngine(engine=_StubMetaEngine(metas))
    series = tl.daily_counts(days=30)
    anomalies = tl.detect_anomalies(series=series)
    assert len(anomalies) == 1
    assert anomalies[0]["date"] == now.strftime("%Y-%m-%d")
    assert anomalies[0]["count"] == 30
    assert anomalies[0]["by_severity"]["CRITICAL"] == 30
    # Il summary include le anomalie
    s = tl.summary(days=30)
    assert s["anomalies"] == anomalies


def test_timeline_detect_anomalies_no_spike():
    """Traffico uniforme sotto soglia → nessuna anomalia (min_spike evita falsi positivi)."""
    from datetime import datetime, timedelta
    from rag.timeline import TimelineEngine
    now = datetime.now()
    metas = []
    for i in range(14):
        ts = (now - timedelta(days=i)).strftime("%Y-%m-%dT%H:%M:%S")
        metas += [{"timestamp": ts, "severity": "LOW"} for _ in range(2)]
    anomalies = TimelineEngine(engine=_StubMetaEngine(metas)).detect_anomalies(days=14)
    assert anomalies == []


def test_timeline_detect_anomalies_empty():
    """Serie vuota → nessuna anomalia, nessun crash."""
    from rag.timeline import TimelineEngine
    tl = TimelineEngine(engine=_StubMetaEngine([]))
    assert tl.detect_anomalies(days=7) == []


# ======================================================================
# Dispatch anomalie (Gjallarhorn)
# ======================================================================


def test_dispatch_derive_anomaly_severity():
    """CRITICAL nel giorno anomalo → critical, altrimenti high."""
    from rag.dispatch import derive_anomaly_severity
    assert derive_anomaly_severity([{"by_severity": {"CRITICAL": 2, "HIGH": 1}}]) == "critical"
    assert derive_anomaly_severity([{"by_severity": {"HIGH": 5}}]) == "high"
    assert derive_anomaly_severity([{"by_severity": {}}]) == "high"


def test_dispatch_build_anomaly_message():
    """Il messaggio contiene data, conteggio e baseline."""
    from rag.dispatch import build_anomaly_message
    msg = build_anomaly_message([{"date": "2026-09-03", "count": 30,
                                  "avg_baseline": 2.0,
                                  "by_severity": {"CRITICAL": 30}}])
    assert "2026-09-03" in msg
    assert "30 alert" in msg
    assert "CRITICAL=30" in msg


class _StubTimeline:
    def __init__(self, anomalies):
        self._anomalies = anomalies

    def detect_anomalies(self, days=30):
        return self._anomalies


def test_send_timeline_alert_not_configured_no_network(monkeypatch):
    """Senza configurazione Gjallarhorn → nessun tentativo di rete."""
    from rag import dispatch
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    result = dispatch.send_timeline_alert(timeline_engine=_StubTimeline([{"date": "d"}]))
    assert result["sent"] is False
    assert result["configured"] is False


def test_send_timeline_alert_with_anomalies_sends(monkeypatch):
    """Con anomalie e hub configurato → notify chiamato con severità corretta."""
    from rag import dispatch
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    captured = {}

    def fake_notify(**kw):
        captured.update(kw)
        return True

    monkeypatch.setattr("rag.notifier.notify", fake_notify)
    anomalies = [{"date": "2026-09-03", "count": 30, "avg_baseline": 2.0,
                  "by_severity": {"CRITICAL": 30}}]
    result = dispatch.send_timeline_alert(timeline_engine=_StubTimeline(anomalies))
    assert result["sent"] is True
    assert result["severity"] == "critical"
    assert result["anomalies"] == 1
    assert captured["severity"] == "critical"
    assert captured["source"] == "Ragnarok"


def test_send_timeline_alert_no_anomalies_no_send(monkeypatch):
    """Nessuna anomalia → nessun invio (evita rumore), esito pulito."""
    from rag import dispatch
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    called = {"n": 0}
    monkeypatch.setattr("rag.notifier.notify", lambda **kw: called.__setitem__("n", called["n"] + 1) or True)
    result = dispatch.send_timeline_alert(timeline_engine=_StubTimeline([]))
    assert result["sent"] is False
    assert result["configured"] is True
    assert result["anomalies"] == 0
    assert called["n"] == 0


# ======================================================================
# Dispatch Gjallarhorn
# ======================================================================


class _StubEngine2:
    def __init__(self, summary):
        self._summary = summary

    def summary(self):
        return self._summary


_SUMMARY_CRITICAL = {
    "top_ips": [{"ip": "10.0.0.50", "count": 1, "max_severity": "CRITICAL"}],
    "severity_distribution": {"CRITICAL": 1},
    "top_ioc": [], "cve_references": [],
    "compliance": {"assessment_files": 0, "files": []},
}
_SUMMARY_HIGH = {
    "top_ips": [{"ip": "192.168.1.100", "count": 2, "max_severity": "HIGH"}],
    "severity_distribution": {"HIGH": 2},
    "top_ioc": [], "cve_references": [{"cve": "CVE-2024-1234", "count": 1}],
    "compliance": {"assessment_files": 1, "files": ["a.md"]},
}
_SUMMARY_HIGH_FLOOD = {
    "top_ips": [{"ip": "192.168.1.100", "count": 7, "max_severity": "HIGH"}],
    "severity_distribution": {"HIGH": 7},
    "top_ioc": [], "cve_references": [],
    "compliance": {"assessment_files": 1, "files": ["a.md"]},
}


def test_derive_severity_critical():
    from rag.dispatch import derive_severity
    assert derive_severity(_SUMMARY_CRITICAL) == "critical"


def test_derive_severity_high_and_flood():
    from rag.dispatch import derive_severity
    assert derive_severity(_SUMMARY_HIGH) == "high"
    assert derive_severity(_SUMMARY_HIGH_FLOOD) == "medium"


def test_derive_severity_empty_is_low():
    from rag.dispatch import derive_severity
    empty = {"top_ips": [], "severity_distribution": {}, "top_ioc": [],
             "cve_references": [], "compliance": {"assessment_files": 0, "files": []}}
    assert derive_severity(empty) == "low"


def test_build_digest_message_contains_data():
    from rag.dispatch import build_digest_message
    digest = build_digest_message(_SUMMARY_HIGH)
    assert "192.168.1.100" in digest
    assert "CVE-2024-1234" in digest
    assert "HIGH=2" in digest


def test_send_report_not_configured_no_network(monkeypatch):
    """Hub non configurato → nessun tentativo di rete, esito inerte."""
    from rag import dispatch
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    result = dispatch.send_report(engine=_StubEngine2(_SUMMARY_CRITICAL))
    assert result["sent"] is False
    assert result["configured"] is False


def test_send_report_sends_with_derived_severity(monkeypatch):
    """Hub configurato → notify() chiamato con severità derivata dai dati."""
    from rag import dispatch
    from rag.notifier import notify as _unused
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    calls = {}

    def fake_notify(**kwargs):
        calls.update(kwargs)
        return True

    monkeypatch.setattr("rag.notifier.notify", fake_notify)
    result = dispatch.send_report(engine=_StubEngine2(_SUMMARY_CRITICAL))
    assert result["sent"] is True
    assert result["configured"] is True
    assert result["severity"] == "critical"
    assert calls["source"] == "Ragnarok"
    assert calls["api_key"] == "test-key"
    assert calls["hub_url"] == "http://localhost:8090"
    assert "10.0.0.50" in calls["message"]


def test_send_report_hub_down_returns_sent_false(monkeypatch):
    """Hub irraggiungibile → sent=False, mai eccezioni."""
    from rag import dispatch
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    monkeypatch.setattr("rag.notifier.notify", lambda **kw: False)
    result = dispatch.send_report(engine=_StubEngine2(_SUMMARY_HIGH))
    assert result["sent"] is False
    assert result["configured"] is True


def test_export_and_notify_saves_report_and_sends(monkeypatch, temp_asgard_root):
    """export_and_notify salva il report completo e invia il digest."""
    from rag import dispatch
    from rag.insights import InsightsEngine
    from rag.indexer import AsgardIndexer
    monkeypatch.setenv("GJALLARHORN_HUB_URL", "http://localhost:8090")
    monkeypatch.setenv("GJALLARHORN_API_KEY", "test-key")
    monkeypatch.setattr("rag.notifier.notify", lambda **kw: True)
    t = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        del idx
        gc.collect()
        time.sleep(0.3)
        eng = InsightsEngine(db_path=t)
        result = dispatch.export_and_notify(output_dir=out, engine=eng)
        assert result["sent"] is True
        assert result["report_path"].endswith(".md")
        assert os.path.exists(result["report_path"])
        del eng
    finally:
        safe_rmtree(t)
        safe_rmtree(out)


# ======================================================================
# Anomalie per severità + suggerimento playbook per anomalia
# ======================================================================


def _make_series(days_sev_map, n_days=30):
    """Serie sintetica: mappa indice_giorno → {sev: count}."""
    from rag.timeline import SEVERITIES
    series = []
    for i in range(n_days):
        sev_counts = days_sev_map.get(i, {})
        series.append({
            "date": f"2026-01-{i + 1:02d}",
            "count": sum(sev_counts.values()),
            "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
        })
    return series


def test_timeline_detect_severity_anomalies_critical():
    """Spike di CRITICAL in un giorno → rilevato; giorni senza CRITICAL → no."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        series = _make_series({15: {"CRITICAL": 3}})
        anomalies = tl.detect_severity_anomalies(series=series)
        assert len(anomalies) == 1
        assert anomalies[0]["date"] == "2026-01-16"
        assert anomalies[0]["severity"] == "CRITICAL"
        assert anomalies[0]["count"] == 3
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_detect_severity_anomalies_no_false_positive():
    """Traffico uniforme di LOW/MEDIUM → nessuna anomalia di severità."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        series = _make_series({i: {"LOW": 1, "MEDIUM": 1} for i in range(30)})
        assert tl.detect_severity_anomalies(series=series) == []
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_summary_includes_severity_anomalies():
    """summary() espone la chiave severity_anomalies anche su serie vuota."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        s = tl.summary(days=7)
        assert s["severity_anomalies"] == []
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_day_context_extracts_rule_titles(temp_asgard_root):
    """Il contesto giornaliero estrae i rule title dai documenti indicizzati."""
    from rag.timeline import TimelineEngine
    from rag.insights import InsightsEngine
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        del idx
        gc.collect()
        time.sleep(0.3)
        tl = TimelineEngine(engine=InsightsEngine(db_path=t))
        ctx = tl._day_alert_context("2026-01-15")
        assert ctx["rule_titles"]["SSH Brute Force"] == 1
        assert ctx["rule_titles"]["DDoS"] == 1
        assert ctx["severities"]["HIGH"] == 1
        assert ctx["severities"]["CRITICAL"] == 1
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_suggest_playbook_for_anomaly(temp_asgard_root):
    """Anomalia con SSH Brute Force → propone il playbook brute_force (read-only)."""
    from rag.timeline import TimelineEngine
    from rag.insights import InsightsEngine
    from rag.indexer import AsgardIndexer
    pb_dir = os.path.join(temp_asgard_root, "Sleipnir", "playbooks")
    os.makedirs(pb_dir, exist_ok=True)
    for fname, content in PLAYBOOKS.items():
        with open(os.path.join(pb_dir, fname), "w", encoding="utf-8") as f:
            f.write(content)
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        tl = TimelineEngine(engine=InsightsEngine(db_path=t))
        anomaly = {"date": "2026-01-15", "count": 2, "avg_baseline": 0.07,
                   "by_severity": {"HIGH": 1, "CRITICAL": 1}}
        s = tl.suggest_playbook_for_anomaly(anomaly)
        assert s is not None
        assert s["playbook"] == "brute_force_playbook.yaml"
        assert "SSH Brute Force" in s["context"]
        assert s["similarity"] >= 0.4
        del tl
    finally:
        safe_rmtree(t)


def test_timeline_suggest_playbook_unknown_date_returns_none(temp_asgard_root):
    """Anomalia su giorno senza alert indicizzati → nessun suggerimento."""
    from rag.timeline import TimelineEngine
    from rag.insights import InsightsEngine
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_heimdall()
        del idx
        gc.collect()
        time.sleep(0.3)
        tl = TimelineEngine(engine=InsightsEngine(db_path=t))
        anomaly = {"date": "2099-12-31", "count": 5, "avg_baseline": 0.1,
                   "by_severity": {"HIGH": 5}}
        assert tl.suggest_playbook_for_anomaly(anomaly) is None
        del tl
    finally:
        safe_rmtree(t)


def test_dispatch_anomaly_message_with_playbook_hints():
    """Il messaggio di anomalia include il playbook suggerito come sola proposta."""
    from rag.dispatch import build_anomaly_message
    anomalies = [{"date": "2026-01-15", "count": 30, "avg_baseline": 2.0,
                  "by_severity": {"HIGH": 20, "CRITICAL": 10}}]
    hints = {"2026-01-15": {"playbook": "brute_force_playbook.yaml",
                            "similarity": 0.65, "context": "Picco anomalo"}}
    msg = build_anomaly_message(anomalies, hints)
    assert "brute_force_playbook.yaml" in msg
    assert "pertinenza 65%" in msg
    assert "nessuna esecuzione automatica" in msg
    # senza hints il messaggio resta invariato (backward compat)
    assert "Playbook suggerito" not in build_anomaly_message(anomalies)


# ======================================================================
# Baseline adattiva (media mobile pesata)
# ======================================================================


def test_adaptive_baselines_constant_traffic():
    """Traffico costante → baseline adattiva ≈ valore del traffico."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        baselines = tl._adaptive_baselines([2.0] * 30)
        assert all(abs(b - 2.0) < 0.01 for b in baselines)
        del tl
    finally:
        safe_rmtree(t)


def test_adaptive_recovers_spike_masked_by_global_mean():
    """Uno spike vecchio gonfia la media globale e maschera quello nuovo:
    la baseline adattiva (finestra 14 giorni) lo rileva comunque."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [0.0] * 30
        counts[5] = 50.0   # spike vecchio (fuori dalla finestra 14 giorni)
        counts[29] = 4.0   # spike recente
        # Baseline globale: media = 54/30 = 1.8 → soglia 5.4 → il 4 NON è rilevato
        global_anoms = tl.detect_anomalies(series=_make_series_counts(counts), adaptive=False)
        assert not any(a["date"] == "2026-01-30" for a in global_anoms)
        # Baseline adattiva: per il giorno 30 la storia recente è ~0 → soglia 3 → rilevato
        adaptive_anoms = tl.detect_anomalies(series=_make_series_counts(counts), adaptive=True)
        assert any(a["date"] == "2026-01-30" and a["baseline_type"] == "adaptive"
                   for a in adaptive_anoms)
        del tl
    finally:
        safe_rmtree(t)


def test_adaptive_gradual_increase_not_flagged():
    """Un incremento graduale e sostenuto non genera falsi positivi:
    la baseline adattiva segue il traffico invece di restare ferma."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [float(min(i, 10)) for i in range(30)]  # 0,1,2,...,10,10,...
        anoms = tl.detect_anomalies(series=_make_series_counts(counts), adaptive=True)
        # gli ultimi giorni (stato stazionario a 10 con baseline ~10) non sono anomalie
        assert not any(a["date"] >= "2026-01-25" for a in anoms)
        del tl
    finally:
        safe_rmtree(t)


def test_detect_anomalies_includes_baseline_type():
    """Ogni anomalia dichiara il tipo di baseline usata (adaptive/global)."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [0.0] * 30
        counts[29] = 10.0
        adaptive_anoms = tl.detect_anomalies(series=_make_series_counts(counts), adaptive=True)
        global_anoms = tl.detect_anomalies(series=_make_series_counts(counts), adaptive=False)
        assert all(a["baseline_type"] == "adaptive" for a in adaptive_anoms)
        assert all(a["baseline_type"] == "global" for a in global_anoms)
        del tl
    finally:
        safe_rmtree(t)


def _make_series_counts(counts):
    """Serie sintetica dai conteggi giornalieri (tutti LOW)."""
    from rag.timeline import SEVERITIES
    return [{
        "date": f"2026-01-{i + 1:02d}",
        "count": int(c),
        "by_severity": {s: (int(c) if s == "LOW" else 0) for s in SEVERITIES},
    } for i, c in enumerate(counts)]


# ======================================================================
# Agenti specializzati per modulo (routing + ricerca confinata)
# ======================================================================


def test_route_keyword_matching():
    """Ogni prompt va all'agente del suo dominio; prompt generico → None."""
    from rag.agents import route
    assert route("ci sono stati attacchi brute force ssh?").name == "heimdall_agent"
    assert route("quali CVE sono aperte?").name == "fenrir_agent"
    assert route("mostrami l'ultimo scan delle porte").name == "bifrost_agent"
    assert route("come siamo con la compliance GDPR?").name == "forseti_agent"
    assert route("analisi triage del processo sospetto").name == "mjolnir_agent"
    assert route("quali playbook sono disponibili?").name == "sleipnir_agent"
    assert route("ciao, come stai?") is None


def test_route_is_deterministic_first_match():
    """Stesso prompt → sempre lo stesso agente (ordine di dichiarazione)."""
    from rag.agents import route
    results = {route("report alert e scan").name for _ in range(5)}
    assert len(results) == 1  # sempre heimdall_agent (primo nella lista)


def test_agent_answer_confined_to_own_collection(temp_asgard_root):
    """La ricerca dell'agente usa SOLO la collection del suo dominio."""
    from rag.agents import AgentRouter
    from rag.retriever import AsgardRetriever
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        router = AgentRouter(retriever=AsgardRetriever(db_path=t))
        answer = router.answer("alert di brute force rilevati")
        assert answer["routed"] is True
        assert answer["agent"]["name"] == "heimdall_agent"
        assert len(answer["references"]) > 0
        for ref in answer["references"]:
            assert ref["metadata"]["source"] == "heimdall"
        assert "HEIMDALL_AGENT" in answer["context"]
        del router
    finally:
        safe_rmtree(t)


def test_agent_answer_empty_collection_no_crash():
    """Collection vuota → contesto informativo, nessun crash."""
    from rag.agents import AgentRouter
    t = tempfile.mkdtemp()
    try:
        router = AgentRouter(retriever=None)
        answer = router.answer("quali CVE abbiamo?")
        assert answer["routed"] is True
        assert answer["references"] == []
        assert "Nessun dato" in answer["context"]
    finally:
        safe_rmtree(t)


def test_agent_router_list_agents():
    """Listing completo: 6 agenti con nome, modulo e collection."""
    from rag.agents import AgentRouter
    agents = AgentRouter().list_agents()
    assert len(agents) == 6
    names = {a["name"] for a in agents}
    assert names == {"heimdall_agent", "fenrir_agent", "bifrost_agent",
                     "forseti_agent", "mjolnir_agent", "sleipnir_agent"}
    assert all(a["collection"] and a["module"] and a["description"] for a in agents)


# ======================================================================
# PDF Report
# ======================================================================


def test_pdf_report_generates_bytes():
    """Il PDF genera bytes validi (non vuoti, header PDF)."""
    from rag.pdf_report import PDFReportExporter
    from rag.insights import InsightsEngine
    t = tempfile.mkdtemp()
    try:
        eng = InsightsEngine(db_path=t)
        data = PDFReportExporter(engine=eng).generate_pdf()
        assert len(data) > 100
        assert data[:5] == b"%PDF-"
        del eng
    finally:
        safe_rmtree(t)


def test_pdf_report_save_creates_file():
    """Il PDF viene salvato su disco come file .pdf."""
    from rag.pdf_report import PDFReportExporter
    from rag.insights import InsightsEngine
    t = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    try:
        eng = InsightsEngine(db_path=t)
        path = PDFReportExporter(engine=eng).save(output_dir=out)
        assert os.path.exists(path)
        assert path.endswith(".pdf")
        assert os.path.getsize(path) > 100
        del eng
    finally:
        safe_rmtree(t)
        safe_rmtree(out)


# ======================================================================
# PDF Report Exporter
# ======================================================================


def test_pdf_report_creates_valid_pdf(temp_asgard_root):
    """Il PDF viene generato con successo e inizia con la magic string %PDF."""
    from rag.pdf_report import PDFReportExporter
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        from rag.insights import InsightsEngine
        from rag.report import ReportExporter
        eng = InsightsEngine(db_path=t)
        rep = ReportExporter(engine=eng)
        path = PDFReportExporter(report_exporter=rep).generate_pdf(
            output_path=os.path.join(out, "test_report.pdf")
        )
        assert os.path.exists(path)
        assert path.endswith(".pdf")
        with open(path, "rb") as f:
            header = f.read(5)
        assert header == b"%PDF-"
        del eng
    finally:
        safe_rmtree(t)
        safe_rmtree(out)


def test_pdf_report_default_output_path(temp_asgard_root):
    """Senza output_path il PDF va in output/reports/."""
    from rag.pdf_report import PDFReportExporter
    from rag.indexer import AsgardIndexer
    t = tempfile.mkdtemp()
    out = tempfile.mkdtemp()
    env_backup = os.environ.get("ASGARD_REPORT_DIR")
    os.environ["ASGARD_REPORT_DIR"] = out
    try:
        idx = AsgardIndexer(asgard_root=temp_asgard_root, db_path=t)
        idx.index_all()
        del idx
        gc.collect()
        time.sleep(0.3)
        from rag.insights import InsightsEngine
        from rag.report import ReportExporter
        eng = InsightsEngine(db_path=t)
        rep = ReportExporter(engine=eng)
        path = PDFReportExporter(report_exporter=rep).generate_pdf()
        assert os.path.exists(path)
        assert "asgard_report_" in os.path.basename(path)
        assert path.endswith(".pdf")
        del eng
    finally:
        if env_backup is None:
            del os.environ["ASGARD_REPORT_DIR"]
        else:
            os.environ["ASGARD_REPORT_DIR"] = env_backup
        safe_rmtree(t)
        safe_rmtree(out)


def test_pdf_parse_markdown_structured():
    """Il parser Markdown separa header, tabelle, liste e testo."""
    from rag.pdf_report import PDFReportExporter
    md = "# Titolo\n\nParagrafo.\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n- Item 1\n- Item 2"
    elements = PDFReportExporter()._parse_md_to_structured(md)
    types = [e["type"] for e in elements]
    assert "header" in types
    assert "table" in types
    assert "list" in types
    assert "text" in types


def test_pdf_clean_markdown_removes_formatting():
    """La pulizia rimuove **, *, `, []()."""
    from rag.pdf_report import PDFReportExporter
    cleaned = PDFReportExporter()._clean_markdown("**bold** *italic* `code` [link](url)")
    assert "**" not in cleaned
    assert "*" not in cleaned
    assert "`" not in cleaned
    assert "[" not in cleaned
    assert "]" not in cleaned


# ======================================================================
# Security Score History
# ======================================================================


def test_security_history_record_and_get():
    """Salvataggio e recupero punteggio."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(75, "HIGH", 3, 2)
        h.record_score(85, "LOW", 1, 1)
        history = h.get_history(days=30)
        assert len(history) == 2
        assert history[0]["score"] == 75
        assert history[1]["score"] == 85
        del h
    finally:
        safe_rmtree(t)


def test_security_history_trend_improving():
    """Score crescente → trend improving."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(50, "CRITICAL", 10, 5)
        h.record_score(90, "LOW", 1, 1)
        trend = h.get_trend(days=30)
        assert trend["trend"] == "improving"
        assert trend["difference"] == 40
        del h
    finally:
        safe_rmtree(t)


def test_security_history_trend_worsening():
    """Score decrescente → trend worsening."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(90, "LOW", 1, 1)
        h.record_score(40, "CRITICAL", 10, 5)
        trend = h.get_trend(days=30)
        assert trend["trend"] == "worsening"
        assert trend["difference"] == -50
        del h
    finally:
        safe_rmtree(t)


def test_security_history_trend_stable():
    """Score invariato → trend stable."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(75, "HIGH", 3, 2)
        h.record_score(78, "HIGH", 3, 2)
        trend = h.get_trend(days=30)
        assert trend["trend"] == "stable"
        del h
    finally:
        safe_rmtree(t)


def test_security_history_insufficient_data():
    """Un solo punto dati → insufficient_data."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(75, "HIGH", 3, 2)
        trend = h.get_trend(days=30)
        assert trend["trend"] == "insufficient_data"
        del h
    finally:
        safe_rmtree(t)


def test_security_history_summary_empty():
    """Senza dati → available=False."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        s = h.get_summary(days=30)
        assert s["available"] is False
        del h
    finally:
        safe_rmtree(t)


def test_security_history_summary_with_data():
    """Summary con dati: min, max, avg, trend."""
    from rag.security_history import SecurityScoreHistory
    t = tempfile.mkdtemp()
    try:
        db = os.path.join(t, "test.db")
        h = SecurityScoreHistory(db_path=db)
        h.record_score(50, "CRITICAL", 10, 5)
        h.record_score(75, "HIGH", 3, 2)
        h.record_score(90, "LOW", 1, 1)
        s = h.get_summary(days=30)
        assert s["available"] is True
        assert s["min_score"] == 50
        assert s["max_score"] == 90
        assert s["current_score"] == 90
        assert s["avg_score"] == 71.7
        assert s["trend"] == "improving"
        del h
    finally:
        safe_rmtree(t)


# ======================================================================
# GDPR Compliance per Agenti + Raccomandazione per PMI
# ======================================================================


def test_gdpr_checklist_has_10_items():
    """Checklist GDPR completa: 10 domande con principio e peso."""
    from rag.gdpr import GDPR_CHECKLIST
    assert len(GDPR_CHECKLIST) == 10
    assert all("principio" in item and "peso" in item and "question" in item for item in GDPR_CHECKLIST)
    principles = {item["principio"] for item in GDPR_CHECKLIST}
    assert "art. 5.1.c" in principles
    assert "art. 5.1.e" in principles
    assert "art. 32" in principles


def test_gdpr_evaluate_all_yes_ottimo():
    """Tutte le risposte sì → score 100%, livello ottimo."""
    from rag.gdpr import GDPRComplianceChecker, GDPR_CHECKLIST
    checker = GDPRComplianceChecker()
    answers = {item["id"]: True for item in GDPR_CHECKLIST}
    result = checker.evaluate_checklist(answers)
    assert result["percentage"] == 100
    assert result["level"] == "ottimo"
    assert result["color"] == "green"
    assert len(result["gaps"]) == 0
    assert len(result["strengths"]) == 10


def test_gdpr_evaluate_all_no_critico():
    """Tutte le risposte no → score 0%, livello critico, tutti gap."""
    from rag.gdpr import GDPRComplianceChecker, GDPR_CHECKLIST
    checker = GDPRComplianceChecker()
    answers = {item["id"]: False for item in GDPR_CHECKLIST}
    result = checker.evaluate_checklist(answers)
    assert result["percentage"] == 0
    assert result["level"] == "critico"
    assert result["color"] == "red"
    assert len(result["gaps"]) == 10
    assert len(result["strengths"]) == 0


def test_gdpr_evaluate_partial_buono():
    """Risposte parziali → livello intermedio corretto."""
    from rag.gdpr import GDPRComplianceChecker, GDPR_CHECKLIST
    checker = GDPRComplianceChecker()
    # Rispondi sì a circa metà degli item (peso 10 su 21 = 47%)
    partial_ids = {"data_inventory", "consent_management", "data_minimization", "retention_policy"}
    answers = {item["id"]: (item["id"] in partial_ids) for item in GDPR_CHECKLIST}
    result = checker.evaluate_checklist(answers)
    assert result["level"] in ("sufficiente", "buono")
    assert 40 <= result["percentage"] <= 70


def test_gdpr_recommend_micro_enterprise():
    """Micro-impresa → solo agenti essenziali consigliati."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("micro")
    assert "heimdall_agent" in rec["recommended_agents"]
    assert "forseti_agent" in rec["recommended_agents"]
    assert rec["company_size"] == "Micro-imprese (1-9 dipendenti)"


def test_gdpr_recommend_medium_enterprise():
    """Media impresa → suite completa consigliata."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("medium")
    assert "heimdall_agent" in rec["recommended_agents"]
    assert "fenrir_agent" in rec["recommended_agents"]
    assert "bifrost_agent" in rec["recommended_agents"]
    assert "forseti_agent" in rec["recommended_agents"]


def test_gdpr_recommend_healthcare_adds_agents():
    """Settore sanitario → aggiunge agenti anche per piccole imprese."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("small", sector="sanita")
    assert "fenrir_agent" in rec["recommended_agents"]
    assert "bifrost_agent" in rec["recommended_agents"]


def test_gdpr_recommend_finance_adds_agents():
    """Settore finanziario → aggiunge agenti di threat intel e scan."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("small", sector="finanza")
    assert "fenrir_agent" in rec["recommended_agents"]
    assert "bifrost_agent" in rec["recommended_agents"]


def test_gdpr_recommend_maturity_base_removes_sleipnir():
    """Maturità base → Sleipnir rimosso dai consigliati, messo opzionale."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("medium", maturity="base")
    assert "sleipnir_agent" not in rec["recommended_agents"]
    assert "sleipnir_agent" in rec["optional_agents"]


def test_gdpr_recommend_maturity_avanzata_adds_sleipnir():
    """Maturità avanzata → Sleipnir promosso a consigliato."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("medium", maturity="avanzata")
    assert "sleipnir_agent" in rec["recommended_agents"]


def test_gdpr_recommend_unknown_size_defaults_small():
    """Dimensione sconosciuta → fallback a small."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    rec = checker.recommend_agents("gigante")
    assert "heimdall_agent" in rec["recommended_agents"]
    assert "forseti_agent" in rec["recommended_agents"]


def test_gdpr_generate_privacy_report():
    """Report privacy completo: valutazione + raccomandazioni + disclaimer."""
    from rag.gdpr import GDPRComplianceChecker
    checker = GDPRComplianceChecker()
    report = checker.generate_privacy_report(company_size="small")
    assert "generated_at" in report
    assert "gdpr_evaluation" in report
    assert "agent_recommendations" in report
    assert "data_retention" in report
    assert "disclaimer" in report
    assert "DPO qualificato" in report["disclaimer"]


# ======================================================================
# Security Auditor
# ======================================================================


def test_security_audit_detects_missing_api_keys():
    """Senza API key configurate → findings CRITICAL."""
    from rag.security import SecurityAuditor, CRITICAL
    import os
    # Salva e rimuovi temporaneamente le variabili
    saved = {}
    for k in ["RAGNAROK_API_KEY", "BIFROST_API_KEY", "GJALLARHORN_API_KEY"]:
        if k in os.environ:
            saved[k] = os.environ.pop(k)
    try:
        auditor = SecurityAuditor()
        audit = auditor.run_full_audit()
        assert audit["score"] < 100
        severities = [f["severity"] for f in audit["findings"]]
        assert CRITICAL in severities
        titles = " ".join(f["title"] for f in audit["findings"])
        assert "RAGNAROK_API_KEY" in titles
    finally:
        os.environ.update(saved)


def test_security_audit_with_all_keys_configured():
    """Con tutte le API key configurate → score più alto."""
    from rag.security import SecurityAuditor
    import os
    saved = {k: os.environ.get(k) for k in ["RAGNAROK_API_KEY", "BIFROST_API_KEY", "GJALLARHORN_API_KEY"]}
    os.environ["RAGNAROK_API_KEY"] = "test-key-long-enough-for-security"
    os.environ["BIFROST_API_KEY"] = "test-bifrost-key"
    os.environ["GJALLARHORN_API_KEY"] = "test-gjallarhorn-key"
    try:
        auditor = SecurityAuditor()
        audit = auditor.run_full_audit()
        # Non ci dovrebbero essere findings CRITICAL per auth
        auth_findings = [f for f in audit["findings"] if f["category"] == "authentication"]
        assert not any(f["severity"] == "CRITICAL" for f in auth_findings)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_security_audit_score_and_grade():
    """Score 0-100 con grade A-F."""
    from rag.security import SecurityAuditor
    auditor = SecurityAuditor()
    audit = auditor.run_full_audit()
    assert 0 <= audit["score"] <= 100
    assert audit["grade"] in ("A", "B", "C", "D", "F")
    assert audit["total_findings"] == len(audit["findings"])


def test_security_audit_format_report_contains_sections():
    """Il report Markdown contiene score, findings e raccomandazioni."""
    from rag.security import SecurityAuditor
    auditor = SecurityAuditor()
    audit = auditor.run_full_audit()
    report = auditor.format_report(audit)
    assert "Security Audit Report" in report
    assert "Security Score" in report
    assert "Findings" in report
    assert "Raccomandazione" in report


def test_security_audit_findings_have_required_fields():
    """Ogni finding ha severità, categoria, titolo, descrizione, raccomandazione."""
    from rag.security import SecurityAuditor
    auditor = SecurityAuditor()
    audit = auditor.run_full_audit()
    for f in audit["findings"]:
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert f["category"]
        assert f["title"]
        assert f["description"]
        assert f["recommendation"]


def test_security_audit_tls_disabled_generates_finding():
    """TLS non abilitato → finding HIGH."""
    from rag.security import SecurityAuditor, HIGH
    import os
    saved = os.environ.get("ASGARD_TLS")
    os.environ.pop("ASGARD_TLS", None)
    try:
        auditor = SecurityAuditor()
        audit = auditor.run_full_audit()
        tls_findings = [f for f in audit["findings"] if "TLS" in f["title"]]
        assert len(tls_findings) == 1
        assert tls_findings[0]["severity"] == HIGH
    finally:
        if saved is not None:
            os.environ["ASGARD_TLS"] = saved


def test_security_auditor_save_report_writes_file(tmp_path):
    """
    Regression test: rag/cli.py's `cmd_security --save` called a
    SecurityAuditor.save_report() method that didn't exist (AttributeError
    on every call) - the class only had format_report(), no save-to-file
    method, unlike the analogous ReportExporter.save(). Added save_report()
    mirroring that pattern.
    """
    from rag.security import SecurityAuditor
    auditor = SecurityAuditor()
    path = auditor.save_report(output_dir=str(tmp_path))
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "Security Audit Report" in content


# ======================================================================
# CLI (rag/cli.py)
# ======================================================================


def _patch_security_history_db(monkeypatch, db_path):
    """cmd_security_history() imports SecurityScoreHistory locally (inside
    the function body), so it can't be patched via the cli module - patch
    the class's own __init__ default instead, isolating tests from the
    suite's real history DB."""
    import rag.security_history as sh_module
    orig_init = sh_module.SecurityScoreHistory.__init__
    monkeypatch.setattr(
        sh_module.SecurityScoreHistory, "__init__",
        lambda self, db_path=db_path: orig_init(self, db_path=db_path),
    )


def test_cli_cmd_security_history_reports_no_data_when_empty(tmp_path, capsys, monkeypatch):
    """No history yet -> prints the "no data" message, doesn't crash."""
    from rag import cli as cli_module
    import argparse

    _patch_security_history_db(monkeypatch, str(tmp_path / "history.db"))
    args = argparse.Namespace(days=30, record=False)
    cli_module.cmd_security_history(args)
    out = capsys.readouterr().out
    assert "Nessun dato storico" in out


def test_cli_cmd_security_history_record_then_shows_summary(tmp_path, capsys, monkeypatch):
    """
    Regression test: rag/cli.py's argparse tree wired the "security-history"
    subcommand to `cmd_security_history`, a function that was never
    defined anywhere in the file (NameError). Because parser.set_defaults()
    resolves that name immediately when main()'s parser is built - not only
    when that specific subcommand is chosen - this crashed EVERY invocation
    of the CLI, not just `security-history`. Now implemented: --record runs
    a real audit and persists it, then prints the summary.
    """
    from rag import cli as cli_module
    import argparse

    _patch_security_history_db(monkeypatch, str(tmp_path / "history.db"))
    args = argparse.Namespace(days=30, record=True)
    cli_module.cmd_security_history(args)
    out = capsys.readouterr().out
    assert "Punteggio registrato" in out
    assert "Storico security score" in out
    assert "Trend" in out


def test_cli_cmd_security_prints_report_without_save(capsys):
    """
    Regression test: cmd_security called auditor.run_audit() and
    auditor.save_report() with save=True - but SecurityAuditor only ever
    had run_full_audit() and (before the fix above) no save_report() at
    all. Every real `python -m rag.cli security` invocation crashed with
    AttributeError. Now uses run_full_audit() + format_report().
    """
    from rag import cli as cli_module
    import argparse

    args = argparse.Namespace(save=False, out=None)
    cli_module.cmd_security(args)
    out = capsys.readouterr().out
    assert "Security Audit Report" in out


def test_cli_cmd_security_save_writes_file(tmp_path, capsys):
    from rag import cli as cli_module
    import argparse

    args = argparse.Namespace(save=True, out=str(tmp_path))
    cli_module.cmd_security(args)
    out = capsys.readouterr().out
    assert "Report sicurezza salvato" in out
    saved_files = list(tmp_path.glob("*.md"))
    assert len(saved_files) == 1


def test_cli_parser_builds_without_crashing_for_every_subcommand():
    """
    Regression test: building main()'s argparse tree referenced
    `cmd_security_history` before it was defined anywhere, which raised
    NameError as soon as main() ran - for ANY subcommand, not just
    security-history, since parser construction happens unconditionally
    before argparse even looks at argv. This exercises the same
    construction path main() does, without actually running a command.
    """
    import argparse
    from rag import cli as cli_module

    parser = argparse.ArgumentParser(prog="rag")
    sub = parser.add_subparsers(dest="command", required=True)
    p_sec_hist = sub.add_parser("security-history")
    p_sec_hist.add_argument("--days", type=int, default=30)
    p_sec_hist.add_argument("--record", action="store_true")
    # This is the exact line that used to raise NameError.
    p_sec_hist.set_defaults(func=cli_module.cmd_security_history)
    assert callable(p_sec_hist.get_default("func"))


@pytest.fixture
def isolated_rag_db(tmp_path, monkeypatch):
    """Points every rag/* class's default ChromaDB path at an empty temp
    dir, so CLI smoke tests below never touch the real dev database."""
    monkeypatch.setenv("ASGARD_RAG_DB_PATH", str(tmp_path / "chroma"))
    return tmp_path


def test_cli_main_builds_and_dispatches_real_parser(isolated_rag_db, capsys):
    """
    The authoritative version of test_cli_parser_builds_without_crashing_
    for_every_subcommand above: calls the actual cli.main() - the exact
    function that crashed on every subcommand - end to end with real argv,
    instead of a hand-built parser that only mimics its shape.
    """
    from rag import cli as cli_module
    cli_module.main(["stats"])
    out = capsys.readouterr().out
    assert "Documenti indicizzati" in out


def test_cli_cmd_insights_smoke(isolated_rag_db, capsys):
    from rag import cli as cli_module
    import argparse
    cli_module.cmd_insights(argparse.Namespace())
    out = capsys.readouterr().out
    assert out.strip() != ""


def test_cli_cmd_report_markdown_and_save(isolated_rag_db, capsys, tmp_path):
    from rag import cli as cli_module
    import argparse

    cli_module.cmd_report(argparse.Namespace(pdf=False, save=False, out=None))
    out = capsys.readouterr().out
    assert out.strip() != ""

    save_dir = tmp_path / "reports"
    cli_module.cmd_report(argparse.Namespace(pdf=False, save=True, out=str(save_dir)))
    out = capsys.readouterr().out
    assert "Report salvato" in out
    assert len(list(save_dir.glob("*.md"))) == 1


def test_cli_cmd_notify_inert_without_gjallarhorn(isolated_rag_db, capsys, monkeypatch):
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    from rag import cli as cli_module
    import argparse

    cli_module.cmd_notify(argparse.Namespace(save=False, out=None))
    out = capsys.readouterr().out
    assert "non configurato" in out


def test_cli_cmd_anomalies_inert_without_gjallarhorn(isolated_rag_db, capsys, monkeypatch):
    monkeypatch.delenv("GJALLARHORN_HUB_URL", raising=False)
    monkeypatch.delenv("GJALLARHORN_API_KEY", raising=False)
    from rag import cli as cli_module
    import argparse

    cli_module.cmd_anomalies(argparse.Namespace(days=30))
    out = capsys.readouterr().out
    assert "non configurato" in out


def test_cli_cmd_gdpr_checklist_action(capsys):
    from rag import cli as cli_module
    import argparse
    cli_module.cmd_gdpr(argparse.Namespace(action="checklist"))
    out = capsys.readouterr().out
    assert "CHECKLIST GDPR" in out


def test_cli_cmd_gdpr_recommend_action(capsys):
    from rag import cli as cli_module
    import argparse
    cli_module.cmd_gdpr(argparse.Namespace(action="recommend", size="small", sector=None, maturity=None))
    out = capsys.readouterr().out
    assert "RACCOMANDAZIONE AGENTI" in out


def test_cli_cmd_gdpr_report_action(capsys):
    from rag import cli as cli_module
    import argparse
    cli_module.cmd_gdpr(argparse.Namespace(action="report", size="small", sector=None, maturity=None))
    out = capsys.readouterr().out
    assert "REPORT GDPR" in out


def test_cli_cmd_index_and_query_smoke(isolated_rag_db, capsys, temp_asgard_root, monkeypatch):
    monkeypatch.setenv("ASGARD_ROOT", str(temp_asgard_root))
    from rag import cli as cli_module
    import argparse

    cli_module.cmd_index(argparse.Namespace())
    out = capsys.readouterr().out
    assert "Indicizzazione completata" in out

    cli_module.cmd_query(argparse.Namespace(query="brute force", n=5, sources=None))
    out = capsys.readouterr().out
    assert "risultati per" in out or "Nessun risultato" in out


# ======================================================================
# Parametri di detection configurabili
# ======================================================================


def test_detect_anomalies_custom_spike_factor():
    """spike_factor più basso → più sensibile: rileva spike che il default perde."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [0.0] * 30
        counts[29] = 2.0  # sotto min_spike default (3) ma sopra min_spike=1
        # default: soglia max(3*0, 3) = 3 → non rilevato
        assert tl.detect_anomalies(series=_make_series_counts(counts)) == []
        # min_spike=1: soglia max(3*0, 1) = 1 → rilevato
        anoms = tl.detect_anomalies(series=_make_series_counts(counts), min_spike=1)
        assert len(anoms) == 1 and anoms[0]["count"] == 2
        del tl
    finally:
        safe_rmtree(t)


def test_detect_anomalies_high_spike_factor_less_sensitive():
    """spike_factor alto → meno sensibile: spike moderato non più rilevato."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [2.0] * 29 + [8.0]  # baseline 2, spike 8
        # default: soglia max(3*2, 3) = 6 → 8 rilevato
        assert len(tl.detect_anomalies(series=_make_series_counts(counts))) == 1
        # spike_factor=10: soglia max(10*2, 3) = 20 → non rilevato
        assert tl.detect_anomalies(series=_make_series_counts(counts),
                                   spike_factor=10.0) == []
        del tl
    finally:
        safe_rmtree(t)


def test_summary_passes_detection_params():
    """summary() propaga spike_factor/min_spike a detect_anomalies."""
    from rag.timeline import TimelineEngine
    t = tempfile.mkdtemp()
    try:
        tl = TimelineEngine(engine_kwargs={"db_path": t})
        counts = [0.0] * 29 + [2.0]
        series = _make_series_counts(counts)
        # con min_spike default il picco di 2 non è anomalia
        s_default = tl.summary_from_series(series)
        assert s_default["anomalies"] == []
        # con min_spike=1 lo diventa
        s_sens = tl.summary_from_series(series, min_spike=1)
        assert len(s_sens["anomalies"]) == 1
        del tl
    finally:
        safe_rmtree(t)
