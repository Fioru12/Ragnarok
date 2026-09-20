import os, sqlite3, logging, glob
from datetime import datetime, timezone
from typing import Optional, Dict
import chromadb
import numpy as np
from chromadb.config import Settings
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
from . import get_db_path
logger = logging.getLogger('Asgard.RAG.Indexer')

class FastEmbedAdapter(EmbeddingFunction):
    def __init__(self, model_name='BAAI/bge-small-en-v1.5'):
        from fastembed import TextEmbedding
        self.model = TextEmbedding(model_name=model_name)
    def __call__(self, input: Documents) -> Embeddings:
        return [np.array(e, dtype=np.float32) for e in self.model.embed(input)]

COL_ALERTS = 'heimdall_alerts'
COL_IOC = 'fenrir_ioc'
COL_TRIAGE = 'mjolnir_triage'
COL_SCANS = 'bifrost_scans'
COL_COMPLIANCE = 'forseti_compliance'
COL_PLAYBOOKS = 'sleipnir_playbooks'

class AsgardIndexer:
    def __init__(self, asgard_root=None, db_path=None):
        import pathlib
        self.asgard_root = asgard_root or os.environ.get('ASGARD_ROOT', str(pathlib.Path(__file__).parent.parent.parent.parent))
        self.db_path = db_path or get_db_path()
        os.makedirs(self.db_path, exist_ok=True)
        self.client = chromadb.PersistentClient(
            path=self.db_path,
            settings=Settings(anonymized_telemetry=False)
        )
        self.ef = FastEmbedAdapter()

    def _reset_collection(self, name: str):
        try:
            self.client.delete_collection(name)
        except Exception:
            pass
        return self.client.get_or_create_collection(
            name=name,
            embedding_function=self.ef,
            metadata={'hnsw:space': 'cosine'}
        )

    def index_heimdall(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(self.asgard_root, 'Heimdall', 'heimdall.db')
        if not os.path.isfile(db_path):
            return 0
        collection = self._reset_collection(COL_ALERTS)
        count = 0
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        if not cur.fetchone():
            conn.close()
            return 0
        for row in cur.execute('SELECT * FROM alerts ORDER BY id'):
            row = dict(row)
            doc_id = 'alert-' + str(row.get('id', count))
            text = 'Alert: ' + str(row.get('rule_title', 'Unknown')) + '. Severity: ' + str(row.get('severity', 'unknown')) + '. Source IP: ' + str(row.get('source_ip', 'N/A')) + '. Action: ' + str(row.get('action_taken', 'none')) + '. Count: ' + str(row.get('count', 1)) + '.'
            collection.add(ids=[doc_id], documents=[text], metadatas=[{'source': 'heimdall', 'type': 'alert', 'severity': str(row.get('severity', 'unknown')), 'source_ip': str(row.get('source_ip', 'N/A')), 'timestamp': str(row.get('timestamp', '')), 'action': str(row.get('action_taken', ''))}])
            count += 1
        conn.close()
        return count

    def index_fenrir(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(self.asgard_root, 'Fenrir', 'fenrir.db')
        if not os.path.isfile(db_path):
            return 0
        collection = self._reset_collection(COL_IOC)
        count = 0
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ioc', 'iocs')")
        tbl = cur.fetchone()
        if not tbl:
            conn.close()
            return 0
        table_name = tbl[0]

        for row in cur.execute(f'SELECT * FROM {table_name} ORDER BY id'):
            row = dict(row)
            doc_id = 'ioc-' + str(row.get('id', count))
            val = row.get('value') or row.get('indicator') or 'unknown'
            typ = row.get('type') or row.get('indicator_type') or 'unknown'
            src = row.get('source') or 'unknown'
            cve = row.get('cve_id') or 'N/A'
            threat = row.get('threat_type') or 'N/A'
            sev = row.get('severity') or 'unknown'
            text = f"IOC: {val}. Tipo: {typ}. Fonte: {src}. CVE: {cve}. Threat: {threat}. Severità: {sev}."
            collection.add(ids=[doc_id], documents=[text], metadatas=[{'source': 'fenrir', 'type': 'ioc', 'ioc_value': str(val), 'ioc_type': str(typ), 'ioc_source': str(src), 'cve_id': str(cve), 'threat_type': str(threat), 'severity': str(sev), 'timestamp': str(row.get('timestamp', ''))}])
            count += 1
        conn.close()
        return count

    def index_mjolnir(self, output_dir=None):
        if output_dir is None:
            output_dir = os.path.join(self.asgard_root, 'Mjolnir', 'output')
        if not os.path.isdir(output_dir):
            return 0
        collection = self._reset_collection(COL_TRIAGE)
        count = 0
        for md_file in sorted(glob.glob(os.path.join(output_dir, '*.md'))):
            doc_id = 'triage-' + os.path.basename(md_file)
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()[:4000]
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'mjolnir', 'type': 'triage_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.now(timezone.utc).isoformat()}])
            count += 1
        return count

    def index_bifrost(self, output_dir=None):
        if output_dir is None:
            output_dir = os.path.join(self.asgard_root, 'Bifrost', 'output')
        if not os.path.isdir(output_dir):
            return 0
        collection = self._reset_collection(COL_SCANS)
        count = 0
        for md_file in sorted(glob.glob(os.path.join(output_dir, '*.md'))):
            doc_id = 'scan-' + os.path.basename(md_file)
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()[:4000]
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'bifrost', 'type': 'scan_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.now(timezone.utc).isoformat()}])
            count += 1
        return count

    def index_forseti(self, output_dir=None):
        if output_dir is None:
            output_dir = os.path.join(self.asgard_root, 'Forseti', 'output')
        if not os.path.isdir(output_dir):
            return 0
        collection = self._reset_collection(COL_COMPLIANCE)
        count = 0
        for md_file in sorted(glob.glob(os.path.join(output_dir, '*.md'))):
            doc_id = 'compliance-' + os.path.basename(md_file)
            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()[:4000]
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'forseti', 'type': 'compliance_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.now(timezone.utc).isoformat()}])
            count += 1
        return count

    def index_playbooks(self, dir_name=None):
        """Indicizza i playbook YAML di Sleipnir (flussi SOAR)."""
        if dir_name is None:
            dir_name = os.path.join(self.asgard_root, 'Sleipnir', 'playbooks')
        if not os.path.isdir(dir_name):
            return 0
        collection = self._reset_collection(COL_PLAYBOOKS)
        count = 0
        for pb_file in sorted(glob.glob(os.path.join(dir_name, '*.yaml'))):
            doc_id = 'playbook-' + os.path.basename(pb_file)
            try:
                with open(pb_file, 'r', encoding='utf-8') as f:
                    content = f.read()[:4000]
                collection.add(ids=[doc_id], documents=[content],
                               metadatas=[{'source': 'sleipnir', 'type': 'playbook',
                                           'filename': os.path.basename(pb_file),
                                           'indexed_at': datetime.now(timezone.utc).isoformat()}])
                count += 1
            except Exception as e:
                logger.warning(f'Errore lettura playbook {pb_file}: {e}')
        logger.info(f'Sleipnir playbook: {count} indicizzati')
        return count

    def index_all(self):
        results = {'heimdall': self.index_heimdall(), 'fenrir': self.index_fenrir(),
                   'mjolnir': self.index_mjolnir(), 'bifrost': self.index_bifrost(),
                   'forseti': self.index_forseti(), 'playbooks': self.index_playbooks()}
        results['total'] = sum(v for v in results.values() if isinstance(v, int))
        return results

    def get_stats(self):
        stats = {}
        for name in [COL_ALERTS, COL_IOC, COL_TRIAGE, COL_SCANS, COL_COMPLIANCE, COL_PLAYBOOKS]:
            try:
                stats[name] = self.client.get_collection(name).count()
            except Exception:
                stats[name] = 0
        return stats
