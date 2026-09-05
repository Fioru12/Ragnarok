import os, sqlite3, logging, glob
from datetime import datetime
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
        self.client = chromadb.PersistentClient(path=self.db_path, settings=Settings(anonymized_telemetry=False))
        self.embedding_fn = FastEmbedAdapter()

    def _get_or_create(self, name):
        return self.client.get_or_create_collection(name=name, embedding_function=self.embedding_fn, metadata={'hnsw:space': 'cosine'})

    def _reset_collection(self, name):
        col = self._get_or_create(name)
        if col.count() > 0:
            self.client.delete_collection(name)
            col = self._get_or_create(name)
        return col

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
        for row in cur.execute('SELECT * FROM alerts ORDER BY id'):
            row = dict(row)
            doc_id = 'alert-' + str(row.get('id', count))
            text = 'Alert: ' + str(row.get('rule_title', 'Unknown')) + '. Severity: ' + str(row.get('severity', 'unknown')) + '. Source IP: ' + str(row.get('source_ip', 'N/A')) + '. Action: ' + str(row.get('action_taken', 'none')) + '. Count: ' + str(row.get('count', 1)) + '.'
            collection.add(ids=[doc_id], documents=[text], metadatas=[{'source': 'heimdall', 'type': 'alert', 'severity': row.get('severity', 'unknown'), 'source_ip': row.get('source_ip', 'N/A'), 'timestamp': row.get('timestamp', ''), 'action': row.get('action_taken', '')}])
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
        for row in cur.execute('SELECT * FROM ioc ORDER BY id'):
            row = dict(row)
            doc_id = 'ioc-' + str(row.get('id', count))
            text = 'IOC: ' + str(row.get('value', 'unknown')) + '. Tipo: ' + str(row.get('type', 'unknown')) + '. Fonte: ' + str(row.get('source', 'unknown')) + '. CVE: ' + str(row.get('cve_id', 'N/A')) + '. Threat: ' + str(row.get('threat_type', 'N/A')) + '.'
            collection.add(ids=[doc_id], documents=[text], metadatas=[{'source': 'fenrir', 'type': 'ioc', 'ioc_value': row.get('value', ''), 'ioc_type': row.get('type', ''), 'ioc_source': row.get('source', ''), 'cve_id': row.get('cve_id', ''), 'threat_type': row.get('threat_type', ''), 'timestamp': row.get('timestamp', '')}])
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
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'mjolnir', 'type': 'triage_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.utcnow().isoformat()}])
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
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'bifrost', 'type': 'scan_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.utcnow().isoformat()}])
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
            collection.add(ids=[doc_id], documents=[content], metadatas=[{'source': 'forseti', 'type': 'compliance_report', 'filename': os.path.basename(md_file), 'indexed_at': datetime.utcnow().isoformat()}])
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
                                           'indexed_at': datetime.utcnow().isoformat()}])
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
