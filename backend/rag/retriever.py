import os, logging
from typing import List, Dict, Any, Optional
import chromadb
import numpy as np
from chromadb.config import Settings
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
from . import get_db_path
logger = logging.getLogger('Asgard.RAG.Retriever')

class FastEmbedAdapter(EmbeddingFunction):
    def __init__(self, model_name='BAAI/bge-small-en-v1.5'):
        from fastembed import TextEmbedding
        self.model = TextEmbedding(model_name=model_name)
    def __call__(self, input: Documents) -> Embeddings:
        return [np.array(e, dtype=np.float32) for e in self.model.embed(input)]

ALL_COLLECTIONS = ['heimdall_alerts', 'fenrir_ioc', 'mjolnir_triage', 'bifrost_scans', 'forseti_compliance', 'sleipnir_playbooks']

class AsgardRetriever:
    def __init__(self, db_path=None):
        self.db_path = db_path or get_db_path()
        self.client = chromadb.PersistentClient(path=self.db_path, settings=Settings(anonymized_telemetry=False))
        try:
            self.embedding_fn = FastEmbedAdapter()
        except Exception:
            self.embedding_fn = None

    def search(self, query, n_results=5, sources=None, filters=None):
        results = []
        for col_name in ALL_COLLECTIONS:
            try:
                kwargs = {'name': col_name}
                if self.embedding_fn:
                    kwargs['embedding_function'] = self.embedding_fn
                col = self.client.get_collection(**kwargs)
                if col.count() == 0:
                    continue
                q = {'query_texts': [query], 'n_results': min(n_results, col.count()), 'include': ['documents', 'metadatas', 'distances']}
                if filters:
                    q['where'] = filters
                resp = col.query(**q)
                docs = resp.get('documents', [[]])[0]
                metas = resp.get('metadatas', [[]])[0]
                dists = resp.get('distances', [[]])[0]
                for doc, meta, dist in zip(docs, metas, dists):
                    sim = max(0.0, 1.0 - dist) if dist is not None else 0.0
                    results.append({'text': doc, 'metadata': meta, 'similarity': round(sim, 3), 'collection': col_name})
            except Exception as e:
                logger.debug('Query su ' + col_name + ' fallita: ' + str(e))
        results.sort(key=lambda r: r['similarity'], reverse=True)
        return results[:n_results * len(ALL_COLLECTIONS)]

    def search_collection(self, collection_name, query, n_results=3):
        """Ricerca semantica mirata su una singola collection."""
        try:
            kwargs = {'name': collection_name}
            if self.embedding_fn:
                kwargs['embedding_function'] = self.embedding_fn
            col = self.client.get_collection(**kwargs)
            if col.count() == 0:
                return []
            resp = col.query(query_texts=[query], n_results=min(n_results, col.count()),
                             include=['documents', 'metadatas', 'distances'])
            out = []
            for doc, meta, dist in zip(resp.get('documents', [[]])[0],
                                       resp.get('metadatas', [[]])[0],
                                       resp.get('distances', [[]])[0]):
                sim = max(0.0, 1.0 - dist) if dist is not None else 0.0
                out.append({'text': doc, 'metadata': meta, 'similarity': round(sim, 3)})
            return out
        except Exception as e:
            logger.debug('Query su ' + collection_name + ' fallita: ' + str(e))
            return []

    def format_for_llm(self, results):
        if not results:
            return '(Nessun dato storico rilevante trovato.)'
        lines = ['=== CONTESTO DATI ASGARD ===']
        for i, r in enumerate(results, 1):
            meta = r.get('metadata', {})
            lines.append('[' + str(i) + '] Source: ' + str(meta.get('source', '?')) + ' | Relevance: ' + '{:.0%}'.format(r['similarity']))
            lines.append('    ' + r['text'][:300])
        return chr(10).join(lines)

    def get_stats(self):
        stats = {}
        for name in ALL_COLLECTIONS:
            try:
                stats[name] = self.client.get_collection(name).count()
            except Exception:
                stats[name] = 0
        return stats
