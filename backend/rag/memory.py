import os, sqlite3, json, logging
from datetime import datetime, timezone
from typing import List, Dict, Optional
from . import get_db_path
logger = logging.getLogger('Asgard.RAG.Memory')

class ConversationMemory:
    def __init__(self, db_path=None):
        mem_dir = get_db_path()
        os.makedirs(mem_dir, exist_ok=True)
        self.db_path = os.path.join(mem_dir, 'memory.db')
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS conversation_memory (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, metadata TEXT, timestamp TEXT NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_session ON conversation_memory(session_id)')
        conn.commit()
        conn.close()

    def add(self, session_id, role, content, metadata=None):
        conn = sqlite3.connect(self.db_path)
        conn.execute('INSERT INTO conversation_memory (session_id, role, content, metadata, timestamp) VALUES (?, ?, ?, ?, ?)', (session_id, role, content, json.dumps(metadata) if metadata else None, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()

    def get_history(self, session_id, limit=20):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute('SELECT role, content, metadata, timestamp FROM conversation_memory WHERE session_id = ? ORDER BY id DESC LIMIT ?', (session_id, limit))
        rows = cur.fetchall()
        conn.close()
        history = []
        for row in reversed(rows):
            history.append({'role': row['role'], 'content': row['content'], 'metadata': json.loads(row['metadata']) if row['metadata'] else None, 'timestamp': row['timestamp']})
        return history

    def get_summary(self, session_id):
        history = self.get_history(session_id, limit=50)
        if not history:
            return ''
        lines = []
        for msg in history:
            lines.append(f"{msg['role'].upper()}: {msg['content'][:200]}")
        return '\n'.join(lines)

    def clear_session(self, session_id):
        conn = sqlite3.connect(self.db_path)
        conn.execute('DELETE FROM conversation_memory WHERE session_id = ?', (session_id,))
        conn.commit()
        conn.close()

    def get_all_sessions(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('SELECT DISTINCT session_id FROM conversation_memory')
        sessions = [row[0] for row in cur.fetchall()]
        conn.close()
        return sessions
