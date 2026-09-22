import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

import rotate_keys
import suite_backup


def test_rotate_keys_detects_weak():
    assert rotate_keys.is_weak(None) is True
    assert rotate_keys.is_weak("asgard-heimdall-key") is True
    assert rotate_keys.is_weak("short") is True
    assert rotate_keys.is_weak("x" * 32) is False
    assert len(rotate_keys.generate_key()) >= 40


def test_rotate_keys_upsert_env_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("HEIMDALL_API_KEY=asgard-heimdall-key\n", encoding="utf-8")
    updated = rotate_keys.upsert_env_file(str(env))
    assert "HEIMDALL_API_KEY" in updated
    text = env.read_text(encoding="utf-8")
    assert "asgard-heimdall-key" not in text
    # Seconda passata: chiavi già forti -> nessuna modifica
    assert rotate_keys.upsert_env_file(str(env)) == {}


def test_suite_backup_roundtrip(tmp_path, monkeypatch):
    # Fake repo root con 2 db finti
    root = tmp_path / "repo"
    (root / "Heimdall").mkdir(parents=True)
    (root / "Fenrir").mkdir(parents=True)
    import sqlite3
    for rel in ("Heimdall/heimdall.db", "Fenrir/fenrir.db"):
        c = sqlite3.connect(str(root / rel))
        c.execute("CREATE TABLE t(id INTEGER)")
        c.commit()
        c.close()
    monkeypatch.setattr(suite_backup, "ROOT", str(root))
    monkeypatch.setattr(suite_backup, "CANDIDATES", [
        ("heimdall_db", "Heimdall/heimdall.db"),
        ("fenrir_db", "Fenrir/fenrir.db"),
    ])
    out = tmp_path / "out"
    res = suite_backup.create_suite_backup(str(out), keep=2)
    assert suite_backup.verify_suite_backup(res["path"])["verified"] is True
