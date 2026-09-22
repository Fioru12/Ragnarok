import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import backup


def _touch(path, mtime):
    with open(path, "wb") as f:
        f.write(b"x")
    os.utime(path, (mtime, mtime))


def test_retention_limits_defaults_and_invalid(tmp_path, monkeypatch):
    monkeypatch.delenv("BACKUP_KEEP_COUNT", raising=False)
    monkeypatch.delenv("BACKUP_RETENTION_DAYS", raising=False)
    assert backup._retention_limits() == {"keep_count": 14, "retention_days": 30}
    monkeypatch.setenv("BACKUP_KEEP_COUNT", "nan")
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "-5")
    assert backup._retention_limits() == {"keep_count": 14, "retention_days": 30}


def test_prune_old_backups_keep_count(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_KEEP_COUNT", "2")
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "0")
    now = time.time()
    for i in range(4):
        _touch(str(tmp_path / f"ragnarok_backup_2026010{i}.zip"), now - i * 10)
    res = backup.prune_old_backups(str(tmp_path))
    assert res["kept"] == 2
    assert len(res["pruned"]) == 2
    remaining = sorted(f for f in os.listdir(str(tmp_path)) if f.endswith(".zip"))
    assert len(remaining) == 2


def test_prune_old_backups_retention_days(tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_KEEP_COUNT", "0")
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "7")
    now = time.time()
    _touch(str(tmp_path / "old.zip"), now - 10 * 86400)
    _touch(str(tmp_path / "new.zip"), now)
    res = backup.prune_old_backups(str(tmp_path))
    assert res["pruned"] == ["old.zip"]
    assert res["kept"] == 1


def test_create_backup_returns_pruned_key(tmp_path, monkeypatch):
    # Backup reale minimo: monkeypatch _store_paths con un singolo file.
    src = tmp_path / "dummy.db"
    src.write_bytes(b"data")
    monkeypatch.setattr(backup, "_store_paths", lambda: [{"label": "auth_db", "path": str(src), "is_dir": False}])
    monkeypatch.setenv("BACKUP_KEEP_COUNT", "5")
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "0")
    out = tmp_path / "out"
    res = backup.create_backup(str(out))
    assert "pruned" in res
    assert os.path.isfile(res["path"])
    assert backup.verify_backup(res["path"])["verified"] is True
