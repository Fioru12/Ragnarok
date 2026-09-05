"""Backup & restore of all Ragnarok persistent state.

Covers every local data store the orchestrator relies on:
  - ragnarok_auth.db    (users, sessions, failed logins)
  - ragnarok_audit.db   (audit trail)
  - ChromaDB directory  (RAG vector index + conversation memory.db)
  - output/security_history.db (compliance score history)

Every archive contains a manifest.json with the sha256 of each entry so a
restore is verified before any file is written back ("it really works, or it
isn't in the suite" — a restore that cannot be verified is not a restore).

No external dependencies: zipfile/hashlib/json from the standard library.
"""

import hashlib
import json
import os
import time
import zipfile
from typing import Any, Dict, List

MANIFEST_NAME = "manifest.json"


def _store_paths() -> List[Dict[str, Any]]:
    """Resolve the current set of data stores. Imported lazily so that
    monkeypatching the source modules in tests is respected."""
    from auth import AUTH_DB_PATH  # local import: paths may be monkeypatched
    import server as _server
    from rag import get_db_path

    stores: List[Dict[str, Any]] = [
        {"label": "auth_db", "path": AUTH_DB_PATH, "is_dir": False},
        {"label": "audit_db", "path": _server.AUDIT_DB_PATH, "is_dir": False},
        {"label": "rag_vector_db", "path": get_db_path(), "is_dir": True},
    ]
    # Security score history (optional: may not exist on fresh installs)
    sh = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "security_history.db")
    if os.path.isfile(sh):
        stores.append({"label": "security_history_db", "path": sh, "is_dir": False})
    return [s for s in stores if os.path.exists(s["path"])]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_backup(output_dir: str = None) -> Dict[str, Any]:
    """
    Create a verified backup archive. Returns {path, files, bytes, stores}.
    Fails loudly if nothing could be backed up.
    """
    stores = _store_paths()
    if not stores:
        raise RuntimeError("No data stores found to back up.")
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
    os.makedirs(output_dir, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(output_dir, f"ragnarok_backup_{ts}.zip")

    manifest: Dict[str, Any] = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stores": [s["label"] for s in stores],
        "entries": {},  # archive name -> {"sha256": ..., "size": ...}
    }
    files = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for store in stores:
            if store["is_dir"]:
                for root, _dirs, names in os.walk(store["path"]):
                    for name in names:
                        full = os.path.join(root, name)
                        rel = os.path.relpath(full, store["path"]).replace("\\", "/")
                        arcname = f"{store['label']}/{rel}"
                        zf.write(full, arcname)
                        manifest["entries"][arcname] = {
                            "sha256": _sha256_file(full),
                            "size": os.path.getsize(full),
                        }
                        files += 1
            else:
                arcname = f"{store['label']}.db"
                zf.write(store["path"], arcname)
                manifest["entries"][arcname] = {
                    "sha256": _sha256_file(store["path"]),
                    "size": os.path.getsize(store["path"]),
                }
                files += 1
        zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))

    return {
        "path": zip_path,
        "files": files,
        "bytes": os.path.getsize(zip_path),
        "stores": [s["label"] for s in stores],
    }


def verify_backup(zip_path: str) -> Dict[str, Any]:
    """
    Verify an archive against its manifest (presence + sha256 of every entry).
    Raises RuntimeError on any mismatch — never a silent pass.
    """
    if not os.path.isfile(zip_path):
        raise RuntimeError(f"Backup file not found: {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        if MANIFEST_NAME not in zf.namelist():
            raise RuntimeError("Invalid backup: manifest.json missing.")
        manifest = json.loads(zf.read(MANIFEST_NAME))
        checked, bad = 0, []
        for arcname, meta in manifest["entries"].items():
            if arcname not in zf.namelist():
                bad.append(f"missing: {arcname}")
                continue
            digest = hashlib.sha256(zf.read(arcname)).hexdigest()
            if digest != meta["sha256"]:
                bad.append(f"corrupted: {arcname}")
                continue
            checked += 1
    if bad:
        raise RuntimeError("Backup verification failed: " + "; ".join(bad))
    return {
        "verified": True,
        "checked": checked,
        "stores": manifest["stores"],
        "created_at": manifest["created_at"],
    }


def restore_backup(zip_path: str) -> Dict[str, Any]:
    """
    Verify the archive, then restore every entry to its live location.
    Returns {restored: [archive names], stores}. Raises on verification
    failure or when an entry maps to a store not configured on this system.
    """
    verify_backup(zip_path)
    restored: List[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
        label_to_path = {s["label"]: s for s in _store_paths()}
        for arcname in manifest["entries"]:
            label = arcname.split("/", 1)[0]
            if "/" not in arcname:
                # Single-file store entry, e.g. 'auth_db.db' -> label 'auth_db'
                label = label.rsplit(".", 1)[0]
            store = label_to_path.get(label)
            if store is None:
                raise RuntimeError(
                    f"Cannot restore '{arcname}': store '{label}' is not configured on this system."
                )
            if store["is_dir"]:
                data = zf.read(arcname)
                dest = os.path.join(store["path"], *arcname.split("/", 1)[1].split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as f:
                    f.write(data)
            else:
                with open(store["path"], "wb") as f:
                    f.write(zf.read(arcname))
            restored.append(arcname)
    return {"restored": restored, "stores": manifest["stores"]}
