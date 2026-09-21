"""Setup wizard endpoints — moved out of server.py to keep it lean.

Owns SETUP_FIELDS (the env vars downstream modules genuinely read),
SetupRequest, _mask and both /api/v1/setup handlers, verbatim. server.py
re-imports SETUP_FIELDS (tests read server.SETUP_FIELDS); SETUP_ENV_PATH is
imported lazily inside save_setup — same deferred pattern as the other
routers — so there is no import cycle. Paths unchanged.
"""
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict

from auth import require_role

router = APIRouter(tags=["setup"])


# environment variable each downstream module actually reads. Every entry
# here corresponds to an env var a module genuinely consults today - this
# list is deliberately not padded with fields nothing reads yet.
SETUP_FIELDS: Dict[str, Dict[str, str]] = {
    "virustotal_api_key": {"env": "VT_API_KEY", "label": "Chiave API VirusTotal", "used_by": "Mjolnir"},
    "otx_api_key": {"env": "OTX_API_KEY", "label": "Chiave API AlienVault OTX", "used_by": "Fenrir"},
    "telegram_bot_token": {"env": "TELEGRAM_BOT_TOKEN", "label": "Token Bot Telegram", "used_by": "Heimdall"},
    "telegram_chat_id": {"env": "TELEGRAM_CHAT_ID", "label": "Chat ID Telegram", "used_by": "Heimdall"},
    "gjallarhorn_hub_url": {"env": "GJALLARHORN_HUB_URL", "label": "URL Hub Gjallarhorn", "used_by": "Heimdall, Sleipnir"},
    "gjallarhorn_api_key": {"env": "GJALLARHORN_API_KEY", "label": "Chiave API Gjallarhorn", "used_by": "Heimdall, Sleipnir"},
}


class SetupRequest(BaseModel):
    values: Dict[str, str]


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


@router.get("/api/v1/setup")
def get_setup_status(user: dict = Depends(require_role("admin", "analyst", "viewer"))):
    """Reports which integrations are configured, without ever returning the
    actual secret values back to the frontend."""
    fields = {}
    for field, meta in SETUP_FIELDS.items():
        raw = os.environ.get(meta["env"], "")
        fields[field] = {
            "label": meta["label"],
            "used_by": meta["used_by"],
            "configured": bool(raw),
            "preview": _mask(raw) if raw else None,
        }
    return {"fields": fields}


@router.post("/api/v1/setup")
def save_setup(req: SetupRequest, user: dict = Depends(require_role("admin"))):
    """Persists integration keys as env vars for this process (so the next
    module Ragnarok launches immediately picks them up) and writes them to
    a local file so they survive a restart. Unknown field names are ignored
    rather than silently accepted, so a typo in the frontend fails loudly."""
    from server import SETUP_ENV_PATH

    unknown = [f for f in req.values if f not in SETUP_FIELDS]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown setup field(s): {', '.join(unknown)}")

    updated = []
    for field, value in req.values.items():
        env_name = SETUP_FIELDS[field]["env"]
        value = value.strip()
        if not value:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = value
        updated.append(env_name)

    try:
        with open(SETUP_ENV_PATH, "w", encoding="utf-8") as f:
            f.write("# Written by the Ragnarok setup wizard. Do not commit this file.\n")
            for field, meta in SETUP_FIELDS.items():
                current = os.environ.get(meta["env"], "")
                if current:
                    f.write(f"{meta['env']}={current}\n")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Saved in memory but failed to persist to disk: {e}")

    return {"status": "saved", "updated_fields": updated}
