"""Gjallarhorn client - copia vendorizzata (stesso pattern di Heimdall e Sleipnir).

Permette a Ragnarök di inviare notifiche all'hub centralizzato Gjallarhorn
invece di reimplementare la logica Telegram/webhook/SMTP localmente.

Example:

    from rag.notifier import notify

    ok = notify(
        hub_url="http://localhost:8090",
        api_key=os.environ["GJALLARHORN_API_KEY"],
        source="Ragnarok",
        severity="high",
        title="Report Proattivo Asgard",
        message="1 IP CRITICAL rilevato.",
    )
"""

import logging
from typing import List, Optional

import requests

logger = logging.getLogger("gjallarhorn_client")

VALID_SEVERITIES = ("low", "medium", "high", "critical")


def notify(
    hub_url: str,
    api_key: str,
    source: str,
    severity: str,
    title: str,
    message: str,
    channels: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> bool:
    """Invia una notifica a un hub Gjallarhorn.

    Ritorna True se l'hub accetta la notifica (HTTP 2xx), False per qualsiasi
    errore - hub irraggiungibile, timeout, risposta non-2xx, input non valido.
    Non solleva mai eccezioni: il chiamante può usarla fire-and-forget.
    """
    if severity.lower() not in VALID_SEVERITIES:
        logger.warning("Invalid severity '%s', not sending notification.", severity)
        return False

    payload = {
        "source": source,
        "severity": severity.lower(),
        "title": title,
        "message": message,
    }
    if channels:
        payload["channels"] = channels

    url = f"{hub_url.rstrip('/')}/api/v1/notify"

    try:
        response = requests.post(
            url,
            json=payload,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        logger.warning("Could not deliver notification to Gjallarhorn hub at %s: %s", url, e)
        return False