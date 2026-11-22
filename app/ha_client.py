import logging
import os

import requests

logger = logging.getLogger(__name__)

_SUPERVISOR_URL = "http://supervisor/core/api"
_DEV_TOKEN = "fake_token_for_dev"


def send_persistent_notification(title: str, message: str) -> None:
    token = os.getenv("SUPERVISOR_TOKEN", _DEV_TOKEN)

    if token == _DEV_TOKEN:
        logger.info("[DEV] persistent_notification → %s | %s", title, message)
        return

    try:
        resp = requests.post(
            f"{_SUPERVISOR_URL}/services/persistent_notification/create",
            json={"title": title, "message": message},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("Error enviando notificación HA: %s", exc)
