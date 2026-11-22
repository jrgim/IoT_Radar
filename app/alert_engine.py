import asyncio
import logging

import database
import ha_client

logger = logging.getLogger(__name__)
_event_loop = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _event_loop
    _event_loop = loop


def create_alert(severity: str, category: str, title: str, detail: str, recommendation: str = "") -> bool:
    is_new = database.insert_alert(severity, category, title, detail, recommendation)

    if not is_new:
        logger.debug("Alerta duplicada ignorada: [%s] %s", category, title)
        return False

    _notify(severity, title, detail, recommendation)
    _broadcast(severity, category, title, detail, recommendation)
    return True


def _notify(severity: str, title: str, detail: str, recommendation: str) -> None:
    message = (
        f"{detail}\n\nRecomendación: {recommendation}" if recommendation else detail
    )

    ha_client.send_persistent_notification(title, message)


def _broadcast(severity: str, category: str, title: str, detail: str, recommendation: str = "") -> None:
    if _event_loop is None:
        return
    try:
        from web.websocket import manager

        alert_dict = {
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
        }
        asyncio.run_coroutine_threadsafe(manager.broadcast(alert_dict), _event_loop)
    except Exception as exc:
        logger.warning("WebSocket broadcast fallido: %s", exc)
