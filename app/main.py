import asyncio
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

import alert_engine
from database import init_db, get_alerts, get_devices, get_zigbee_devices
from mqtt.monitor import MQTTMonitor
from scanner.scanner import NetworkScanner
from web.websocket import manager

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


class _NormalizePath:
    #Strips leading double slashes injected by HA Ingress when ingress_entry is '/'.

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            path: str = scope.get("path", "")
            if path.startswith("//"):
                scope = {**scope, "path": "/" + path.lstrip("/")}
        await self.app(scope, receive, send)


DB_PATH = os.getenv("DB_PATH", "/tmp/iot_radar.db")
_STATIC_DIR = Path(__file__).parent / "web" / "static"
_INDEX_HTML = (_STATIC_DIR / "index.html").read_text()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(DB_PATH)
    alert_engine.set_event_loop(asyncio.get_running_loop())

    threading.Thread(target=_mqtt_thread, daemon=True).start()
    logger.info("Thread MQTT iniciado")

    threading.Thread(target=_scanner_thread, daemon=True).start()
    logger.info("Thread Scanner iniciado")

    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(_NormalizePath)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def _mqtt_thread():
    try:
        MQTTMonitor().start()
    except Exception as exc:
        logger.exception("MQTT thread caído irrecuperablemente: %s", exc)


def _scanner_thread():
    while True:
        try:
            NetworkScanner().run_loop()
        except Exception as exc:
            logger.exception("Scanner thread caído, reintentando en 60s: %s", exc)
        time.sleep(60)


# = API routes

@app.get("/api/status")
def status():
    alerts = get_alerts(limit=200)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
    score = max(0, 100 - counts["CRITICAL"] * 30 - counts["HIGH"] * 15
                - counts["MEDIUM"] * 5 - counts["LOW"] * 1)
    return {"score": score, **counts, "total_devices": len(get_devices())}


@app.get("/api/alerts")
def api_alerts():
    return get_alerts()


@app.post("/api/alerts/{alert_id}/resolve")
def resolve(alert_id: int):
    from database import resolve_alert
    resolve_alert(alert_id)
    return {"ok": True}


@app.get("/api/devices")
def api_devices():
    from database import get_ports_by_mac, get_cves_by_mac
    devices = get_devices()
    for d in devices:
        d["ports"] = get_ports_by_mac(d["mac"])
        d["cves"] = get_cves_by_mac(d["mac"])
    return devices


@app.get("/api/zigbee")
def api_zigbee():
    return get_zigbee_devices()


@app.post("/api/scan")
def api_scan():
    def _run():
        try:
            NetworkScanner().scan()
        except Exception as exc:
            logger.error("Scan manual fallido: %s", exc)
    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True}


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


@app.get("/")
@app.get("/{full_path:path}")
def root(request: Request):
    ingress = request.headers.get("X-Ingress-Path", "").rstrip("/")
    base = ingress + "/" if ingress else "/"
    html = _INDEX_HTML.replace("<head>", f'<head>\n    <base href="{base}">', 1)
    return HTMLResponse(html)


if __name__ == "__main__":
    port = int(os.getenv("INGRESS_PORT", "8765"))
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=True, forwarded_allow_ips="*")
