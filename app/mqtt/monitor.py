import json
import logging
import os
import threading
import time
from collections import defaultdict

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

import database
from . import rules

logger = logging.getLogger(__name__)

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "")
Z2M_PREFIX = os.getenv("Z2M_TOPIC_PREFIX", "zigbee2mqtt")
_RECONNECT_INITIAL_SECS = 2
_RECONNECT_MAX_SECS = 60


class MQTTMonitor:
    def __init__(self):
        # Shared state accessed from the MQTT loop thread
        self._known_zigbee: set[str] = set()
        self._friendly_to_ieee: dict[str, str] = {}
        self._lqi_history: defaultdict[str, list] = defaultdict(list)
        self._flood_log: defaultdict[str, list] = defaultdict(list)

        self._client = mqtt.Client(CallbackAPIVersion.VERSION2)
        if MQTT_USER:
            self._client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code != 0:
            logger.error("MQTT conexión rechazada: %s", reason_code)
            return

        logger.info("MQTT conectado a %s:%s", MQTT_HOST, MQTT_PORT)

        client.subscribe("#", qos=0)

        # Run in background to avoid blocking the MQTT loop
        threading.Thread(
            target=rules.check_broker_tls,
            args=(MQTT_HOST,),
            daemon=True,
        ).start()
        threading.Thread(target=self._probe_anonymous, daemon=True).start()

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            payload = {}

        if topic == f"{Z2M_PREFIX}/bridge/info":
            rules.check_permit_join(payload)
            rules.check_frontend_auth(payload)
            # Z2M 2.x: network_key under config.advanced
            rules.check_network_key(payload, source="bridge/info")

        elif topic == f"{Z2M_PREFIX}/bridge/config":
            # Z2M 1.x: legacy topic kept for backwards compatibility
            rules.check_network_key(payload, source="bridge/config")

        elif topic == f"{Z2M_PREFIX}/bridge/event":
            rules.check_device_joined(
                payload, self._known_zigbee, self._friendly_to_ieee
            )

        elif topic == f"{Z2M_PREFIX}/bridge/devices":
            self._populate_known_zigbee(payload)

        device_key = self._resolve_device_key(topic)
        rules.check_lqi(device_key, payload, self._lqi_history)

        # Persist LQI history to DB whenever a linkquality reading arrives
        if (isinstance(payload, dict)
                and payload.get("linkquality") is not None
                and device_key in self._known_zigbee):
            database.update_zigbee_lqi(
                device_key,
                json.dumps(self._lqi_history[device_key]),
            )

        rules.check_flood(topic, self._flood_log)

    def _probe_anonymous(self) -> None:
        """Connects without credentials to detect an unauthenticated broker."""
        connected = threading.Event()
        accepted = [False]

        def on_connect(client, userdata, flags, reason_code, properties):
            accepted[0] = reason_code == 0
            connected.set()
            client.disconnect()

        anon = mqtt.Client(CallbackAPIVersion.VERSION2)
        anon.on_connect = on_connect
        try:
            anon.connect(MQTT_HOST, MQTT_PORT, keepalive=5)
            anon.loop_start()
            connected.wait(timeout=5)
            anon.loop_stop()
        except Exception as exc:
            logger.debug("Sonda anónima fallida (broker protegido): %s", exc)
            return

        if accepted[0]:
            rules.check_broker_auth()

    def _populate_known_zigbee(self, payload) -> None:
        if not isinstance(payload, list):
            return

        for device in payload:
            ieee = device.get("ieee_address", "")
            friendly = device.get("friendly_name", "")
            if not ieee:
                continue
            self._known_zigbee.add(ieee)
            if friendly:
                self._friendly_to_ieee[friendly] = ieee
            # Devices listed in bridge/devices are pre-existing known devices → trusted=1
            database.upsert_zigbee_device(ieee, friendly_name=friendly, trusted=1)

        logger.info(
            "Zigbee conocidos cargados: %d dispositivos (%d con friendly_name mapeado)",
            len(self._known_zigbee),
            len(self._friendly_to_ieee),
        )

    def _resolve_device_key(self, topic: str) -> str:
        """Maps `{prefix}/<friendly>/...` → IEEE when known; otherwise returns the topic as-is."""
        prefix = f"{Z2M_PREFIX}/"
        if not topic.startswith(prefix):
            return topic
        remainder = topic[len(prefix) :]
        # Bridge topics don't correspond to individual devices
        if remainder.startswith("bridge/"):
            return topic
        friendly = remainder.split("/", 1)[0]
        return self._friendly_to_ieee.get(friendly, topic)

    def start(self) -> None:
        backoff = _RECONNECT_INITIAL_SECS
        while True:
            try:
                logger.info("Conectando a MQTT %s:%s …", MQTT_HOST, MQTT_PORT)
                self._client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
                backoff = _RECONNECT_INITIAL_SECS
                # loop_forever handles reconnects transparently; only returns on loop_stop()
                # or an unrecoverable failure on the initial connection.
                self._client.loop_forever(retry_first_connection=False)
                logger.warning("MQTT loop_forever terminó, reintentando…")
            except Exception as exc:
                logger.error("MQTT no disponible (%s). Reintento en %ss", exc, backoff)

            time.sleep(backoff)
            backoff = min(backoff * 2, _RECONNECT_MAX_SECS)
