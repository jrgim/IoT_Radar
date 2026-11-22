import logging
import os
import socket
import time
from collections import defaultdict

import alert_engine
import database

logger = logging.getLogger(__name__)

LQI_WINDOW = 10
LQI_THRESHOLD = 20
FLOOD_WINDOW_SECS = 60
FLOOD_THRESHOLD = 200
_Z2M_PREFIX = os.getenv("Z2M_TOPIC_PREFIX", "zigbee2mqtt") + "/"


def check_broker_auth() -> None:
    alert_engine.create_alert(
        severity="CRITICAL",
        category="MQTT",
        title="Broker sin autenticación",
        detail=(
            "El broker MQTT acepta conexiones anónimas. "
            "Cualquier dispositivo de la red puede publicar y suscribirse sin credenciales."
        ),
        recommendation=(
            "Configura allow_anonymous false en Mosquitto y establece "
            "usuario y contraseña en /etc/mosquitto/mosquitto.conf."
        ),
    )


def check_broker_tls(host: str) -> None:
    tls_port = 8883
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex((host, tls_port))
    sock.close()

    if result != 0:
        alert_engine.create_alert(
            severity="HIGH",
            category="MQTT",
            title="Broker MQTT sin TLS",
            detail=(
                f"El broker en {host} no acepta conexiones TLS en el puerto {tls_port}. "
                "El tráfico MQTT viaja en texto plano, incluyendo credenciales y estados de dispositivos."
            ),
            recommendation=(
                "Habilita el puerto 8883 con certificado TLS en Mosquitto "
                "para cifrar el tráfico MQTT."
            ),
        )


def check_permit_join(payload: dict) -> None:
    permit_join = payload.get("permit_join")
    permit_join_timeout = payload.get("permit_join_timeout")

    if permit_join is True and permit_join_timeout is None:
        alert_engine.create_alert(
            severity="HIGH",
            category="ZIGBEE",
            title="permit_join permanente activo",
            detail=(
                "La red Zigbee está abierta a nuevos dispositivos sin límite de tiempo. "
                "Cualquier dispositivo Zigbee cercano puede unirse sin autorización."
            ),
            recommendation=(
                "Desactiva permit_join desde el panel de Zigbee2MQTT "
                "en cuanto termines de emparejar dispositivos."
            ),
        )


def check_network_key(payload: dict, source: str = "bridge/config") -> None:
    """Supports Z2M 1.x (`bridge/config`, `network_key` at root) and
    Z2M 2.x (`bridge/info`, `config.advanced.network_key`, normally masked as "HIDDEN")."""
    if not isinstance(payload, dict):
        return

    if source == "bridge/info":
        advanced = payload.get("config", {}).get("advanced")
        if not isinstance(advanced, dict):
            return
        network_key = advanced.get("network_key")
        topic_label = "bridge/info"
    else:
        network_key = payload.get("network_key")
        topic_label = "bridge/config"

    if not _is_network_key_exposed(network_key):
        return

    alert_engine.create_alert(
        severity="CRITICAL",
        category="ZIGBEE",
        title="Network key Zigbee expuesta en MQTT",
        detail=(
            f"La clave de cifrado AES-128 de la red Zigbee está visible en el topic "
            f"{topic_label} sin enmascarar. Con esta clave, un atacante puede descifrar "
            "todo el tráfico Zigbee."
        ),
        recommendation=(
            "Regenera la network key desde Zigbee2MQTT (Settings → "
            "Tools → Reset network key) y revisa que no se publique "
            "en claro en los topics MQTT."
        ),
    )


def _is_network_key_exposed(value) -> bool:
    #Returns True if the published value exposes the real network key.
    if value is None:
        return False
    if isinstance(value, str):
        if value.upper() in ("GENERATE", "HIDDEN", ""):
            return False
        if set(value) <= {"*"}:  # masks like "************"
            return False
        return True
    if isinstance(value, list):  # unmasked byte array
        return True
    return False


def check_device_joined(
    payload: dict, known_zigbee: set, friendly_to_ieee: dict | None = None
) -> None:
    if payload.get("type") != "device_joined":
        return

    data = payload.get("data", {})
    ieee = data.get("ieee_address", "")
    if not ieee:
        return

    if ieee not in known_zigbee:
        friendly = data.get("friendly_name", ieee)
        alert_engine.create_alert(
            severity="HIGH",
            category="ZIGBEE",
            title=f"Dispositivo Zigbee desconocido: {friendly}",
            detail=(
                f"El dispositivo con IEEE {ieee} se ha unido a la red Zigbee "
                "pero no estaba en la lista de dispositivos conocidos."
            ),
            recommendation=(
                "Verifica si reconoces este dispositivo por su IEEE. "
                "Si no lo autorizaste, expúlsalo desde el panel de "
                "Zigbee2MQTT y revisa quién tiene acceso físico a tu red."
            ),
        )
        known_zigbee.add(ieee)
        if friendly_to_ieee is not None and friendly and friendly != ieee:
            friendly_to_ieee[friendly] = ieee
        database.upsert_zigbee_device(ieee, friendly_name=friendly)


def check_frontend_auth(payload: dict) -> None:
    config = payload.get("config", {})
    if not isinstance(config, dict):
        return

    frontend = config.get("frontend")
    if not isinstance(frontend, dict):
        return

    auth_token = frontend.get("auth_token")
    if not auth_token:
        alert_engine.create_alert(
            severity="MEDIUM",
            category="MQTT",
            title="Frontend Zigbee2MQTT sin autenticación",
            detail=(
                "El panel web de Zigbee2MQTT no tiene auth_token configurado. "
                "Cualquier usuario de la red local puede acceder y controlar los dispositivos Zigbee."
            ),
            recommendation=(
                "Añade auth_token en la configuración del frontend de "
                "Zigbee2MQTT para requerir contraseña de acceso."
            ),
        )


def check_lqi(device_key: str, payload: dict, lqi_history: defaultdict) -> None:
    """ `device_key` should be the device IEEE address when resolvable from `bridge/devices`;
    falls back to the full topic otherwise. """
    if not isinstance(payload, dict):
        return

    lqi = payload.get("linkquality")
    if lqi is None:
        return

    history = lqi_history[device_key]
    history.append(int(lqi))

    if len(history) > LQI_WINDOW:
        del history[0]

    if len(history) == LQI_WINDOW:
        avg = sum(history) / LQI_WINDOW
        if avg < LQI_THRESHOLD:
            alert_engine.create_alert(
                severity="MEDIUM",
                category="ZIGBEE",
                title=f"LQI crítico en {device_key}",
                detail=(
                    f"El promedio de calidad de señal (LQI) en las últimas {LQI_WINDOW} "
                    f"lecturas es {avg:.1f}/255, por debajo del umbral de {LQI_THRESHOLD}. "
                    "Posible jamming o interferencia de radio."
                ),
                recommendation=(
                    "Busca fuentes de interferencia en la banda de 2.4 GHz "
                    "cerca de tus dispositivos Zigbee (routers Wi-Fi, "
                    "microondas, teléfonos inalámbricos)."
                ),
            )


def check_flood(topic: str, flood_log: defaultdict) -> None:
    # Z2M topics are exempt: their legitimate high-frequency telemetry would cause continuous false positives.
    if topic.startswith(_Z2M_PREFIX):
        return

    now = time.time()

    timestamps = flood_log[topic]
    flood_log[topic] = [t for t in timestamps if now - t <= FLOOD_WINDOW_SECS]
    flood_log[topic].append(now)

    count = len(flood_log[topic])
    if count > FLOOD_THRESHOLD:
        alert_engine.create_alert(
            severity="HIGH",
            category="MQTT",
            title=f"Flood MQTT en topic {topic}",
            detail=(
                f"Se han recibido {count} mensajes en el topic '{topic}' "
                f"en los últimos {FLOOD_WINDOW_SECS}s "
                f"(umbral: {FLOOD_THRESHOLD}). "
                "Posible ataque de denegación de servicio contra el broker."
            ),
            recommendation=(
                "Identifica el cliente que genera el flood con un monitor "
                "MQTT (ej: MQTT Explorer) y desconéctalo. Puede indicar "
                "un dispositivo malfuncionando o un cliente malintencionado."
            ),
        )
