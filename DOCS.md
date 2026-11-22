# IoT Radar

Monitor de seguridad para redes domésticas con dispositivos IoT: MQTT, Zigbee y
LAN. Las alertas aparecen en el panel de la barra lateral y como notificaciones
persistentes en Home Assistant.

## Puesta en marcha

1. Configura el broker MQTT en la pestaña **Configuración**. Con el add-on
   oficial Mosquitto:

   ```yaml
   mqtt_host: core-mosquitto
   mqtt_port: 1883
   mqtt_user: iot_radar
   mqtt_password: "tu_contraseña"
   ```

2. Inicia el add-on y abre **IoT Radar** desde la barra lateral.
3. El primer escaneo de red arranca unos 30 segundos después. Puedes forzar uno
   con **Escanear ahora**.

## Opciones

| Opción | Por defecto | Descripción |
|--------|-------------|-------------|
| `mqtt_host` | `core-mosquitto` | Host del broker MQTT. Cámbialo si no usas el add-on Mosquitto. |
| `mqtt_port` | `1883` | Puerto del broker. |
| `mqtt_user` | — | Usuario del broker. |
| `mqtt_password` | — | Contraseña del broker. |
| `z2m_topic_prefix` | `zigbee2mqtt` | Prefijo base de Zigbee2MQTT. |
| `scan_interval_minutes` | `60` | Minutos entre escaneos de la LAN. |
| `nvd_api_key` | — | API key de NVD (opcional). Sin ella, las consultas de CVE son más lentas. |

## Qué comprueba

**MQTT**
- El broker acepta conexiones sin credenciales (CRITICAL).
- El broker no escucha TLS en el puerto 8883 (HIGH).
- Más de 200 mensajes/minuto en un mismo topic (HIGH).
- Frontend de Zigbee2MQTT sin `auth_token` (MEDIUM).

**Zigbee** (requiere Zigbee2MQTT)
- `permit_join` activo sin límite de tiempo (HIGH).
- Network key publicada en claro en MQTT (CRITICAL).
- Se une un dispositivo que no estaba en la lista conocida (HIGH).
- LQI medio por debajo de 20 en las últimas 10 lecturas (MEDIUM).

**LAN**
- Dispositivo nuevo en la red (HIGH).
- Telnet abierto (HIGH) o HTTP sin HTTPS (MEDIUM).
- Credenciales web por defecto detectadas por nmap (CRITICAL).
- Acceso SSH con credenciales típicas de Mirai (CRITICAL).
- CVEs con CVSS ≥ 7 en los servicios detectados (HIGH / CRITICAL).
- Dispositivos IoT y PCs en la misma subred (MEDIUM).

Una alerta resuelta desde el panel desaparece de la lista. Las alertas se
deduplican: la misma alerta no se notifica dos veces.

## Datos

La base de datos SQLite se guarda en `/data/iot_radar.db`, dentro del
almacenamiento del add-on, y se incluye en las copias de seguridad de Home
Assistant.

## Aviso

Este add-on escanea puertos y prueba credenciales SSH por defecto contra los
dispositivos de tu subred. Úsalo solo en redes propias o con autorización.
