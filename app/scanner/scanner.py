import logging
import os
import subprocess
import time

import alert_engine
import database
from scanner.mirai_check import check_mirai_ssh
from scanner.nmap_runner import Host, ServiceResult, ping_scan, service_scan
from scanner.nvd_client import search_cves

logger = logging.getLogger(__name__)

_IOT_KEYWORDS = {
    "espressif",
    "tuya",
    "xiaomi",
    "shelly",
    "raspberry pi",
    "sonoff",
    "wyze",
    "meross",
    "blink",
    "ring",
    "tado gmbh",
    "philips lighting bv",
    "amazon technologies",
    "seongji industry company",
    "tp-link systems",
}

_PC_KEYWORDS = {
    "intel",
    "apple",
    "dell",
    "lenovo",
    "microsoft",
    "vmware",
    "hewlett packard",
    "asustek computer",
    "nintendo",
    "liteon technology",
    "acer",
}


def _classify_vendor(vendor: str) -> str:
    v = vendor.lower()
    if any(k in v for k in _IOT_KEYWORDS):
        return "iot"
    if any(k in v for k in _PC_KEYWORDS):
        return "pc"
    return "unknown"


def _detect_subnet() -> str:
    try:
        out = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            subnet = parts[0]
            if "/" not in subnet:
                continue
            if subnet.startswith("172."):
                continue
            if "proto" in parts and "kernel" in parts:
                logger.info("Subred detectada: %s", subnet)
                return subnet
    except Exception as exc:
        logger.warning("ip route falló: %s", exc)

    fallback = "192.168.1.0/24"
    logger.warning("Usando subred por defecto: %s", fallback)
    return fallback


class NetworkScanner:
    def __init__(self) -> None:
        self._api_key = os.getenv("NVD_API_KEY", "")
        self._scan_interval = int(os.getenv("SCAN_INTERVAL") or "60") * 60

    def scan(self) -> None:
        subnet = _detect_subnet()
        logger.info("Scan iniciado en %s", subnet)

        hosts = ping_scan(subnet)
        if not hosts:
            logger.warning("No se encontraron hosts en %s", subnet)
            return

        existing_macs = {d["mac"] for d in database.get_devices()}
        device_types: list[str] = []

        for host in hosts:
            mac = host.mac or "UNKNOWN"
            device_type = _classify_vendor(host.vendor)
            device_types.append(device_type)

            is_new = mac != "UNKNOWN" and mac not in existing_macs

            database.upsert_device(
                mac=mac,
                ip=host.ip,
                vendor=host.vendor,
                device_type=device_type,
            )

            if is_new:
                alert_engine.create_alert(
                    severity="HIGH",
                    category="NETWORK",
                    title=f"Nuevo dispositivo LAN: {host.ip}",
                    detail=(
                        f"Se ha detectado un nuevo dispositivo: IP {host.ip}, "
                        f"MAC {mac}, vendor '{host.vendor}'. "
                        "No estaba registrado en el inventario."
                    ),
                    recommendation=(
                        "Identifica el dispositivo por su dirección MAC usando "
                        "un buscador OUI. Si no lo reconoces, desconéctalo de "
                        "tu red y cambia la contraseña del Wi-Fi."
                    ),
                )

        if "iot" in device_types and "pc" in device_types:
            alert_engine.create_alert(
                severity="MEDIUM",
                category="NETWORK",
                title="IoT y PCs sin segmentar en la misma subred",
                detail=(
                    f"Hay dispositivos IoT y PCs conviviendo en {subnet}. "
                    "Un IoT comprometido puede acceder directamente a los PCs."
                ),
                recommendation=(
                    "Crea una VLAN separada para dispositivos IoT en tu "
                    "router o punto de acceso para aislarlos de los PCs "
                    "y datos personales."
                ),
            )

        for host in hosts:
            self._scan_host_services(host)

        logger.info("Scan completado: %d hosts procesados", len(hosts))

    def run_loop(self) -> None:
        time.sleep(30)
        while True:
            try:
                self.scan()
            except Exception as exc:
                logger.error("Error en scan: %s", exc, exc_info=True)
            time.sleep(self._scan_interval)


    def _scan_host_services(self, host: Host) -> None:
        result = service_scan(host)
        mac = host.mac or "UNKNOWN"
        open_ports = {p.port for p in result.open_ports}

        for port_info in result.open_ports:
            database.insert_port(
                device_mac=mac,
                port=port_info.port,
                protocol=port_info.protocol,
                service=port_info.service,
                version=port_info.version,
            )

        if 23 in open_ports:
            alert_engine.create_alert(
                severity="HIGH",
                category="NETWORK",
                title=f"Telnet expuesto en {host.ip}",
                detail=(
                    f"Puerto 23 (Telnet) abierto en {host.ip} ({mac}). "
                    "Las credenciales viajan en texto plano."
                ),
                recommendation=(
                    "Deshabilita Telnet en la configuración del dispositivo "
                    "y usa SSH si necesitas acceso remoto por línea de comandos."
                ),
            )

        if 80 in open_ports and 443 not in open_ports:
            alert_engine.create_alert(
                severity="MEDIUM",
                category="NETWORK",
                title=f"HTTP sin HTTPS en {host.ip}",
                detail=(
                    f"Puerto 80 abierto pero no el 443 en {host.ip} ({mac}). "
                    "El tráfico web no está cifrado."
                ),
                recommendation=(
                    "Accede al dispositivo solo desde red local y actualiza "
                    "su firmware a la última versión disponible del fabricante."
                ),
            )

        if result.has_default_web_creds:
            alert_engine.create_alert(
                severity="CRITICAL",
                category="NETWORK",
                title=f"Credenciales web por defecto en {host.ip}",
                detail=(
                    f"nmap detectó credenciales por defecto activas en {host.ip} ({mac}). "
                    f"Detalle: {result.http_script_output[:300]}"
                ),
                recommendation=(
                    "Cambia inmediatamente las credenciales por defecto del "
                    "panel web del dispositivo desde su página de administración."
                ),
            )

        if 22 in open_ports:
            success, user, password = check_mirai_ssh(host.ip)
            if success:
                alert_engine.create_alert(
                    severity="CRITICAL",
                    category="NETWORK",
                    title=f"Credenciales Mirai SSH en {host.ip}",
                    detail=(
                        f"El dispositivo {host.ip} ({mac}) acepta SSH con '{user}'/'{password}', "
                        "credencial asociada al malware Mirai. "
                        "El dispositivo puede estar comprometido."
                    ),
                    recommendation=(
                        "Cambia las credenciales SSH del dispositivo, deshabilita "
                        "el acceso root por SSH y considera usar autenticación "
                        "por clave pública en lugar de contraseña."
                    ),
                )

        self._check_cves(host, result)

    def _check_cves(self, host: Host, result: ServiceResult) -> None:
        mac = host.mac or "UNKNOWN"
        queried: set[str] = set()

        for port_info in result.open_ports:
            service = port_info.service
            version = port_info.version

            query_key = f"{service} {version}".strip()
            if not query_key or query_key in queried:
                continue
            queried.add(query_key)

            cves = search_cves(service, version, self._api_key)

            for cve in cves:
                score = cve["cvss_score"]
                severity = "CRITICAL" if score >= 9.0 else "HIGH"

                database.insert_cve(
                    device_mac=mac,
                    cve_id=cve["cve_id"],
                    severity=severity,
                    cvss_score=score,
                    description=cve["description"],
                )

                if score >= 9.0:
                    cve_rec = (
                        "Actualiza el firmware o software del dispositivo a la "
                        "última versión disponible del fabricante con urgencia. "
                        "Consulta los detalles en nvd.nist.gov."
                    )
                else:
                    cve_rec = (
                        "Revisa el CVE en nvd.nist.gov y aplica el parche del "
                        "fabricante si está disponible. Considera aislar el "
                        "dispositivo hasta que esté actualizado."
                    )

                alert_engine.create_alert(
                    severity=severity,
                    category="CVE",
                    title=f"{cve['cve_id']} en {host.ip} ({query_key})",
                    detail=f"CVSS {score:.1f}: {cve['description'][:300]}",
                    recommendation=cve_rec,
                )
