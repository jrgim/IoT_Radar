import logging
from dataclasses import dataclass, field

import nmap

logger = logging.getLogger(__name__)

_SERVICE_PORTS = "22,23,80,443,8080,8443,1883,8883"


@dataclass
class Host:
    ip: str
    mac: str
    vendor: str


@dataclass
class PortInfo:
    port: int
    protocol: str
    service: str
    version: str


@dataclass
class ServiceResult:
    host: Host
    open_ports: list[PortInfo] = field(default_factory=list)
    has_default_web_creds: bool = False
    http_script_output: str = ""


def ping_scan(subnet: str) -> list[Host]:
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn -T4 --send-eth")
    except nmap.PortScannerError as exc:
        logger.error("ping_scan error en %s: %s", subnet, exc)
        return []

    hosts: list[Host] = []
    for ip in nm.all_hosts():
        addresses = nm[ip].get("addresses", {})
        mac = addresses.get("mac", "").upper()
        vendor_dict = nm[ip].get("vendor", {})
        vendor = vendor_dict.get(mac, "") if mac else ""
        hosts.append(Host(ip=ip, mac=mac, vendor=vendor))

    logger.info("ping_scan: %d hosts encontrados en %s", len(hosts), subnet)
    return hosts


def service_scan(host: Host) -> ServiceResult:
    try:
        nm = nmap.PortScanner()
        nm.scan(
            hosts=host.ip,
            arguments=(
                f"-sV -T3 --open --script http-default-accounts -p {_SERVICE_PORTS}"
            ),
        )
    except nmap.PortScannerError as exc:
        logger.error("service_scan error en %s: %s", host.ip, exc)
        return ServiceResult(host=host)

    result = ServiceResult(host=host)

    if host.ip not in nm.all_hosts():
        return result

    host_data = nm[host.ip]
    for proto in ("tcp", "udp"):
        proto_data = host_data.get(proto, {})
        for port_num, port_data in proto_data.items():
            if port_data.get("state") != "open":
                continue

            script_output = port_data.get("script", {})
            http_creds = script_output.get("http-default-accounts", "")
            
            if http_creds.strip():
                result.has_default_web_creds = True
                result.http_script_output = http_creds

            product = port_data.get("product", "")
            version = port_data.get("version", "")
            version_str = f"{product} {version}".strip()

            result.open_ports.append(PortInfo(
                port=int(port_num),
                protocol=proto,
                service=port_data.get("name", ""),
                version=version_str,
            ))

    logger.info(
        "service_scan %s: %d puertos abiertos, creds_defecto=%s",
        host.ip, len(result.open_ports), result.has_default_web_creds,
    )
    return result
