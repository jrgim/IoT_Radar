from unittest.mock import MagicMock, patch

import pytest
import nmap
from scanner.nmap_runner import ping_scan, service_scan, Host, PortInfo, ServiceResult


def _make_ping_nm(hosts_data: dict):
    """
    hosts_data: {ip: {"mac": "AA:BB:CC:DD:EE:FF", "vendor": "Espressif"}}
    """
    nm = MagicMock(spec=nmap.PortScanner)
    nm.all_hosts.return_value = list(hosts_data.keys())

    def getitem(ip):
        d = hosts_data[ip]
        mac = d.get("mac", "")
        return {
            "addresses": {"mac": mac, "ipv4": ip},
            "vendor": {mac.upper(): d.get("vendor", "")} if mac else {},
        }

    nm.__getitem__.side_effect = getitem
    return nm


def _make_service_nm(ip: str, ports: dict):
    """
    ports: {"tcp": {80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4", "script": {}}}}
    """
    nm = MagicMock(spec=nmap.PortScanner)
    nm.all_hosts.return_value = [ip]
    nm.__getitem__.return_value = ports
    return nm



class TestPingScan:
    def test_returns_host_list(self):
        nm = _make_ping_nm({"192.168.1.1": {"mac": "AA:BB:CC:DD:EE:FF", "vendor": "Espressif"}})
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert len(hosts) == 1
        assert hosts[0].ip == "192.168.1.1"
        assert hosts[0].mac == "AA:BB:CC:DD:EE:FF"
        assert hosts[0].vendor == "Espressif"

    def test_mac_uppercased(self):
        nm = _make_ping_nm({"192.168.1.1": {"mac": "aa:bb:cc:dd:ee:ff", "vendor": ""}})
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert hosts[0].mac == "AA:BB:CC:DD:EE:FF"

    def test_returns_empty_on_no_hosts(self):
        nm = MagicMock(spec=nmap.PortScanner)
        nm.all_hosts.return_value = []
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert hosts == []

    def test_returns_empty_on_scanner_error(self):
        nm = MagicMock(spec=nmap.PortScanner)
        nm.scan.side_effect = nmap.PortScannerError("no nmap")
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert hosts == []

    def test_multiple_hosts(self):
        nm = _make_ping_nm({
            "192.168.1.1": {"mac": "AA:AA:AA:AA:AA:AA", "vendor": "VendorA"},
            "192.168.1.2": {"mac": "BB:BB:BB:BB:BB:BB", "vendor": "VendorB"},
        })
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert len(hosts) == 2

    def test_host_without_mac(self):
        nm = _make_ping_nm({"192.168.1.1": {"mac": "", "vendor": ""}})
        with patch("nmap.PortScanner", return_value=nm):
            hosts = ping_scan("192.168.1.0/24")
        assert hosts[0].mac == ""
        assert hosts[0].vendor == ""



class TestServiceScan:
    HOST = Host(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF", vendor="Test")

    def test_returns_open_ports(self):
        ports = {
            "tcp": {80: {"state": "open", "name": "http", "product": "Apache", "version": "2.4.1", "script": {}}},
            "udp": {},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 80
        assert result.open_ports[0].protocol == "tcp"
        assert result.open_ports[0].service == "http"

    def test_skips_non_open_ports(self):
        ports = {
            "tcp": {
                80: {"state": "open", "name": "http", "product": "", "version": "", "script": {}},
                22: {"state": "filtered", "name": "ssh", "product": "", "version": "", "script": {}},
            },
            "udp": {},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 80

    def test_detects_default_web_credentials(self):
        ports = {
            "tcp": {
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "",
                    "version": "",
                    "script": {"http-default-accounts": "admin:admin found"},
                }
            },
            "udp": {},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert result.has_default_web_creds is True
        assert "admin:admin found" in result.http_script_output

    def test_no_default_creds_when_script_empty(self):
        ports = {
            "tcp": {80: {"state": "open", "name": "http", "product": "", "version": "", "script": {}}},
            "udp": {},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert result.has_default_web_creds is False

    def test_returns_empty_result_on_scanner_error(self):
        nm = MagicMock(spec=nmap.PortScanner)
        nm.scan.side_effect = nmap.PortScannerError("nmap not found")
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert result.open_ports == []
        assert result.has_default_web_creds is False

    def test_returns_empty_result_when_host_not_in_output(self):
        nm = MagicMock(spec=nmap.PortScanner)
        nm.all_hosts.return_value = []
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert result.open_ports == []

    def test_version_string_concatenated_from_product_and_version(self):
        ports = {
            "tcp": {22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.2", "script": {}}},
            "udp": {},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert result.open_ports[0].version == "OpenSSH 8.2"

    def test_udp_ports_included(self):
        ports = {
            "tcp": {},
            "udp": {1883: {"state": "open", "name": "mqtt", "product": "", "version": "", "script": {}}},
        }
        nm = _make_service_nm(self.HOST.ip, ports)
        with patch("nmap.PortScanner", return_value=nm):
            result = service_scan(self.HOST)
        assert len(result.open_ports) == 1
        assert result.open_ports[0].protocol == "udp"
