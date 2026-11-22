from unittest.mock import MagicMock, patch

import pytest
from scanner.scanner import _classify_vendor, _detect_subnet, NetworkScanner
from scanner.nmap_runner import Host, ServiceResult, PortInfo


# ── _classify_vendor ──────────────────────────────────────────────────────────

class TestClassifyVendor:
    def test_iot_keyword_espressif(self):
        assert _classify_vendor("Espressif Inc.") == "iot"

    def test_iot_keyword_tuya(self):
        assert _classify_vendor("Tuya Smart") == "iot"

    def test_iot_keyword_shelly(self):
        assert _classify_vendor("Shelly") == "iot"

    def test_iot_keyword_raspberry_pi(self):
        assert _classify_vendor("Raspberry Pi Foundation") == "iot"

    def test_pc_keyword_intel(self):
        assert _classify_vendor("Intel Corporate") == "pc"

    def test_pc_keyword_apple(self):
        assert _classify_vendor("Apple, Inc.") == "pc"

    def test_pc_keyword_dell(self):
        assert _classify_vendor("Dell Inc.") == "pc"

    def test_unknown_vendor(self):
        assert _classify_vendor("Generic Manufacturer") == "unknown"

    def test_empty_vendor(self):
        assert _classify_vendor("") == "unknown"

    def test_case_insensitive(self):
        assert _classify_vendor("ESPRESSIF") == "iot"
        assert _classify_vendor("APPLE") == "pc"


# ── _detect_subnet ────────────────────────────────────────────────────────────

class TestDetectSubnet:
    _ROUTE_OUTPUT = (
        "default via 192.168.1.1 dev eth0 proto dhcp\n"
        "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100\n"
    )

    def test_parses_subnet_from_ip_route(self):
        mock_result = MagicMock()
        mock_result.stdout = self._ROUTE_OUTPUT
        with patch("subprocess.run", return_value=mock_result):
            subnet = _detect_subnet()
        assert subnet == "192.168.1.0/24"

    def test_skips_172_subnets(self):
        mock_result = MagicMock()
        mock_result.stdout = (
            "172.17.0.0/16 dev docker0 proto kernel scope link\n"
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.1\n"
        )
        with patch("subprocess.run", return_value=mock_result):
            subnet = _detect_subnet()
        assert subnet == "192.168.1.0/24"

    def test_fallback_on_subprocess_exception(self):
        with patch("subprocess.run", side_effect=Exception("not found")):
            subnet = _detect_subnet()
        assert subnet == "192.168.1.0/24"

    def test_fallback_when_no_matching_route(self):
        mock_result = MagicMock()
        mock_result.stdout = "default via 192.168.1.1 dev eth0\n"
        with patch("subprocess.run", return_value=mock_result):
            subnet = _detect_subnet()
        assert subnet == "192.168.1.0/24"


# ── NetworkScanner.scan ───────────────────────────────────────────────────────

class TestNetworkScannerScan:
    @pytest.fixture
    def scanner(self, tmp_db):
        return NetworkScanner()

    def test_no_hosts_returns_early(self, scanner, alert_calls):
        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[]), \
             patch("scanner.scanner.database.get_devices", return_value=[]):
            scanner.scan()
        assert len(alert_calls) == 0

    def test_new_device_creates_high_alert(self, scanner, alert_calls, tmp_db):
        host = Host(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:FF", vendor="Unknown")
        mock_result = ServiceResult(host=host)

        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[host]), \
             patch("scanner.scanner.database.get_devices", return_value=[]), \
             patch("scanner.scanner.service_scan", return_value=mock_result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner.scan()

        new_device_alerts = [c for c in alert_calls if "Nuevo dispositivo" in c["title"]]
        assert len(new_device_alerts) == 1
        assert new_device_alerts[0]["severity"] == "HIGH"
        assert new_device_alerts[0]["category"] == "NETWORK"

    def test_existing_device_no_new_device_alert(self, scanner, alert_calls):
        host = Host(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF", vendor="Intel")
        mock_result = ServiceResult(host=host)

        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[host]), \
             patch("scanner.scanner.database.get_devices", return_value=[{"mac": "AA:BB:CC:DD:EE:FF"}]), \
             patch("scanner.scanner.service_scan", return_value=mock_result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner.scan()

        new_device_alerts = [c for c in alert_calls if "Nuevo dispositivo" in c["title"]]
        assert len(new_device_alerts) == 0

    def test_iot_and_pc_in_same_subnet_creates_segmentation_alert(self, scanner, alert_calls):
        iot_host = Host(ip="192.168.1.10", mac="AA:AA:AA:AA:AA:AA", vendor="Espressif")
        pc_host = Host(ip="192.168.1.20", mac="BB:BB:BB:BB:BB:BB", vendor="Intel Corporate")

        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[iot_host, pc_host]), \
             patch("scanner.scanner.database.get_devices", return_value=[]), \
             patch("scanner.scanner.service_scan", return_value=ServiceResult(host=iot_host)), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner.scan()

        seg_alerts = [c for c in alert_calls if "segmentar" in c["title"]]
        assert len(seg_alerts) == 1
        assert seg_alerts[0]["severity"] == "MEDIUM"

    def test_only_iot_no_segmentation_alert(self, scanner, alert_calls):
        host = Host(ip="192.168.1.10", mac="AA:AA:AA:AA:AA:AA", vendor="Espressif")

        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[host]), \
             patch("scanner.scanner.database.get_devices", return_value=[]), \
             patch("scanner.scanner.service_scan", return_value=ServiceResult(host=host)), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner.scan()

        seg_alerts = [c for c in alert_calls if "segmentar" in c["title"]]
        assert len(seg_alerts) == 0

    def test_unknown_mac_not_treated_as_new_device(self, scanner, alert_calls):
        host = Host(ip="192.168.1.10", mac="", vendor="Unknown")
        mock_result = ServiceResult(host=host)

        with patch("scanner.scanner._detect_subnet", return_value="192.168.1.0/24"), \
             patch("scanner.scanner.ping_scan", return_value=[host]), \
             patch("scanner.scanner.database.get_devices", return_value=[]), \
             patch("scanner.scanner.service_scan", return_value=mock_result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner.scan()

        new_device_alerts = [c for c in alert_calls if "Nuevo dispositivo" in c["title"]]
        assert len(new_device_alerts) == 0


# ── _scan_host_services ───────────────────────────────────────────────────────

class TestScanHostServices:
    @pytest.fixture
    def scanner(self, tmp_db):
        return NetworkScanner()

    HOST = Host(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF", vendor="")

    def test_telnet_port_creates_high_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=23, protocol="tcp", service="telnet", version="")],
        )
        with patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)  # needs service_scan mock
        # Better: call _scan_host_services indirectly via mocked service_scan
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        telnet_alerts = [c for c in alert_calls if "Telnet" in c["title"]]
        assert len(telnet_alerts) >= 1
        assert telnet_alerts[0]["severity"] == "HIGH"

    def test_http_without_https_creates_medium_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=80, protocol="tcp", service="http", version="")],
        )
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        http_alerts = [c for c in alert_calls if "HTTP sin HTTPS" in c["title"]]
        assert len(http_alerts) == 1
        assert http_alerts[0]["severity"] == "MEDIUM"

    def test_http_with_https_no_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[
                PortInfo(port=80, protocol="tcp", service="http", version=""),
                PortInfo(port=443, protocol="tcp", service="https", version=""),
            ],
        )
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        http_alerts = [c for c in alert_calls if "HTTP sin HTTPS" in c["title"]]
        assert len(http_alerts) == 0

    def test_default_web_creds_creates_critical_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=80, protocol="tcp", service="http", version="")],
            has_default_web_creds=True,
            http_script_output="admin:admin",
        )
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        cred_alerts = [c for c in alert_calls if "Credenciales web" in c["title"]]
        assert len(cred_alerts) == 1
        assert cred_alerts[0]["severity"] == "CRITICAL"

    def test_ssh_with_mirai_creds_creates_critical_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=22, protocol="tcp", service="ssh", version="")],
        )
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.check_mirai_ssh", return_value=(True, "admin", "admin")), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        mirai_alerts = [c for c in alert_calls if "Mirai" in c["title"]]
        assert len(mirai_alerts) == 1
        assert mirai_alerts[0]["severity"] == "CRITICAL"

    def test_ssh_without_mirai_creds_no_alert(self, scanner, alert_calls):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=22, protocol="tcp", service="ssh", version="")],
        )
        with patch("scanner.scanner.service_scan", return_value=result), \
             patch("scanner.scanner.check_mirai_ssh", return_value=(False, "", "")), \
             patch("scanner.scanner.search_cves", return_value=[]):
            scanner._scan_host_services(self.HOST)

        mirai_alerts = [c for c in alert_calls if "Mirai" in c["title"]]
        assert len(mirai_alerts) == 0


# ── _check_cves ───────────────────────────────────────────────────────────────

class TestCheckCVEs:
    @pytest.fixture
    def scanner(self, tmp_db):
        return NetworkScanner()

    HOST = Host(ip="192.168.1.10", mac="AA:BB:CC:DD:EE:FF", vendor="")

    def test_critical_cve_score_above_9_creates_critical_alert(self, scanner, alert_calls, tmp_db):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=22, protocol="tcp", service="openssh", version="7.4")],
        )
        cve_data = [{"cve_id": "CVE-2023-0001", "cvss_score": 9.8, "description": "Critical vuln"}]
        with patch("scanner.scanner.search_cves", return_value=cve_data):
            scanner._check_cves(self.HOST, result)

        cve_alerts = [c for c in alert_calls if "CVE-2023-0001" in c["title"]]
        assert len(cve_alerts) == 1
        assert cve_alerts[0]["severity"] == "CRITICAL"

    def test_high_cve_score_below_9_creates_high_alert(self, scanner, alert_calls, tmp_db):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[PortInfo(port=80, protocol="tcp", service="apache", version="2.4")],
        )
        cve_data = [{"cve_id": "CVE-2023-0002", "cvss_score": 7.5, "description": "High vuln"}]
        with patch("scanner.scanner.search_cves", return_value=cve_data):
            scanner._check_cves(self.HOST, result)

        cve_alerts = [c for c in alert_calls if "CVE-2023-0002" in c["title"]]
        assert len(cve_alerts) == 1
        assert cve_alerts[0]["severity"] == "HIGH"

    def test_duplicate_service_version_queried_once(self, scanner, alert_calls, tmp_db):
        result = ServiceResult(
            host=self.HOST,
            open_ports=[
                PortInfo(port=80, protocol="tcp", service="apache", version="2.4"),
                PortInfo(port=443, protocol="tcp", service="apache", version="2.4"),
            ],
        )
        with patch("scanner.scanner.search_cves", return_value=[]) as mock_search:
            scanner._check_cves(self.HOST, result)
        assert mock_search.call_count == 1

    def test_no_ports_no_cve_query(self, scanner, alert_calls, tmp_db):
        result = ServiceResult(host=self.HOST, open_ports=[])
        with patch("scanner.scanner.search_cves", return_value=[]) as mock_search:
            scanner._check_cves(self.HOST, result)
        assert mock_search.call_count == 0
