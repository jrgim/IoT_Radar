import pytest
import database


# ── alerts ────────────────────────────────────────────────────────────────────

class TestInsertAlert:
    def test_new_alert_returns_true(self, tmp_db):
        assert database.insert_alert("HIGH", "CAT", "Title", "detail") is True

    def test_duplicate_returns_false(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Title", "detail")
        assert database.insert_alert("HIGH", "CAT", "Title", "detail") is False

    def test_fingerprint_based_on_category_and_title_only(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Title", "first detail")
        # Different severity/detail but same category+title → still duplicate
        assert database.insert_alert("CRITICAL", "CAT", "Title", "second detail") is False

    def test_different_title_is_new(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Title A", "d")
        assert database.insert_alert("HIGH", "CAT", "Title B", "d") is True

    def test_different_category_is_new(self, tmp_db):
        database.insert_alert("HIGH", "CAT_A", "Title", "d")
        assert database.insert_alert("HIGH", "CAT_B", "Title", "d") is True

    def test_recommendation_updated_when_blank(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Title", "d", recommendation="")
        database.insert_alert("HIGH", "CAT", "Title", "d", recommendation="Fix it")
        assert database.get_alerts()[0]["recommendation"] == "Fix it"

    def test_recommendation_not_overwritten_when_already_set(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Title", "d", recommendation="Original")
        database.insert_alert("HIGH", "CAT", "Title", "d", recommendation="Override")
        assert database.get_alerts()[0]["recommendation"] == "Original"


class TestGetAlerts:
    def test_returns_unresolved_only(self, tmp_db):
        database.insert_alert("HIGH", "CAT", "Alert 1", "d")
        database.insert_alert("HIGH", "CAT", "Alert 2", "d")
        alert_id = database.get_alerts()[0]["id"]
        database.resolve_alert(alert_id)
        assert len(database.get_alerts()) == 1

    def test_ordered_by_id_desc(self, tmp_db):
        database.insert_alert("HIGH", "C", "First", "d")
        database.insert_alert("HIGH", "C", "Second", "d")
        alerts = database.get_alerts()
        assert alerts[0]["title"] == "Second"
        assert alerts[1]["title"] == "First"

    def test_limit_respected(self, tmp_db):
        for i in range(5):
            database.insert_alert("LOW", "C", f"Alert {i}", "d")
        assert len(database.get_alerts(limit=3)) == 3

    def test_empty_when_all_resolved(self, tmp_db):
        database.insert_alert("LOW", "C", "A", "d")
        database.resolve_alert(database.get_alerts()[0]["id"])
        assert database.get_alerts() == []

    def test_empty_on_fresh_db(self, tmp_db):
        assert database.get_alerts() == []


class TestResolveAlert:
    def test_marks_as_resolved(self, tmp_db):
        database.insert_alert("HIGH", "C", "Title", "d")
        alert_id = database.get_alerts()[0]["id"]
        database.resolve_alert(alert_id)
        assert database.get_alerts() == []

    def test_nonexistent_id_is_safe(self, tmp_db):
        database.resolve_alert(9999)  # Should not raise


# ── devices ───────────────────────────────────────────────────────────────────

class TestDevices:
    def test_upsert_inserts_new_device(self, tmp_db):
        database.upsert_device("AA:BB:CC:DD:EE:FF", "192.168.1.1", vendor="Espressif")
        devices = database.get_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert devices[0]["vendor"] == "Espressif"

    def test_upsert_updates_ip_on_conflict(self, tmp_db):
        database.upsert_device("AA:BB:CC:DD:EE:FF", "192.168.1.1")
        database.upsert_device("AA:BB:CC:DD:EE:FF", "192.168.1.99")
        devices = database.get_devices()
        assert len(devices) == 1
        assert devices[0]["ip"] == "192.168.1.99"

    def test_first_seen_preserved_on_update(self, tmp_db):
        database.upsert_device("AA:BB:CC:DD:EE:FF", "192.168.1.1")
        first_seen = database.get_devices()[0]["first_seen"]
        database.upsert_device("AA:BB:CC:DD:EE:FF", "192.168.1.2")
        assert database.get_devices()[0]["first_seen"] == first_seen

    def test_device_type_stored(self, tmp_db):
        database.upsert_device("AA:BB:CC:DD:EE:FF", "1.2.3.4", device_type="iot")
        assert database.get_devices()[0]["device_type"] == "iot"

    def test_multiple_devices(self, tmp_db):
        database.upsert_device("AA:AA:AA:AA:AA:AA", "1.1.1.1")
        database.upsert_device("BB:BB:BB:BB:BB:BB", "2.2.2.2")
        assert len(database.get_devices()) == 2

    def test_empty_on_fresh_db(self, tmp_db):
        assert database.get_devices() == []


# ── ports ─────────────────────────────────────────────────────────────────────

class TestPorts:
    MAC = "AA:BB:CC:DD:EE:FF"

    def test_insert_port(self, tmp_db):
        database.insert_port(self.MAC, 80, "tcp", "http", "2.4.1")
        ports = database.get_ports_by_mac(self.MAC)
        assert len(ports) == 1
        assert ports[0]["port"] == 80
        assert ports[0]["service"] == "http"
        assert ports[0]["version"] == "2.4.1"

    def test_duplicate_port_ignored(self, tmp_db):
        database.insert_port(self.MAC, 80, "tcp")
        database.insert_port(self.MAC, 80, "tcp")
        assert len(database.get_ports_by_mac(self.MAC)) == 1

    def test_same_port_different_protocol_is_distinct(self, tmp_db):
        database.insert_port(self.MAC, 80, "tcp")
        database.insert_port(self.MAC, 80, "udp")
        assert len(database.get_ports_by_mac(self.MAC)) == 2

    def test_ordered_by_port_asc(self, tmp_db):
        database.insert_port(self.MAC, 443, "tcp")
        database.insert_port(self.MAC, 80, "tcp")
        ports = database.get_ports_by_mac(self.MAC)
        assert ports[0]["port"] == 80
        assert ports[1]["port"] == 443

    def test_empty_for_unknown_mac(self, tmp_db):
        assert database.get_ports_by_mac("00:00:00:00:00:00") == []


# ── CVEs ──────────────────────────────────────────────────────────────────────

class TestCVEs:
    MAC = "AA:BB:CC:DD:EE:FF"

    def test_insert_cve(self, tmp_db):
        database.insert_cve(self.MAC, "CVE-2023-1234", "HIGH", 7.5, "desc")
        cves = database.get_cves_by_mac(self.MAC)
        assert len(cves) == 1
        assert cves[0]["cve_id"] == "CVE-2023-1234"
        assert cves[0]["cvss_score"] == 7.5

    def test_duplicate_cve_ignored(self, tmp_db):
        database.insert_cve(self.MAC, "CVE-2023-1234", "HIGH", 7.5, "desc")
        database.insert_cve(self.MAC, "CVE-2023-1234", "HIGH", 7.5, "desc")
        assert len(database.get_cves_by_mac(self.MAC)) == 1

    def test_same_cve_different_mac_allowed(self, tmp_db):
        database.insert_cve("AA:AA:AA:AA:AA:AA", "CVE-2023-1234", "HIGH", 7.5, "d")
        database.insert_cve("BB:BB:BB:BB:BB:BB", "CVE-2023-1234", "HIGH", 7.5, "d")
        assert len(database.get_cves_by_mac("AA:AA:AA:AA:AA:AA")) == 1
        assert len(database.get_cves_by_mac("BB:BB:BB:BB:BB:BB")) == 1

    def test_ordered_by_cvss_desc(self, tmp_db):
        database.insert_cve(self.MAC, "CVE-2023-0001", "HIGH", 7.5, "d")
        database.insert_cve(self.MAC, "CVE-2023-0002", "CRITICAL", 9.8, "d")
        cves = database.get_cves_by_mac(self.MAC)
        assert cves[0]["cvss_score"] == 9.8
        assert cves[1]["cvss_score"] == 7.5

    def test_empty_for_unknown_mac(self, tmp_db):
        assert database.get_cves_by_mac("00:00:00:00:00:00") == []


# ── Zigbee devices ────────────────────────────────────────────────────────────

class TestZigbeeDevices:
    def test_upsert_inserts_new(self, tmp_db):
        database.upsert_zigbee_device("0x1234", "sensor1")
        devs = database.get_zigbee_devices()
        assert len(devs) == 1
        assert devs[0]["ieee"] == "0x1234"
        assert devs[0]["friendly_name"] == "sensor1"

    def test_upsert_updates_friendly_name(self, tmp_db):
        database.upsert_zigbee_device("0x1234", "old_name")
        database.upsert_zigbee_device("0x1234", "new_name")
        devs = database.get_zigbee_devices()
        assert len(devs) == 1
        assert devs[0]["friendly_name"] == "new_name"

    def test_trusted_max_logic_cannot_downgrade(self, tmp_db):
        database.upsert_zigbee_device("0x1234", trusted=1)
        database.upsert_zigbee_device("0x1234", trusted=0)
        assert database.get_zigbee_devices()[0]["trusted"] == 1

    def test_trusted_can_be_upgraded(self, tmp_db):
        database.upsert_zigbee_device("0x1234", trusted=0)
        database.upsert_zigbee_device("0x1234", trusted=1)
        assert database.get_zigbee_devices()[0]["trusted"] == 1

    def test_update_lqi_history(self, tmp_db):
        database.upsert_zigbee_device("0x1234")
        database.update_zigbee_lqi("0x1234", "[100, 120, 130]")
        assert database.get_zigbee_devices()[0]["lqi_history"] == "[100, 120, 130]"

    def test_empty_on_fresh_db(self, tmp_db):
        assert database.get_zigbee_devices() == []
