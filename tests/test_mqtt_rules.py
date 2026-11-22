import time
from collections import defaultdict
from unittest.mock import patch, MagicMock

import pytest
import mqtt.rules as rules



class TestBrokerAuth:
    def test_creates_critical_mqtt_alert(self, alert_calls):
        rules.check_broker_auth()
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "CRITICAL"
        assert alert_calls[0]["category"] == "MQTT"



class TestBrokerTLS:
    def _make_socket(self, connect_result):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = connect_result
        return mock_sock

    def test_no_alert_when_tls_port_open(self, alert_calls):
        with patch("socket.socket", return_value=self._make_socket(0)):
            rules.check_broker_tls("192.168.1.1")
        assert len(alert_calls) == 0

    def test_high_alert_when_tls_port_closed(self, alert_calls):
        with patch("socket.socket", return_value=self._make_socket(111)):
            rules.check_broker_tls("192.168.1.1")
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "HIGH"
        assert alert_calls[0]["category"] == "MQTT"



class TestPermitJoin:
    def test_alert_when_open_without_timeout(self, alert_calls):
        rules.check_permit_join({"permit_join": True, "permit_join_timeout": None})
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "HIGH"
        assert alert_calls[0]["category"] == "ZIGBEE"

    def test_no_alert_when_timeout_set(self, alert_calls):
        rules.check_permit_join({"permit_join": True, "permit_join_timeout": 254})
        assert len(alert_calls) == 0

    def test_no_alert_when_permit_join_false(self, alert_calls):
        rules.check_permit_join({"permit_join": False, "permit_join_timeout": None})
        assert len(alert_calls) == 0

    def test_no_alert_when_key_absent(self, alert_calls):
        rules.check_permit_join({})
        assert len(alert_calls) == 0



class TestIsNetworkKeyExposed:
    def test_none_is_not_exposed(self):
        assert rules._is_network_key_exposed(None) is False

    def test_empty_string_is_not_exposed(self):
        assert rules._is_network_key_exposed("") is False

    def test_hidden_uppercase_is_not_exposed(self):
        assert rules._is_network_key_exposed("HIDDEN") is False

    def test_hidden_lowercase_is_not_exposed(self):
        assert rules._is_network_key_exposed("hidden") is False

    def test_generate_is_not_exposed(self):
        assert rules._is_network_key_exposed("GENERATE") is False

    def test_star_mask_is_not_exposed(self):
        assert rules._is_network_key_exposed("*" * 16) is False

    def test_real_string_key_is_exposed(self):
        assert rules._is_network_key_exposed("some-real-aes-key-value") is True

    def test_byte_list_is_exposed(self):
        assert rules._is_network_key_exposed([1, 2, 3, 4, 5, 6, 7, 8]) is True

    def test_integer_is_not_exposed(self):
        assert rules._is_network_key_exposed(12345) is False



class TestNetworkKey:
    def test_bridge_config_real_string_creates_critical_alert(self, alert_calls):
        rules.check_network_key({"network_key": "real-key-value"}, "bridge/config")
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "CRITICAL"
        assert alert_calls[0]["category"] == "ZIGBEE"

    def test_bridge_config_generate_no_alert(self, alert_calls):
        rules.check_network_key({"network_key": "GENERATE"}, "bridge/config")
        assert len(alert_calls) == 0

    def test_bridge_config_no_key_no_alert(self, alert_calls):
        rules.check_network_key({}, "bridge/config")
        assert len(alert_calls) == 0

    def test_bridge_info_array_key_creates_alert(self, alert_calls):
        payload = {"config": {"advanced": {"network_key": [1, 2, 3, 4, 5, 6, 7, 8]}}}
        rules.check_network_key(payload, "bridge/info")
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "CRITICAL"

    def test_bridge_info_hidden_no_alert(self, alert_calls):
        payload = {"config": {"advanced": {"network_key": "HIDDEN"}}}
        rules.check_network_key(payload, "bridge/info")
        assert len(alert_calls) == 0

    def test_bridge_info_missing_advanced_no_alert(self, alert_calls):
        rules.check_network_key({"config": {}}, "bridge/info")
        assert len(alert_calls) == 0

    def test_bridge_info_missing_config_no_alert(self, alert_calls):
        rules.check_network_key({}, "bridge/info")
        assert len(alert_calls) == 0

    def test_non_dict_payload_does_not_raise(self, alert_calls):
        rules.check_network_key("not a dict", "bridge/config")
        assert len(alert_calls) == 0

    def test_non_dict_payload_bridge_info_does_not_raise(self, alert_calls):
        rules.check_network_key(None, "bridge/info")
        assert len(alert_calls) == 0



class TestDeviceJoined:
    def test_unknown_device_creates_high_alert(self, alert_calls, tmp_db):
        known = set()
        rules.check_device_joined(
            {"type": "device_joined", "data": {"ieee_address": "0xABCD", "friendly_name": "sensor1"}},
            known,
        )
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "HIGH"
        assert alert_calls[0]["category"] == "ZIGBEE"

    def test_unknown_device_added_to_known_set(self, alert_calls, tmp_db):
        known = set()
        rules.check_device_joined(
            {"type": "device_joined", "data": {"ieee_address": "0xABCD"}},
            known,
        )
        assert "0xABCD" in known

    def test_known_device_no_alert(self, alert_calls, tmp_db):
        known = {"0xABCD"}
        rules.check_device_joined(
            {"type": "device_joined", "data": {"ieee_address": "0xABCD"}},
            known,
        )
        assert len(alert_calls) == 0

    def test_wrong_event_type_no_alert(self, alert_calls, tmp_db):
        rules.check_device_joined(
            {"type": "device_leave", "data": {"ieee_address": "0xABCD"}},
            set(),
        )
        assert len(alert_calls) == 0

    def test_missing_ieee_no_alert(self, alert_calls, tmp_db):
        rules.check_device_joined({"type": "device_joined", "data": {}}, set())
        assert len(alert_calls) == 0

    def test_friendly_to_ieee_mapping_populated(self, alert_calls, tmp_db):
        friendly_to_ieee = {}
        rules.check_device_joined(
            {"type": "device_joined", "data": {"ieee_address": "0xABCD", "friendly_name": "my_sensor"}},
            set(),
            friendly_to_ieee,
        )
        assert friendly_to_ieee.get("my_sensor") == "0xABCD"



class TestFrontendAuth:
    def test_no_auth_token_creates_medium_alert(self, alert_calls):
        rules.check_frontend_auth({"config": {"frontend": {"auth_token": None}}})
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "MEDIUM"

    def test_empty_auth_token_creates_alert(self, alert_calls):
        rules.check_frontend_auth({"config": {"frontend": {"auth_token": ""}}})
        assert len(alert_calls) == 1

    def test_token_set_no_alert(self, alert_calls):
        rules.check_frontend_auth({"config": {"frontend": {"auth_token": "secret123"}}})
        assert len(alert_calls) == 0

    def test_no_frontend_key_no_alert(self, alert_calls):
        rules.check_frontend_auth({"config": {}})
        assert len(alert_calls) == 0

    def test_non_dict_config_no_alert(self, alert_calls):
        rules.check_frontend_auth({"config": "invalid"})
        assert len(alert_calls) == 0

    def test_non_dict_frontend_no_alert(self, alert_calls):
        rules.check_frontend_auth({"config": {"frontend": "invalid"}})
        assert len(alert_calls) == 0



class TestLQI:
    def test_fewer_than_window_readings_no_alert(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(9):
            rules.check_lqi("dev1", {"linkquality": 5}, hist)
        assert len(alert_calls) == 0

    def test_alert_when_avg_below_threshold(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(10):
            rules.check_lqi("dev1", {"linkquality": 10}, hist)
        assert len(alert_calls) == 1
        assert alert_calls[0]["severity"] == "MEDIUM"
        assert alert_calls[0]["category"] == "ZIGBEE"

    def test_no_alert_when_avg_above_threshold(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(10):
            rules.check_lqi("dev1", {"linkquality": 50}, hist)
        assert len(alert_calls) == 0

    def test_exactly_at_threshold_no_alert(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(10):
            rules.check_lqi("dev1", {"linkquality": 20}, hist)
        assert len(alert_calls) == 0

    def test_window_truncated_to_10_readings(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(15):
            rules.check_lqi("dev1", {"linkquality": 100}, hist)
        assert len(hist["dev1"]) == 10

    def test_no_linkquality_key_ignored(self, alert_calls):
        hist = defaultdict(list)
        rules.check_lqi("dev1", {"temperature": 22}, hist)
        assert len(hist["dev1"]) == 0
        assert len(alert_calls) == 0

    def test_non_dict_payload_ignored(self, alert_calls):
        hist = defaultdict(list)
        rules.check_lqi("dev1", "not a dict", hist)
        assert len(alert_calls) == 0

    def test_different_devices_tracked_separately(self, alert_calls):
        hist = defaultdict(list)
        for _ in range(10):
            rules.check_lqi("dev1", {"linkquality": 5}, hist)
        for _ in range(9):
            rules.check_lqi("dev2", {"linkquality": 5}, hist)
        # dev1 triggered an alert, dev2 has only 9 readings
        assert len(alert_calls) == 1



class TestFlood:
    def test_z2m_topic_always_exempt(self, alert_calls):
        flood_log = defaultdict(list)
        for _ in range(300):
            rules.check_flood("zigbee2mqtt/device/state", flood_log)
        assert len(alert_calls) == 0

    def test_no_alert_at_threshold_exactly(self, alert_calls):
        flood_log = defaultdict(list)
        for _ in range(200):
            rules.check_flood("home/sensor", flood_log)
        assert len(alert_calls) == 0

    def test_alert_above_threshold(self, alert_calls):
        flood_log = defaultdict(list)
        for _ in range(201):
            rules.check_flood("home/sensor", flood_log)
        assert len(alert_calls) >= 1
        assert alert_calls[0]["severity"] == "HIGH"
        assert alert_calls[0]["category"] == "MQTT"

    def test_old_timestamps_pruned(self, alert_calls):
        flood_log = defaultdict(list)
        old_time = time.time() - 120  # outside the 60s window
        flood_log["home/sensor"] = [old_time] * 200
        rules.check_flood("home/sensor", flood_log)
        assert len(alert_calls) == 0

    def test_independent_topics_tracked_separately(self, alert_calls):
        flood_log = defaultdict(list)
        for _ in range(201):
            rules.check_flood("topic/a", flood_log)
        # topic/b has zero messages, should have no alert
        rules.check_flood("topic/b", flood_log)
        assert all(c["title"].find("topic/a") != -1 for c in alert_calls)
