from unittest.mock import MagicMock, patch

import pytest
import alert_engine
import database


@pytest.fixture(autouse=True)
def reset_event_loop():
    original = alert_engine._event_loop
    yield
    alert_engine._event_loop = original


class TestCreateAlert:
    def test_new_alert_returns_true(self, tmp_db):
        with patch("ha_client.send_persistent_notification"):
            assert alert_engine.create_alert("HIGH", "CAT", "Title", "detail") is True

    def test_duplicate_returns_false(self, tmp_db):
        with patch("ha_client.send_persistent_notification"):
            alert_engine.create_alert("HIGH", "CAT", "Title", "detail")
            assert alert_engine.create_alert("HIGH", "CAT", "Title", "detail") is False

    def test_notify_called_once_for_new_alert(self, tmp_db):
        with patch("ha_client.send_persistent_notification") as mock_notify:
            alert_engine.create_alert("HIGH", "CAT", "Title", "detail", "rec")
        mock_notify.assert_called_once()

    def test_notify_not_called_for_duplicate(self, tmp_db):
        with patch("ha_client.send_persistent_notification") as mock_notify:
            alert_engine.create_alert("HIGH", "CAT", "Title", "detail")
            alert_engine.create_alert("HIGH", "CAT", "Title", "detail")
        assert mock_notify.call_count == 1

    def test_notify_message_includes_recommendation(self, tmp_db):
        with patch("ha_client.send_persistent_notification") as mock_notify:
            alert_engine.create_alert("HIGH", "C", "T", "detail", "do this")
        args = mock_notify.call_args[0]
        assert "do this" in args[1]

    def test_notify_message_without_recommendation(self, tmp_db):
        with patch("ha_client.send_persistent_notification") as mock_notify:
            alert_engine.create_alert("HIGH", "C", "T", "just the detail")
        args = mock_notify.call_args[0]
        assert args[1] == "just the detail"

    def test_broadcast_skipped_when_no_event_loop(self, tmp_db):
        alert_engine._event_loop = None
        with patch("ha_client.send_persistent_notification"):
            result = alert_engine.create_alert("HIGH", "CAT", "Title", "d")
        assert result is True

    def test_set_event_loop_stores_loop(self):
        loop = MagicMock()
        alert_engine.set_event_loop(loop)
        assert alert_engine._event_loop is loop

    def test_alert_persisted_in_database(self, tmp_db):
        with patch("ha_client.send_persistent_notification"):
            alert_engine.create_alert("CRITICAL", "NET", "Intruder", "detail")
        alerts = database.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "CRITICAL"
