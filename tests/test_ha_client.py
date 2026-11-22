from unittest.mock import MagicMock, patch

import pytest
import ha_client


class TestSendPersistentNotification:
    def test_dev_mode_makes_no_http_call(self, monkeypatch):
        monkeypatch.delenv("SUPERVISOR_TOKEN", raising=False)
        with patch("requests.post") as mock_post:
            ha_client.send_persistent_notification("Title", "Message")
        mock_post.assert_not_called()

    def test_prod_mode_calls_requests_post(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "real_token_xyz")
        mock_resp = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            ha_client.send_persistent_notification("Title", "Msg")
        mock_post.assert_called_once()

    def test_prod_mode_sends_bearer_token(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "my_secret_token")
        mock_resp = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            ha_client.send_persistent_notification("T", "M")
        headers = mock_post.call_args[1]["headers"]
        assert "Bearer my_secret_token" in headers["Authorization"]

    def test_prod_mode_posts_correct_json_payload(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "tok")
        mock_resp = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            ha_client.send_persistent_notification("My Title", "My Msg")
        payload = mock_post.call_args[1]["json"]
        assert payload["title"] == "My Title"
        assert payload["message"] == "My Msg"

    def test_prod_mode_connection_error_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "tok")
        with patch("requests.post", side_effect=Exception("connection refused")):
            ha_client.send_persistent_notification("T", "M")

    def test_prod_mode_http_error_status_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "tok")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("403 Forbidden")
        with patch("requests.post", return_value=mock_resp):
            ha_client.send_persistent_notification("T", "M")

    def test_fake_token_in_env_is_dev_mode(self, monkeypatch):
        monkeypatch.setenv("SUPERVISOR_TOKEN", "fake_token_for_dev")
        with patch("requests.post") as mock_post:
            ha_client.send_persistent_notification("T", "M")
        mock_post.assert_not_called()
