from unittest.mock import MagicMock, patch, call

import pytest
import paramiko
from scanner.mirai_check import check_mirai_ssh, MIRAI_CREDS


class TestCheckMiraiSSH:
    def _make_client(self):
        client = MagicMock(spec=paramiko.SSHClient)
        return client

    def test_returns_true_when_credentials_accepted(self):
        client = self._make_client()
        client.connect.return_value = None

        with patch("paramiko.SSHClient", return_value=client):
            success, user, password = check_mirai_ssh("192.168.1.10")

        assert success is True
        assert user == MIRAI_CREDS[0][0]
        assert password == MIRAI_CREDS[0][1]

    def test_returns_false_when_all_credentials_rejected(self):
        client = self._make_client()
        client.connect.side_effect = paramiko.AuthenticationException()

        with patch("paramiko.SSHClient", return_value=client):
            success, user, password = check_mirai_ssh("192.168.1.10")

        assert success is False
        assert user == ""
        assert password == ""

    def test_all_credentials_tried_on_auth_failure(self):
        client = self._make_client()
        client.connect.side_effect = paramiko.AuthenticationException()

        with patch("paramiko.SSHClient", return_value=client):
            check_mirai_ssh("192.168.1.10")

        assert client.connect.call_count == len(MIRAI_CREDS)

    def test_connection_error_breaks_loop(self):
        client = self._make_client()
        client.connect.side_effect = Exception("Connection refused")

        with patch("paramiko.SSHClient", return_value=client):
            success, user, password = check_mirai_ssh("192.168.1.10")

        assert success is False
        # Only one attempt made (breaks on first non-auth exception)
        assert client.connect.call_count == 1

    def test_client_always_closed(self):
        client = self._make_client()
        client.connect.side_effect = paramiko.AuthenticationException()

        with patch("paramiko.SSHClient", return_value=client):
            check_mirai_ssh("192.168.1.10")

        assert client.close.call_count == len(MIRAI_CREDS)

    def test_client_closed_on_success(self):
        client = self._make_client()
        client.connect.return_value = None

        with patch("paramiko.SSHClient", return_value=client):
            check_mirai_ssh("192.168.1.10")

        client.close.assert_called()

    def test_success_on_specific_credential(self):
        target_user, target_pass = "root", "vizxv"
        target_index = MIRAI_CREDS.index((target_user, target_pass))

        client = self._make_client()
        def connect_side_effect(*args, **kwargs):
            if kwargs["username"] == target_user and kwargs["password"] == target_pass:
                return None
            raise paramiko.AuthenticationException()

        client.connect.side_effect = connect_side_effect

        with patch("paramiko.SSHClient", return_value=client):
            success, user, password = check_mirai_ssh("192.168.1.10")

        assert success is True
        assert user == target_user
        assert password == target_pass
        assert client.connect.call_count == target_index + 1

    def test_known_credentials_list_has_expected_entries(self):
        assert ("admin", "admin") in MIRAI_CREDS
        assert ("root", "root") in MIRAI_CREDS
        assert ("root", "vizxv") in MIRAI_CREDS
        assert len(MIRAI_CREDS) == 10
