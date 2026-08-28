"""Tests for socks_proxy.dialogs."""

from unittest.mock import patch, MagicMock
import subprocess

from socks_proxy.dialogs import prompt_relay_url, _prompt_zenity, _prompt_kdialog


class TestPromptZenity:
    def test_returns_stripped_output(self):
        proc = MagicMock(returncode=0, stdout="  relay.test.com  \n")
        with patch("socks_proxy.dialogs.subprocess.run", return_value=proc) as mock_run:
            result = _prompt_zenity("Title", "Prompt", "default")
        assert result == "relay.test.com"
        args = mock_run.call_args[0][0]
        assert args[0] == "zenity"

    def test_returns_none_on_cancel(self):
        proc = MagicMock(returncode=1, stdout="")
        with patch("socks_proxy.dialogs.subprocess.run", return_value=proc):
            assert _prompt_zenity("T", "P", "d") is None

    def test_returns_none_on_empty(self):
        proc = MagicMock(returncode=0, stdout="  \n")
        with patch("socks_proxy.dialogs.subprocess.run", return_value=proc):
            assert _prompt_zenity("T", "P", "d") is None

    def test_returns_none_on_not_found(self):
        with patch("socks_proxy.dialogs.subprocess.run",
                   side_effect=FileNotFoundError):
            assert _prompt_zenity("T", "P", "d") is None

    def test_returns_none_on_timeout(self):
        with patch("socks_proxy.dialogs.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("zenity", 120)):
            assert _prompt_zenity("T", "P", "d") is None


class TestPromptKdialog:
    def test_returns_stripped_output(self):
        proc = MagicMock(returncode=0, stdout="relay.test.com\n")
        with patch("socks_proxy.dialogs.subprocess.run", return_value=proc):
            assert _prompt_kdialog("T", "P", "d") == "relay.test.com"

    def test_returns_none_on_cancel(self):
        proc = MagicMock(returncode=1, stdout="")
        with patch("socks_proxy.dialogs.subprocess.run", return_value=proc):
            assert _prompt_kdialog("T", "P", "d") is None


class TestPromptRelayUrl:
    @patch("socks_proxy.dialogs.sys")
    @patch("socks_proxy.dialogs.subprocess.run")
    def test_macos_uses_osascript(self, mock_run, mock_sys):
        mock_sys.platform = "darwin"
        mock_run.return_value = MagicMock(returncode=0, stdout="relay.mac.com\n")
        result = prompt_relay_url("default.com")
        assert result == "relay.mac.com"
        args = mock_run.call_args[0][0]
        assert args[0] == "osascript"

    @patch("socks_proxy.dialogs.sys")
    @patch("socks_proxy.dialogs.shutil.which")
    @patch("socks_proxy.dialogs.subprocess.run")
    def test_linux_prefers_zenity(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        mock_which.side_effect = lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None
        mock_run.return_value = MagicMock(returncode=0, stdout="relay.linux.com\n")
        result = prompt_relay_url("default.com")
        assert result == "relay.linux.com"

    @patch("socks_proxy.dialogs.sys")
    @patch("socks_proxy.dialogs.shutil.which")
    @patch("socks_proxy.dialogs.subprocess.run")
    def test_linux_falls_back_to_kdialog(self, mock_run, mock_which, mock_sys):
        mock_sys.platform = "linux"
        mock_which.side_effect = lambda cmd: "/usr/bin/kdialog" if cmd == "kdialog" else None
        mock_run.return_value = MagicMock(returncode=0, stdout="relay.kde.com\n")
        result = prompt_relay_url("default.com")
        assert result == "relay.kde.com"

    @patch("socks_proxy.dialogs.sys")
    @patch("socks_proxy.dialogs.shutil.which", return_value=None)
    def test_linux_no_dialog_tool(self, mock_which, mock_sys):
        mock_sys.platform = "linux"
        assert prompt_relay_url("default.com") is None
