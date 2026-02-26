"""Tests for socks_proxy_win.app."""

import logging
from unittest.mock import MagicMock, patch

from socks_proxy_win.app import NetBridgeSocksApp, setup_logging
from socks_proxy_win.config import Config
from socks_proxy_win.tray import Status


class TestSetupLogging:
    """Tests for setup_logging()."""

    def test_sets_log_level(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config(log_level="DEBUG")
        setup_logging(config)
        assert logging.getLogger().level == logging.DEBUG

    def test_sets_info_level(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config(log_level="INFO")
        setup_logging(config)
        assert logging.getLogger().level == logging.INFO

    def test_invalid_level_falls_back_to_info(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config(log_level="INVALID")
        setup_logging(config)
        assert logging.getLogger().level == logging.INFO

    def test_adds_file_handler(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config()
        setup_logging(config)
        root = logging.getLogger()
        assert any("TimedRotatingFileHandler" in type(h).__name__ for h in root.handlers)

    def test_console_handler_when_requested(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config()
        setup_logging(config, console=True)
        root = logging.getLogger()
        assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)

    def test_no_console_handler_by_default(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        config = Config()
        setup_logging(config, console=False)
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers
            if type(h) is logging.StreamHandler
        ]
        assert len(stream_handlers) == 0


class TestNetBridgeSocksApp:
    """Tests for the NetBridgeSocksApp class."""

    def _make_app(self, tmp_path, monkeypatch):
        """Create an app instance with mocked dependencies."""
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app = NetBridgeSocksApp()
        app.tray = MagicMock()
        return app

    def test_initial_status_is_disconnected(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        assert app.status == Status.DISCONNECTED

    def test_set_status_updates_status(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.set_status(Status.CONNECTED)
        assert app.status == Status.CONNECTED

    def test_set_status_updates_tray(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.set_status(Status.CONNECTING)
        app.tray.set_status.assert_called_with(Status.CONNECTING)

    def test_set_status_notifies_on_connected(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.set_status(Status.CONNECTED)
        app.tray.show_notification.assert_called_once_with("Connected", "Connected to relay server")

    def test_set_status_notifies_on_disconnect_from_connected(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app._status = Status.CONNECTED
        app.set_status(Status.DISCONNECTED)
        app.tray.show_notification.assert_called_once_with(
            "Disconnected", "Connection lost, reconnecting..."
        )

    def test_set_status_notifies_on_auth_required(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.set_status(Status.AUTH_REQUIRED)
        app.tray.show_notification.assert_called_once_with(
            "Login Required", "Authentication expired - click to login"
        )

    def test_set_status_no_notification_when_same_status(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app._status = Status.CONNECTED
        app.set_status(Status.CONNECTED)
        app.tray.show_notification.assert_not_called()

    def test_set_status_no_notification_when_notify_false(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.set_status(Status.CONNECTED, notify=False)
        app.tray.show_notification.assert_not_called()

    def test_set_status_no_tray_does_not_crash(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app = NetBridgeSocksApp()
        app.tray = None
        app.set_status(Status.CONNECTED)  # should not raise
        assert app.status == Status.CONNECTED

    def test_request_exit_sets_pending(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.request_exit()
        assert app._pending_exit.is_set()

    def test_request_exit_stops_tray(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.request_exit()
        app.tray.stop.assert_called_once()

    def test_request_exit_sets_async_stop_event(self, tmp_path, monkeypatch):
        import asyncio

        app = self._make_app(tmp_path, monkeypatch)
        loop = MagicMock()
        stop_event = MagicMock()
        app._async_loop = loop
        app._stop_event = stop_event
        app.request_exit()
        loop.call_soon_threadsafe.assert_called_once_with(stop_event.set)

    # --- Change Relay URL ---

    @patch("socks_proxy_win.app.subprocess.Popen")
    def test_request_change_relay_url_saves_and_restarts(self, mock_popen, tmp_path, monkeypatch):
        import subprocess as _subprocess
        if not hasattr(_subprocess, "DETACHED_PROCESS"):
            _subprocess.DETACHED_PROCESS = 0x00000008
        if not hasattr(_subprocess, "CREATE_NO_WINDOW"):
            _subprocess.CREATE_NO_WINDOW = 0x08000000

        app = self._make_app(tmp_path, monkeypatch)
        app.config.relay_url = "old-relay.example.com"
        exe_path = tmp_path / "NetBridgeSocks" / "netbridge-socks.exe"
        exe_path.parent.mkdir(parents=True, exist_ok=True)
        exe_path.touch()

        mock_dialogs = MagicMock()
        mock_dialogs.prompt_relay_url.return_value = "new-relay.example.com"
        mock_installer = MagicMock()
        mock_installer.get_exe_path.return_value = exe_path

        with patch.dict("sys.modules", {"socks_proxy_win.dialogs": mock_dialogs,
                                         "socks_proxy_win.installer": mock_installer}):
            app.request_change_relay_url()

        assert app.config.relay_url == "new-relay.example.com"
        mock_popen.assert_called_once()
        assert app._pending_exit.is_set()
        app.tray.stop.assert_called_once()

    def test_request_change_relay_url_cancelled(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.config.relay_url = "old-relay.example.com"

        mock_dialogs = MagicMock()
        mock_dialogs.prompt_relay_url.return_value = None

        with patch.dict("sys.modules", {"socks_proxy_win.dialogs": mock_dialogs}):
            app.request_change_relay_url()

        assert app.config.relay_url == "old-relay.example.com"
        assert not app._pending_exit.is_set()
        app.tray.stop.assert_not_called()

    def test_request_change_relay_url_unchanged(self, tmp_path, monkeypatch):
        app = self._make_app(tmp_path, monkeypatch)
        app.config.relay_url = "same-relay.example.com"

        mock_dialogs = MagicMock()
        mock_dialogs.prompt_relay_url.return_value = "same-relay.example.com"

        with patch.dict("sys.modules", {"socks_proxy_win.dialogs": mock_dialogs}):
            app.request_change_relay_url()

        assert not app._pending_exit.is_set()
        app.tray.stop.assert_not_called()
