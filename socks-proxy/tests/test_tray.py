"""Tests for socks_proxy.tray — Status, icon creation, TrayIcon callbacks."""

import pytest
from unittest.mock import MagicMock, patch

try:
    from socks_proxy.tray import (
        Status, STATUS_COLORS, STATUS_TOOLTIPS,
        create_icon_image, TrayIcon, APP_NAME,
    )
    _TRAY_AVAILABLE = True
except (ImportError, ValueError):
    _TRAY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _TRAY_AVAILABLE, reason="pystray/GTK not available")


class TestStatus:
    def test_all_statuses_have_colors(self):
        for s in Status:
            assert s in STATUS_COLORS

    def test_all_statuses_have_tooltips(self):
        for s in Status:
            assert s in STATUS_TOOLTIPS
            assert APP_NAME in STATUS_TOOLTIPS[s]


class TestCreateIconImage:
    def test_creates_rgba_image(self):
        img = create_icon_image("#FF0000", size=32)
        assert img.mode == "RGBA"
        assert img.size == (32, 32)

    def test_default_size(self):
        img = create_icon_image("#00FF00")
        assert img.size == (64, 64)


class TestTrayIcon:
    def test_initial_status(self):
        tray = TrayIcon()
        assert tray.status == Status.DISCONNECTED

    def test_set_status_without_icon(self):
        tray = TrayIcon()
        tray.set_status(Status.CONNECTED)
        assert tray.status == Status.CONNECTED

    def test_notifications_gated(self):
        tray = TrayIcon(show_notifications=False)
        tray._icon = MagicMock()
        tray.set_status(Status.CONNECTED)
        tray._icon.notify.assert_not_called()

    def test_notifications_enabled(self):
        tray = TrayIcon(show_notifications=True)
        tray._icon = MagicMock()
        tray.set_status(Status.CONNECTED)
        tray._icon.notify.assert_called_once()

    def test_reconnect_callback_stored(self):
        cb = MagicMock()
        tray = TrayIcon(on_reconnect=cb)
        assert tray._on_reconnect is cb

    def test_change_relay_callback_stored(self):
        cb = MagicMock()
        tray = TrayIcon(on_change_relay=cb)
        assert tray._on_change_relay is cb

    @patch("socks_proxy.tray.pystray")
    def test_stop(self, mock_pystray):
        tray = TrayIcon()
        tray._icon = MagicMock()
        tray.stop()
        tray._icon.stop.assert_called_once()
