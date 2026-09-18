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

    def test_status_update_goes_through_ui_thread(self):
        """Icon, tooltip and menu must be refreshed via _on_ui_thread.

        Touching the status item directly from the proxy threads trips an
        AppKit main-thread assertion on macOS and kills the process.
        """
        tray = TrayIcon()
        tray._icon = MagicMock()
        with patch("socks_proxy.tray._on_ui_thread") as on_ui:
            tray.set_status(Status.CONNECTED)
            on_ui.assert_called_once()
            tray._icon.update_menu.assert_not_called()
            # The deferred callable does the actual widget work
            on_ui.call_args[0][0]()
        tray._icon.update_menu.assert_called_once()
        assert tray._icon.icon is tray._icon_cache[Status.CONNECTED]
        assert tray._icon.title == STATUS_TOOLTIPS[Status.CONNECTED]

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


class TestNoAgentStatus:
    """Relay reachable but VDI agent missing must be visually distinct."""

    def test_has_its_own_colour(self):
        colours = {s: STATUS_COLORS[s] for s in Status}
        assert len(set(colours.values())) == len(colours)

    def test_has_its_own_label(self):
        from socks_proxy.tray import STATUS_LABELS
        assert STATUS_LABELS[Status.NO_AGENT] != STATUS_LABELS[Status.CONNECTED]

    def test_tooltip_explains_the_failure(self):
        tip = STATUS_TOOLTIPS[Status.NO_AGENT].lower()
        assert "vdi" in tip and "relay" in tip

    def test_icon_is_distinguishable_without_colour(self):
        """Hollow ring so the state reads in monochrome trays too."""
        from socks_proxy.tray import STATUS_HOLLOW
        filled = create_icon_image("#9B59B6", size=32, hollow=False)
        ring = create_icon_image("#9B59B6", size=32, hollow=True)
        assert Status.NO_AGENT in STATUS_HOLLOW
        assert filled.tobytes() != ring.tobytes()
        # Centre pixel is transparent for a ring, opaque for a filled dot
        assert ring.getpixel((16, 16))[3] == 0
        assert filled.getpixel((16, 16))[3] > 0

    def test_notifies_when_agent_goes_away(self):
        tray = TrayIcon(show_notifications=True)
        tray._icon = MagicMock()
        tray.set_status(Status.CONNECTED)
        tray._icon.notify.reset_mock()

        tray.set_status(Status.NO_AGENT)

        tray._icon.notify.assert_called_once()
        message = tray._icon.notify.call_args[0][0].lower()
        assert "agent" in message

    def test_notifies_on_recovery(self):
        tray = TrayIcon(show_notifications=True)
        tray._icon = MagicMock()
        tray.set_status(Status.NO_AGENT)
        tray._icon.notify.reset_mock()

        tray.set_status(Status.CONNECTED)

        tray._icon.notify.assert_called_once()
        assert "restored" in tray._icon.notify.call_args[0][1].lower()

    def test_check_connection_menu_item(self):
        called = []
        tray = TrayIcon(on_check_connection=lambda: called.append(True))
        labels = [
            item.text for item in tray._create_menu().items
            if getattr(item, "text", None)
        ]
        assert any("Check Connection" in label for label in labels)

    def test_no_check_connection_item_without_callback(self):
        tray = TrayIcon()
        labels = [
            item.text for item in tray._create_menu().items
            if getattr(item, "text", None)
        ]
        assert not any("Check Connection" in label for label in labels)


class TestMenuRefresh:
    """Dynamic menu labels only re-render when update_menu() is called.

    pystray caches the menu; the icon image updates cross-thread but the
    text does not, so a status change must explicitly ask for a refresh.
    """

    def test_status_change_refreshes_menu(self):
        tray = TrayIcon()
        tray._icon = MagicMock()

        tray.set_status(Status.NO_AGENT)

        tray._icon.update_menu.assert_called_once()

    def test_recovery_refreshes_menu(self):
        tray = TrayIcon()
        tray._icon = MagicMock()
        tray.set_status(Status.NO_AGENT)
        tray._icon.update_menu.reset_mock()

        tray.set_status(Status.CONNECTED)

        tray._icon.update_menu.assert_called_once()

    def test_refresh_failure_does_not_break_status(self):
        """Some backends have no menu support; status must still update."""
        tray = TrayIcon()
        tray._icon = MagicMock()
        tray._icon.update_menu.side_effect = RuntimeError("no menu support")

        tray.set_status(Status.CONNECTED)

        assert tray.status == Status.CONNECTED

    def test_menu_labels_follow_status(self):
        tray = TrayIcon(on_check_connection=lambda: None)
        tray._icon = MagicMock()

        tray.set_status(Status.NO_AGENT)
        down = [
            item.text for item in tray._create_menu().items
            if getattr(item, "text", None)
        ]
        tray.set_status(Status.CONNECTED)
        up = [
            item.text for item in tray._create_menu().items
            if getattr(item, "text", None)
        ]

        assert any("NOT reachable" in label for label in down)
        assert not any("NOT reachable" in label for label in up)


class TestOnUiThread:
    """_on_ui_thread must hand AppKit work to the macOS main run loop."""

    def _fake_appkit(self, is_main):
        import sys as _sys
        from types import SimpleNamespace, ModuleType
        foundation = ModuleType("Foundation")
        foundation.NSThread = SimpleNamespace(isMainThread=lambda: is_main)
        app_helper = ModuleType("PyObjCTools.AppHelper")
        app_helper.callAfter = MagicMock()
        pkg = ModuleType("PyObjCTools")
        pkg.AppHelper = app_helper
        return {
            "Foundation": foundation,
            "PyObjCTools": pkg,
            "PyObjCTools.AppHelper": app_helper,
        }, app_helper

    def test_runs_inline_off_darwin(self):
        from socks_proxy.tray import _on_ui_thread
        called = []
        with patch("socks_proxy.tray.sys.platform", "linux"):
            _on_ui_thread(lambda: called.append(True))
        assert called == [True]

    def test_defers_to_main_loop_on_darwin_worker_thread(self):
        import sys as _sys
        from socks_proxy.tray import _on_ui_thread
        modules, app_helper = self._fake_appkit(is_main=False)
        called = []
        with patch.dict(_sys.modules, modules), \
                patch("socks_proxy.tray.sys.platform", "darwin"):
            _on_ui_thread(lambda: called.append(True))
        assert called == []
        app_helper.callAfter.assert_called_once()

    def test_runs_inline_on_darwin_main_thread(self):
        import sys as _sys
        from socks_proxy.tray import _on_ui_thread
        modules, app_helper = self._fake_appkit(is_main=True)
        called = []
        with patch.dict(_sys.modules, modules), \
                patch("socks_proxy.tray.sys.platform", "darwin"):
            _on_ui_thread(lambda: called.append(True))
        assert called == [True]
        app_helper.callAfter.assert_not_called()
