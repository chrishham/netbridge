"""Tests for socks_proxy_win.tray."""

from socks_proxy_win.config import APP_NAME
from socks_proxy_win.tray import (
    STATUS_COLORS,
    STATUS_TOOLTIPS,
    Status,
    create_icon_image,
)


class TestStatus:
    """Tests for the Status enum."""

    def test_all_values(self):
        assert Status.DISCONNECTED.value == "disconnected"
        assert Status.CONNECTING.value == "connecting"
        assert Status.CONNECTED.value == "connected"
        assert Status.AUTH_REQUIRED.value == "auth_required"

    def test_member_count(self):
        assert len(Status) == 4


class TestStatusMappings:
    """Tests for STATUS_COLORS and STATUS_TOOLTIPS."""

    def test_all_statuses_have_colors(self):
        for status in Status:
            assert status in STATUS_COLORS
            assert isinstance(STATUS_COLORS[status], str)
            assert STATUS_COLORS[status].startswith("#")

    def test_all_statuses_have_tooltips(self):
        for status in Status:
            assert status in STATUS_TOOLTIPS
            assert APP_NAME in STATUS_TOOLTIPS[status]

    def test_specific_colors(self):
        assert STATUS_COLORS[Status.CONNECTED] == "#2ECC71"
        assert STATUS_COLORS[Status.DISCONNECTED] == "#E74C3C"
        assert STATUS_COLORS[Status.CONNECTING] == "#F1C40F"
        assert STATUS_COLORS[Status.AUTH_REQUIRED] == "#E67E22"


class TestCreateIconImage:
    """Tests for create_icon_image()."""

    def test_returns_rgba_image(self):
        img = create_icon_image("#FF0000")
        assert img.mode == "RGBA"

    def test_default_size(self):
        img = create_icon_image("#FF0000")
        assert img.size == (64, 64)

    def test_custom_size(self):
        img = create_icon_image("#FF0000", size=32)
        assert img.size == (32, 32)

    def test_transparent_corners(self):
        img = create_icon_image("#FF0000", size=64)
        # Top-left corner should be transparent (outside the circle)
        assert img.getpixel((0, 0))[3] == 0

    def test_center_is_opaque(self):
        img = create_icon_image("#FF0000", size=64)
        # Center should be the fill color (opaque)
        assert img.getpixel((32, 32))[3] == 255

    def test_each_status_produces_distinct_icon(self):
        icons = {}
        for status in Status:
            icons[status] = create_icon_image(STATUS_COLORS[status])
        # All icons should be different (different colors)
        pixel_sets = {s: img.getpixel((32, 32))[:3] for s, img in icons.items()}
        assert len(set(pixel_sets.values())) == len(Status)
