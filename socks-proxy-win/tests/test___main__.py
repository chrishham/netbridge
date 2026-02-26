"""Tests for socks_proxy_win.__main__ — CLI argument parsing."""

import argparse

import pytest

from socks_proxy_win.config import APP_NAME, APP_VERSION


def _parse(args: list[str]) -> argparse.Namespace:
    """Build the same parser as __main__.main() and parse args."""
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} - Windows tray for SOCKS5 & HTTP proxy",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--uninstall", action="store_true")
    mode_group.add_argument("--no-install", action="store_true")
    mode_group.add_argument("--import-check", action="store_true")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} v{APP_VERSION}")
    return parser.parse_args(args)


class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_no_args_defaults(self):
        args = _parse([])
        assert args.uninstall is False
        assert args.no_install is False
        assert args.import_check is False

    def test_uninstall_flag(self):
        args = _parse(["--uninstall"])
        assert args.uninstall is True
        assert args.no_install is False
        assert args.import_check is False

    def test_no_install_flag(self):
        args = _parse(["--no-install"])
        assert args.no_install is True
        assert args.uninstall is False

    def test_import_check_flag(self):
        args = _parse(["--import-check"])
        assert args.import_check is True
        assert args.uninstall is False

    def test_mutually_exclusive_uninstall_no_install(self):
        with pytest.raises(SystemExit):
            _parse(["--uninstall", "--no-install"])

    def test_mutually_exclusive_uninstall_import_check(self):
        with pytest.raises(SystemExit):
            _parse(["--uninstall", "--import-check"])

    def test_mutually_exclusive_no_install_import_check(self):
        with pytest.raises(SystemExit):
            _parse(["--no-install", "--import-check"])

    def test_version_flag_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            _parse(["--version"])
        assert exc_info.value.code == 0
