"""Tests for socks_proxy.__main__ — loopback check."""

from socks_proxy.__main__ import _is_loopback


class TestIsLoopback:
    """Tests for _is_loopback()."""

    def test_ipv4_loopback(self):
        assert _is_loopback("127.0.0.1") is True

    def test_localhost(self):
        assert _is_loopback("localhost") is True

    def test_ipv6_loopback(self):
        assert _is_loopback("::1") is True

    def test_external_ip(self):
        assert _is_loopback("192.168.1.1") is False

    def test_all_interfaces(self):
        assert _is_loopback("0.0.0.0") is False

    def test_empty_string(self):
        assert _is_loopback("") is False


import subprocess
import sys


class TestSubcommands:
    def test_serve_subcommand_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "serve", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "relay" in result.stdout.lower()

    def test_plugin_subcommand_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "plugin", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "install" in result.stdout.lower()

    def test_bare_invocation_shows_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "serve" in result.stdout.lower()
        assert "plugin" in result.stdout.lower()

    def test_version_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "--version"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

    def test_plugin_list_subcommand_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "plugin", "list", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

    def test_plugin_install_subcommand_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "plugin", "install", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "repo_url" in result.stdout.lower()
        assert "plugin_name" in result.stdout.lower()

    def test_backward_compat_bare_invocation_with_relay_arg(self):
        """Verify that old-style invocations still work (backward compat)."""
        # This simulates: netbridge-socks --relay wss://... --port 1080
        # It should default to serve subcommand
        result = subprocess.run(
            [sys.executable, "-m", "socks_proxy", "--relay", "test.example.com", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        # Should show serve help (with all the serve options)
        assert "relay" in result.stdout.lower()
        assert "socks5" in result.stdout.lower()
