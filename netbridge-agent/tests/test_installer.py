"""Tests for netbridge_agent.installer — install, update, and version management."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netbridge_agent.installer import Installer, get_exe_path


# ---------------------------------------------------------------------------
# get_exe_path
# ---------------------------------------------------------------------------
class TestGetExePath:
    """Tests for get_exe_path()."""

    def test_frozen_mode(self):
        """In PyInstaller frozen mode, returns sys.executable."""
        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", "/opt/netbridge.exe"):
            result = get_exe_path()
            assert result == Path("/opt/netbridge.exe")

    def test_script_mode(self):
        """In script mode, returns resolved sys.argv[0]."""
        with patch("netbridge_agent.installer.getattr", side_effect=lambda o, n, d=None: d):
            # Just verify it returns a Path (actual value depends on test runner)
            result = get_exe_path()
            assert isinstance(result, Path)


# ---------------------------------------------------------------------------
# Installer.get_installed_version
# ---------------------------------------------------------------------------
class TestInstallerGetInstalledVersion:
    """Tests for Installer.get_installed_version()."""

    def test_valid_version_file(self, tmp_path):
        """Reads version from a valid JSON file."""
        version_file = tmp_path / "version.json"
        version_file.write_text(json.dumps({"version": "1.2.3"}))

        with patch("netbridge_agent.installer.get_version_file_path", return_value=version_file):
            assert Installer.get_installed_version() == "1.2.3"

    def test_missing_file(self, tmp_path):
        """Returns None when version file doesn't exist."""
        version_file = tmp_path / "nonexistent.json"

        with patch("netbridge_agent.installer.get_version_file_path", return_value=version_file):
            assert Installer.get_installed_version() is None

    def test_corrupt_json(self, tmp_path):
        """Returns None when JSON is corrupt."""
        version_file = tmp_path / "version.json"
        version_file.write_text("not json {{{")

        with patch("netbridge_agent.installer.get_version_file_path", return_value=version_file):
            assert Installer.get_installed_version() is None


# ---------------------------------------------------------------------------
# Installer.save_installed_version
# ---------------------------------------------------------------------------
class TestInstallerSaveInstalledVersion:
    """Tests for Installer.save_installed_version()."""

    def test_writes_version(self, tmp_path):
        """Writes version to JSON file."""
        version_file = tmp_path / "version.json"

        with patch("netbridge_agent.installer.get_version_file_path", return_value=version_file):
            Installer.save_installed_version("2.0.0")

        data = json.loads(version_file.read_text())
        assert data["version"] == "2.0.0"

    def test_io_error(self, tmp_path):
        """IOError during write is silently handled."""
        version_file = tmp_path / "nonexistent_dir" / "version.json"

        with patch("netbridge_agent.installer.get_version_file_path", return_value=version_file):
            # Should not raise
            Installer.save_installed_version("1.0.0")


# ---------------------------------------------------------------------------
# Installer.needs_update
# ---------------------------------------------------------------------------
class TestInstallerNeedsUpdate:
    """Tests for Installer.needs_update()."""

    def test_not_installed(self):
        """Returns True when not installed."""
        with patch.object(Installer, "is_installed", return_value=False):
            assert Installer.needs_update() is True

    def test_no_version_info(self):
        """Returns True when installed but no version file."""
        with patch.object(Installer, "is_installed", return_value=True), \
             patch.object(Installer, "get_installed_version", return_value=None):
            assert Installer.needs_update() is True

    def test_newer_version(self):
        """Returns True when current version is newer."""
        with patch.object(Installer, "is_installed", return_value=True), \
             patch.object(Installer, "get_installed_version", return_value="1.0.0"), \
             patch("netbridge_agent.installer.APP_VERSION", "2.0.0"):
            assert Installer.needs_update() is True

    def test_same_version(self):
        """Returns False when versions match."""
        with patch.object(Installer, "is_installed", return_value=True), \
             patch.object(Installer, "get_installed_version", return_value="1.0.0"), \
             patch("netbridge_agent.installer.APP_VERSION", "1.0.0"):
            assert Installer.needs_update() is False

    def test_older_version(self):
        """Returns False when current version is older."""
        with patch.object(Installer, "is_installed", return_value=True), \
             patch.object(Installer, "get_installed_version", return_value="3.0.0"), \
             patch("netbridge_agent.installer.APP_VERSION", "2.0.0"):
            assert Installer.needs_update() is False


# ---------------------------------------------------------------------------
# Installer.is_installed
# ---------------------------------------------------------------------------
class TestInstallerIsInstalled:
    """Tests for Installer.is_installed()."""

    def test_exists(self, tmp_path):
        """Returns True when exe exists."""
        exe = tmp_path / "netbridge.exe"
        exe.touch()
        with patch("netbridge_agent.installer.get_installed_exe_path", return_value=exe):
            assert Installer.is_installed() is True

    def test_not_exists(self, tmp_path):
        """Returns False when exe doesn't exist."""
        exe = tmp_path / "netbridge.exe"
        with patch("netbridge_agent.installer.get_installed_exe_path", return_value=exe):
            assert Installer.is_installed() is False


# ---------------------------------------------------------------------------
# Installer.create_config
# ---------------------------------------------------------------------------
class TestInstallerCreateConfig:
    """Tests for Installer.create_config()."""

    def test_creates_when_missing(self, tmp_path):
        """Creates config file when it doesn't exist."""
        config_path = tmp_path / "config.json"

        with patch("netbridge_agent.installer.get_config_path", return_value=config_path), \
             patch("netbridge_agent.installer.Config") as MockConfig:
            mock_instance = MagicMock()
            MockConfig.return_value = mock_instance
            Installer.create_config("wss://relay.example.com")
            MockConfig.assert_called_once_with(relay_url="wss://relay.example.com")
            mock_instance.save.assert_called_once()

    def test_skips_when_exists(self, tmp_path):
        """Does not overwrite existing config."""
        config_path = tmp_path / "config.json"
        config_path.write_text('{"relay_url": "old"}')

        with patch("netbridge_agent.installer.get_config_path", return_value=config_path), \
             patch("netbridge_agent.installer.Config") as MockConfig:
            Installer.create_config("wss://new.example.com")
            MockConfig.assert_not_called()


# ---------------------------------------------------------------------------
# Windows-specific tests
# ---------------------------------------------------------------------------
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only functionality")
class TestWindowsStartup:
    """Windows registry startup tests (skipped on non-Windows)."""

    def test_add_to_startup(self):
        """add_to_startup writes to the registry."""
        assert Installer.add_to_startup() is True

    def test_is_in_startup(self):
        """is_in_startup checks the registry."""
        # Just verify it returns a bool
        result = Installer.is_in_startup()
        assert isinstance(result, bool)

    def test_remove_from_startup(self):
        """remove_from_startup deletes from the registry."""
        result = Installer.remove_from_startup()
        assert isinstance(result, bool)


class TestNonWindowsStartup:
    """Startup methods return False on non-Windows platforms."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_add_to_startup_returns_false(self):
        assert Installer.add_to_startup() is False

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_remove_from_startup_returns_false(self):
        assert Installer.remove_from_startup() is False

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_is_in_startup_returns_false(self):
        assert Installer.is_in_startup() is False


class TestTerminateRunningInstances:
    """Tests for Installer.terminate_running_instances()."""

    @pytest.mark.skipif(sys.platform == "win32", reason="Non-Windows test")
    def test_noop_on_non_windows(self):
        """Does nothing on non-Windows platforms."""
        Installer.terminate_running_instances()  # Should not raise
