"""Tests for socks_proxy_win.installer."""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

from socks_proxy_win.config import APP_NAME, Config
from socks_proxy_win.installer import (
    Installer,
    get_exe_path,
    get_installed_exe_path,
    get_version_file_path,
)


class TestPathHelpers:
    """Tests for installer path helpers."""

    def test_get_installed_exe_path(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert get_installed_exe_path() == Path("/fake") / APP_NAME / "netbridge-socks.exe"

    def test_get_version_file_path(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert get_version_file_path() == Path("/fake") / APP_NAME / "version.json"

    def test_get_exe_path_not_frozen(self):
        path = get_exe_path()
        assert isinstance(path, Path)

    def test_get_exe_path_frozen(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", "/fake/netbridge-socks.exe")
        assert get_exe_path() == Path("/fake/netbridge-socks.exe")

    def test_installer_get_installed_exe_path_matches_module(self, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", "/fake")
        assert Installer.get_installed_exe_path() == get_installed_exe_path()


class TestVersionFile:
    """Tests for version file read/write."""

    def test_save_and_get_installed_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir()

        Installer.save_installed_version("1.2.3")
        assert Installer.get_installed_version() == "1.2.3"

    def test_get_installed_version_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert Installer.get_installed_version() is None

    def test_get_installed_version_corrupt_json(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir()
        (app_dir / "version.json").write_text("not json")
        assert Installer.get_installed_version() is None

    def test_get_installed_version_missing_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir()
        (app_dir / "version.json").write_text(json.dumps({"other": "data"}))
        assert Installer.get_installed_version() is None


class TestIsInstalled:
    """Tests for Installer.is_installed()."""

    def test_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert Installer.is_installed() is False

    def test_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        exe = tmp_path / APP_NAME / "netbridge-socks.exe"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"fake exe")
        assert Installer.is_installed() is True


class TestIsRunningInstalled:
    """Tests for Installer.is_running_installed()."""

    def test_not_running_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert Installer.is_running_installed() is False

    def test_running_installed(self, tmp_path, monkeypatch):
        installed_path = tmp_path / APP_NAME / "netbridge-socks.exe"
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        with patch("socks_proxy_win.installer.get_exe_path", return_value=installed_path):
            assert Installer.is_running_installed() is True


class TestNeedsUpdate:
    """Tests for Installer.needs_update()."""

    def test_needs_update_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert Installer.needs_update() is True

    def test_needs_update_no_version_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        exe = tmp_path / APP_NAME / "netbridge-socks.exe"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"fake")
        assert Installer.needs_update() is True

    def test_needs_update_older_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir(parents=True)
        (app_dir / "netbridge-socks.exe").write_bytes(b"fake")
        Installer.save_installed_version("0.0.1")
        with patch("socks_proxy_win.installer.APP_VERSION", "1.0.0"):
            assert Installer.needs_update() is True

    def test_no_update_same_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir(parents=True)
        (app_dir / "netbridge-socks.exe").write_bytes(b"fake")
        Installer.save_installed_version("2.0.0")
        with patch("socks_proxy_win.installer.APP_VERSION", "2.0.0"):
            assert Installer.needs_update() is False

    def test_no_update_newer_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir(parents=True)
        (app_dir / "netbridge-socks.exe").write_bytes(b"fake")
        Installer.save_installed_version("3.0.0")
        with patch("socks_proxy_win.installer.APP_VERSION", "2.0.0"):
            assert Installer.needs_update() is False


class TestCreateConfig:
    """Tests for Installer.create_config()."""

    def test_creates_config_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir(parents=True)

        Installer.create_config("my-relay.example.com")
        config = Config.load(path=app_dir / "config.json")
        assert config.relay_url == "my-relay.example.com"

    def test_does_not_overwrite_existing_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        app_dir = tmp_path / APP_NAME
        app_dir.mkdir(parents=True)

        # Pre-create config with different URL
        existing = Config(relay_url="existing-relay.example.com")
        existing.save(path=app_dir / "config.json")

        Installer.create_config("new-relay.example.com")
        config = Config.load(path=app_dir / "config.json")
        assert config.relay_url == "existing-relay.example.com"


class TestScheduleDelete:
    """Tests for Installer._schedule_delete()."""

    def test_creates_batch_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEMP", str(tmp_path))
        target = tmp_path / "to_delete"
        target.mkdir()

        import subprocess as _sp
        # CREATE_NO_WINDOW and DETACHED_PROCESS are Windows-only constants
        if not hasattr(_sp, "CREATE_NO_WINDOW"):
            monkeypatch.setattr(_sp, "CREATE_NO_WINDOW", 0x08000000, raising=False)
        if not hasattr(_sp, "DETACHED_PROCESS"):
            monkeypatch.setattr(_sp, "DETACHED_PROCESS", 0x00000008, raising=False)

        with patch("subprocess.Popen"):
            Installer._schedule_delete(target)

        batch = tmp_path / "netbridge_socks_uninstall.bat"
        assert batch.exists()
        content = batch.read_text()
        assert str(target) in content
        assert "rmdir" in content
