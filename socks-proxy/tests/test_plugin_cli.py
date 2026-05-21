"""Tests for socks_proxy.plugin_cli module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from socks_proxy.plugin_cli import (
    cmd_list, cmd_install, cmd_uninstall, cmd_update, cmd_info,
    _curl, _validate_plugin_name,
)


class TestValidatePluginName:
    def test_valid_names(self):
        for name in ["gauth", "my-plugin", "plugin_v2", "test.plugin", "a1"]:
            _validate_plugin_name(name)

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            _validate_plugin_name("../evil")

    def test_rejects_backslash(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            _validate_plugin_name("..\\evil")

    def test_rejects_slash(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            _validate_plugin_name("sub/dir")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            _validate_plugin_name("")

    def test_rejects_dot_start(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            _validate_plugin_name(".hidden")


class TestCurl:
    def test_curl_get(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"status":"ok"}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result) as mock_run:
            result = _curl("GET", "/health")
            assert result == {"status": "ok"}
            cmd = mock_run.call_args[0][0]
            assert "curl" in cmd
            assert "http://netbridge-exec/health" in cmd

    def test_curl_connection_error(self):
        mock_result = MagicMock()
        mock_result.returncode = 7
        mock_result.stderr = b"Failed to connect"
        mock_result.stdout = b""
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(ConnectionError):
                _curl("GET", "/health")

    def test_curl_403_raises_permission_error(self):
        mock_result = MagicMock()
        mock_result.returncode = 22
        mock_result.stderr = b"The requested URL returned error: 403"
        mock_result.stdout = b""
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(PermissionError):
                _curl("POST", "/exec")

    def test_curl_agent_error_raises(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"error": "something broke"}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Agent error"):
                _curl("GET", "/health")

    def test_curl_agent_exec_disabled_raises_permission_error(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(
            {"error": "Remote exec is disabled — enable it from the VDI system tray"}
        ).encode()
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(PermissionError):
                _curl("POST", "/exec")


class TestPluginList:
    def test_list_plugins(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "GCloud auth", "repo_url": ""},
            ]}
            cmd_list(1080)
        out = capsys.readouterr().out
        assert "gauth" in out
        assert "1.0.0" in out

    def test_list_empty(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": []}
            cmd_list(1080)
        out = capsys.readouterr().out
        assert "no plugins" in out.lower()


class TestPluginInfo:
    def test_info_found_with_repo(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "GCloud auth",
                 "repo_url": "https://dev.azure.com/org/project/_git/plugins"},
            ]}
            cmd_info(1080, "gauth")
        out = capsys.readouterr().out
        assert "gauth" in out
        assert "netbridge-gauth" in out
        assert "dev.azure.com" in out

    def test_info_not_found(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": []}
            cmd_info(1080, "nonexistent")
        out = capsys.readouterr().out
        assert "not found" in out.lower()


class TestPluginInstall:
    def test_install_clones_and_pushes(self, tmp_path):
        plugin_dir = tmp_path / "repo" / "test-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "test", "hostname": "netbridge-test",
            "description": "test plugin", "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text("pass")

        exec_resp = {"exit_code": 0, "stdout": "C:\\Users\\user\\AppData\\Local"}
        ok_resp = {"status": "ok"}
        reload_resp = {"status": "ok", "added": ["netbridge-test"], "removed": []}

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_clone.return_value = tmp_path / "repo"
            mock_curl.side_effect = [exec_resp, ok_resp, ok_resp, reload_resp]
            cmd_install(1080, "https://example.com/repo.git", "test-plugin")

        put_calls = [c for c in mock_curl.call_args_list if c[0][0] == "PUT"]
        assert len(put_calls) == 2

        # Verify repo_url was included in the uploaded manifest
        manifest_put = [c for c in put_calls if "manifest.json" in c[0][1]][0]
        uploaded_manifest = json.loads(manifest_put[1]["data"])
        assert uploaded_manifest["repo_url"] == "https://example.com/repo.git"

    def test_install_rejects_traversal_name(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            cmd_install(1080, "https://example.com/repo.git", "../evil")

    def test_install_raises_permission_on_403(self, tmp_path):
        plugin_dir = tmp_path / "repo" / "test"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "test", "hostname": "netbridge-test",
            "description": "t", "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text("pass")

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_clone.return_value = tmp_path / "repo"
            mock_curl.side_effect = PermissionError("Remote exec is disabled")
            with pytest.raises(PermissionError):
                cmd_install(1080, "https://example.com/repo.git", "test")


class TestPluginUninstall:
    def test_uninstall_calls_endpoint(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_curl.return_value = {
                "status": "ok",
                "removed": ["netbridge-test"],
                "uninstall_output": "Cleaned up.",
            }
            cmd_uninstall(1080, "test-plugin")
        out = capsys.readouterr().out
        assert "uninstalled" in out.lower()
        assert "Cleaned up" in out
        mock_curl.assert_called_once()
        assert "/plugins/uninstall/" in mock_curl.call_args[0][1]

    def test_uninstall_rejects_traversal_name(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            cmd_uninstall(1080, "../../etc")


class TestPluginUpdate:
    def test_update_reads_repo_from_manifest(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock_curl, \
             patch("socks_proxy.plugin_cli.cmd_uninstall") as mock_uninst, \
             patch("socks_proxy.plugin_cli.cmd_install") as mock_inst:
            mock_curl.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "test",
                 "repo_url": "https://example.com/repo.git"},
            ]}
            cmd_update(1080, "gauth")
            mock_uninst.assert_called_once_with(1080, "gauth")
            mock_inst.assert_called_once_with(1080, "https://example.com/repo.git", "gauth")

    def test_update_no_repo_url(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_curl.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "test", "repo_url": ""},
            ]}
            cmd_update(1080, "gauth")
        out = capsys.readouterr().out
        assert "no repo_url" in out.lower()

    def test_update_plugin_not_found(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_curl.return_value = {"plugins": []}
            cmd_update(1080, "nonexistent")
        out = capsys.readouterr().out
        assert "not found" in out.lower()
