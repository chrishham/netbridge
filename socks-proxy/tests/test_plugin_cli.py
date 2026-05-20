"""Tests for socks_proxy.plugin_cli module."""

import json
from unittest.mock import patch, MagicMock, call

import pytest

from socks_proxy.plugin_cli import (
    cmd_list, cmd_install, cmd_uninstall, cmd_info,
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

    def test_curl_agent_error_raises(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"error": "something broke"}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Agent error"):
                _curl("GET", "/health")

    def test_curl_custom_port(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result) as mock_run:
            _curl("GET", "/health", proxy_port=9999)
            cmd = mock_run.call_args[0][0]
            assert "socks5h://127.0.0.1:9999" in " ".join(cmd)

    def test_curl_with_binary_data(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"status":"ok"}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result) as mock_run:
            _curl("PUT", "/files/test.txt", data=b"hello")
            assert mock_run.call_args[1]["input"] == b"hello"


class TestPluginList:
    def test_list_plugins(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "GCloud auth"},
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
    def test_info_found(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock:
            mock.return_value = {"plugins": [
                {"name": "gauth", "hostname": "netbridge-gauth",
                 "version": "1.0.0", "description": "GCloud auth helper"},
            ]}
            cmd_info(1080, "gauth")
        out = capsys.readouterr().out
        assert "gauth" in out
        assert "netbridge-gauth" in out

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

        exec_resp = {"exit_code": 0, "stdout": "C:\\Users\\user\\AppData\\Local\\NetBridge\\plugins"}
        ok_resp = {"status": "ok"}
        reload_resp = {"status": "ok", "added": ["netbridge-test"], "removed": []}

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_clone.return_value = tmp_path / "repo"
            # _get_remote_plugins_dir calls POST /exec, then PUT calls, then POST /plugins/reload
            mock_curl.side_effect = [exec_resp, ok_resp, ok_resp, reload_resp]
            cmd_install(1080, "https://example.com/repo.git", "test-plugin")

        put_calls = [c for c in mock_curl.call_args_list if c[0][0] == "PUT"]
        assert len(put_calls) == 2
        reload_calls = [c for c in mock_curl.call_args_list if c[0][1] == "/plugins/reload"]
        assert len(reload_calls) == 1

    def test_install_rejects_traversal_name(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            cmd_install(1080, "https://example.com/repo.git", "../evil")

    def test_install_validates_hostname_prefix(self, tmp_path):
        plugin_dir = tmp_path / "repo" / "bad"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text(json.dumps({
            "name": "bad", "hostname": "not-netbridge",
            "description": "bad", "version": "1.0.0",
            "entry_point": "handlers.py",
        }))

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl"):
            mock_clone.return_value = tmp_path / "repo"
            with pytest.raises(ValueError, match="netbridge-"):
                cmd_install(1080, "https://example.com/repo.git", "bad")


class TestPluginUninstall:
    def test_uninstall_deletes_and_reloads(self, capsys):
        exec_resp = {"exit_code": 0, "stdout": "C:\\Users\\user\\AppData\\Local\\NetBridge\\plugins"}
        list_resp = {"dir": "...", "entries": [{"name": "manifest.json"}, {"name": "handlers.py"}]}
        delete_resp = {"status": "ok", "deleted": "..."}
        reload_resp = {"status": "ok", "added": [], "removed": ["netbridge-test"]}

        with patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_curl.side_effect = [exec_resp, list_resp, delete_resp, reload_resp]
            cmd_uninstall(1080, "test-plugin")
        out = capsys.readouterr().out
        assert "uninstalled" in out.lower()

    def test_uninstall_rejects_traversal_name(self):
        with pytest.raises(ValueError, match="Invalid plugin name"):
            cmd_uninstall(1080, "../../etc")
