"""Tests for socks_proxy.plugin_cli module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from socks_proxy.plugin_cli import cmd_list, cmd_install, cmd_uninstall, cmd_info, _curl


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
            assert "socks5h://127.0.0.1:1080" in " ".join(cmd)
            assert "http://netbridge-exec/health" in cmd

    def test_curl_connection_error(self):
        mock_result = MagicMock()
        mock_result.returncode = 7
        mock_result.stderr = b"Failed to connect"
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result):
            with pytest.raises(ConnectionError):
                _curl("GET", "/health")

    def test_curl_custom_port(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result) as mock_run:
            _curl("GET", "/health", proxy_port=9999)
            cmd = mock_run.call_args[0][0]
            assert "socks5h://127.0.0.1:9999" in " ".join(cmd)

    def test_curl_with_json_body(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b'{"exit_code":0}'
        with patch("socks_proxy.plugin_cli.subprocess.run", return_value=mock_result) as mock_run:
            _curl("POST", "/exec", json_body={"cmd": "echo hi"})
            cmd = mock_run.call_args[0][0]
            assert "-X" in cmd
            assert "POST" in cmd
            assert "Content-Type: application/json" in " ".join(cmd)

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
            "description": "test", "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (plugin_dir / "handlers.py").write_text("pass")

        with patch("socks_proxy.plugin_cli._clone_repo") as mock_clone, \
             patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_clone.return_value = tmp_path / "repo"
            mock_curl.return_value = {"status": "ok"}
            cmd_install(1080, "https://example.com/repo.git", "test-plugin")

        # Should have called PUT for each file + POST reload
        put_calls = [c for c in mock_curl.call_args_list if c[0][0] == "PUT"]
        assert len(put_calls) == 2  # manifest.json + handlers.py
        reload_calls = [c for c in mock_curl.call_args_list if c[0][1] == "/plugins/reload"]
        assert len(reload_calls) == 1


class TestPluginUninstall:
    def test_uninstall_deletes_and_reloads(self, capsys):
        with patch("socks_proxy.plugin_cli._curl") as mock_curl:
            mock_curl.side_effect = [
                {"dir": "...", "entries": [{"name": "manifest.json"}, {"name": "handlers.py"}]},
                {"status": "ok"},  # DELETE
                {"status": "ok", "added": [], "removed": ["netbridge-test"]},  # reload
            ]
            cmd_uninstall(1080, "test-plugin")
        out = capsys.readouterr().out
        assert "uninstalled" in out.lower()
