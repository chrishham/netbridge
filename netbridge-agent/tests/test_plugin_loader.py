"""Tests for netbridge_agent.plugin_loader module."""

import json

import pytest

from netbridge_agent.plugin_loader import (
    PluginLoadError,
    PluginManifest,
    discover_plugins,
    load_manifest,
    load_plugin_app,
)


# ---------------------------------------------------------------------------
# load_manifest
# ---------------------------------------------------------------------------


class TestLoadManifest:
    def _write_manifest(self, plugin_dir, data):
        plugin_dir.mkdir(exist_ok=True)
        (plugin_dir / "manifest.json").write_text(json.dumps(data))

    def test_valid_manifest(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "test-plugin",
            "hostname": "netbridge-test",
            "description": "A test plugin",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        m = load_manifest(tmp_path)
        assert m.name == "test-plugin"
        assert m.hostname == "netbridge-test"
        assert m.version == "1.0.0"
        assert m.path == tmp_path

    def test_missing_manifest_file(self, tmp_path):
        with pytest.raises(PluginLoadError, match="manifest.json not found"):
            load_manifest(tmp_path)

    def test_invalid_json(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "manifest.json").write_text("not json{{{")
        with pytest.raises(PluginLoadError, match="invalid JSON"):
            load_manifest(tmp_path)

    def test_missing_required_field(self, tmp_path):
        self._write_manifest(tmp_path, {"name": "x"})
        with pytest.raises(PluginLoadError, match="missing required field"):
            load_manifest(tmp_path)

    def test_hostname_must_start_with_netbridge(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "bad",
            "hostname": "not-netbridge",
            "description": "bad hostname",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        with pytest.raises(PluginLoadError, match="must start with 'netbridge-'"):
            load_manifest(tmp_path)

    def test_reserved_hostname_rejected(self, tmp_path):
        self._write_manifest(tmp_path, {
            "name": "sneaky",
            "hostname": "netbridge-exec",
            "description": "hijack attempt",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        })
        with pytest.raises(PluginLoadError, match="reserved"):
            load_manifest(tmp_path)


# ---------------------------------------------------------------------------
# load_plugin_app
# ---------------------------------------------------------------------------


class TestLoadPluginApp:
    def test_loads_create_app(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (tmp_path / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    app = web.Application()\n"
            "    return app\n"
        )
        manifest = load_manifest(tmp_path)
        app = load_plugin_app(manifest)
        from aiohttp.web import Application
        assert isinstance(app, Application)

    def test_missing_entry_point_file(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        manifest = load_manifest(tmp_path)
        with pytest.raises(PluginLoadError, match="not found"):
            load_plugin_app(manifest)

    def test_missing_create_app_function(self, tmp_path):
        (tmp_path / "manifest.json").write_text(json.dumps({
            "name": "test",
            "hostname": "netbridge-test",
            "description": "test",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (tmp_path / "handlers.py").write_text("x = 1\n")
        manifest = load_manifest(tmp_path)
        with pytest.raises(PluginLoadError, match="no create_app"):
            load_plugin_app(manifest)


# ---------------------------------------------------------------------------
# discover_plugins
# ---------------------------------------------------------------------------


class TestDiscoverPlugins:
    def _make_plugin(self, plugins_dir, name, hostname=None):
        d = plugins_dir / name
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({
            "name": name,
            "hostname": hostname or f"netbridge-{name}",
            "description": f"{name} plugin",
            "version": "1.0.0",
            "entry_point": "handlers.py",
        }))
        (d / "handlers.py").write_text(
            "from aiohttp import web\n"
            "def create_app():\n"
            "    return web.Application()\n"
        )

    def test_empty_dir(self, tmp_path):
        assert discover_plugins(tmp_path) == []

    def test_nonexistent_dir(self, tmp_path):
        assert discover_plugins(tmp_path / "nope") == []

    def test_discovers_valid_plugin(self, tmp_path):
        self._make_plugin(tmp_path, "myplugin")
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "myplugin"

    def test_skips_invalid_plugin(self, tmp_path):
        self._make_plugin(tmp_path, "good")
        bad = tmp_path / "bad"
        bad.mkdir()
        # No manifest — should be skipped
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1
        assert plugins[0].name == "good"

    def test_skips_non_directory_entries(self, tmp_path):
        self._make_plugin(tmp_path, "valid")
        (tmp_path / "readme.txt").write_text("not a plugin")
        plugins = discover_plugins(tmp_path)
        assert len(plugins) == 1

    def test_discovers_multiple_sorted(self, tmp_path):
        self._make_plugin(tmp_path, "beta")
        self._make_plugin(tmp_path, "alpha")
        plugins = discover_plugins(tmp_path)
        assert [p.name for p in plugins] == ["alpha", "beta"]
