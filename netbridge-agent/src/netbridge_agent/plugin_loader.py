"""Plugin discovery and manifest validation.

Plugins live under ``%LOCALAPPDATA%/NetBridge/plugins/<name>/``.
Each plugin directory must contain a ``manifest.json`` declaring
its hostname, description, version, and entry point module.  The
entry point module must export a ``create_app()`` function
returning an ``aiohttp.web.Application``.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from aiohttp import web

LOG = logging.getLogger(__name__)

RESERVED_HOSTNAMES = {"netbridge-exec"}


class PluginLoadError(Exception):
    pass


@dataclass
class PluginManifest:
    name: str
    hostname: str
    description: str
    version: str
    entry_point: str
    path: Path


def load_manifest(plugin_dir: Path) -> PluginManifest:
    manifest_path = plugin_dir / "manifest.json"
    if not manifest_path.exists():
        raise PluginLoadError(f"manifest.json not found in {plugin_dir}")

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        raise PluginLoadError(f"invalid JSON in {manifest_path}")

    required = ("name", "hostname", "description", "version", "entry_point")
    for field in required:
        if field not in data:
            raise PluginLoadError(
                f"missing required field '{field}' in {manifest_path}"
            )

    hostname = data["hostname"]
    if not isinstance(hostname, str):
        raise PluginLoadError(
            f"hostname must be a string, got {type(hostname).__name__} in {manifest_path}"
        )
    hostname = hostname.lower()
    if not hostname.startswith("netbridge-"):
        raise PluginLoadError(
            f"hostname '{hostname}' must start with 'netbridge-'"
        )
    if hostname in RESERVED_HOSTNAMES:
        raise PluginLoadError(f"hostname '{hostname}' is reserved")

    return PluginManifest(
        name=data["name"],
        hostname=hostname,
        description=data["description"],
        version=data["version"],
        entry_point=data["entry_point"],
        path=plugin_dir,
    )


def load_plugin_app(manifest: PluginManifest) -> web.Application:
    entry = (manifest.path / manifest.entry_point).resolve()
    if not entry.is_relative_to(manifest.path.resolve()):
        raise PluginLoadError(
            f"entry_point escapes plugin directory: {manifest.entry_point}"
        )
    if not entry.exists():
        raise PluginLoadError(f"entry point {entry} not found")

    plugin_dir = str(manifest.path.resolve())
    if plugin_dir not in sys.path:
        sys.path.insert(0, plugin_dir)

    spec = importlib.util.spec_from_file_location(
        f"netbridge_plugin_{manifest.name}", entry
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "create_app"):
        raise PluginLoadError(
            f"plugin {manifest.name}: {entry} has no create_app()"
        )

    return module.create_app()


def discover_plugins(plugins_dir: Path) -> list[PluginManifest]:
    if not plugins_dir.is_dir():
        return []

    manifests = []
    for child in sorted(plugins_dir.iterdir()):
        if not child.is_dir():
            continue
        try:
            manifest = load_manifest(child)
            manifests.append(manifest)
        except Exception as e:
            LOG.warning("Skipping plugin %s: %s", child.name, e)

    return manifests
