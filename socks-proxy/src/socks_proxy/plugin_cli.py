"""Plugin management CLI for NetBridge VDI plugins."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote


def _validate_plugin_name(name):
    """Reject plugin names that could escape the plugins directory."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', name):
        raise ValueError(
            f"Invalid plugin name '{name}': must be alphanumeric "
            "(with dots, hyphens, underscores allowed, no path separators)"
        )


def _curl(method, path, proxy_port=1080, json_body=None, data=None, timeout=30):
    """HTTP request to netbridge-exec through the SOCKS proxy via curl."""
    url = f"http://netbridge-exec{path}"
    cmd = [
        "curl", "-sS", "--fail-with-body", "--max-time", str(timeout),
        "--proxy", f"socks5h://127.0.0.1:{proxy_port}",
        "-X", method,
    ]
    if json_body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(json_body)]
    if data is not None:
        cmd += ["--data-binary", "@-"]
    cmd.append(url)

    result = subprocess.run(
        cmd, capture_output=True, input=data,
        timeout=timeout + 10,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        stdout = result.stdout.decode(errors="replace").strip()
        detail = stderr or stdout
        if "403" in detail:
            raise PermissionError(
                "Remote exec is disabled — enable it from the VDI system tray"
            )
        raise ConnectionError(f"Request failed: {detail}")
    if not result.stdout:
        return {}
    resp = json.loads(result.stdout)
    if "error" in resp:
        if "disabled" in resp["error"].lower() and "tray" in resp["error"].lower():
            raise PermissionError(resp["error"])
        raise RuntimeError(f"Agent error: {resp['error']}")
    return resp


def _get_remote_plugins_dir(proxy_port):
    """Get the actual plugins directory path from the VDI agent."""
    exec_resp = _curl(
        "POST", "/exec", proxy_port,
        json_body={"cmd": 'echo %LOCALAPPDATA%'},
    )
    localappdata = exec_resp.get("stdout", "").strip().strip('"')
    if not localappdata or "%" in localappdata:
        raise RuntimeError("Could not determine remote plugins directory")
    return f"{localappdata}\\NetBridge\\plugins"


def _clone_repo(repo_url):
    """Clone a git repo to a temporary directory."""
    tmpdir = Path(tempfile.mkdtemp(prefix="netbridge-plugin-"))
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(tmpdir)],
            capture_output=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr.decode(errors='replace')}")
        return tmpdir
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise


def _install_laptop_files(plugin_dir, plugin_name, bin_dir=None, config_dir=None):
    """Install laptop-side files from plugin's laptop/ directory."""
    laptop_dir = plugin_dir / "laptop"
    if not laptop_dir.is_dir():
        return

    if bin_dir is None:
        bin_dir = Path.home() / ".local" / "bin"
    if config_dir is None:
        config_dir = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))

    installed = []
    skipped = []

    laptop_bin = laptop_dir / "bin"
    if laptop_bin.is_dir():
        bin_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(laptop_bin.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                dest = bin_dir / f.name
                shutil.copy2(f, dest)
                dest.chmod(dest.stat().st_mode | 0o755)
                installed.append(f"~/.local/bin/{f.name}")

    env_template = laptop_dir / "config" / ".env.template"
    if env_template.is_file():
        env_dest_dir = config_dir / plugin_name
        env_dest = env_dest_dir / ".env"
        if env_dest.exists():
            skipped.append(f"~/.config/{plugin_name}/.env (already exists)")
        else:
            env_dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(env_template, env_dest)
            installed.append(f"~/.config/{plugin_name}/.env (fill in your credentials)")

    if installed or skipped:
        print("  Laptop setup:")
        for item in installed:
            label = "Created" if ".env" in item else "Installed"
            print(f"    {label}: {item}")
        for item in skipped:
            print(f"    Skipped: {item}")


def cmd_list(proxy_port):
    """List installed plugins on VDI."""
    response = _curl("GET", "/plugins", proxy_port)
    plugins = response.get("plugins", [])

    if not plugins:
        print("No plugins installed.")
        return

    print(f"{'Name':<20} {'Version':<12} {'Hostname':<25} {'Description'}")
    print("-" * 90)
    for plugin in plugins:
        name = plugin.get("name", "?")
        version = plugin.get("version", "?")
        hostname = plugin.get("hostname", "?")
        description = plugin.get("description", "")
        print(f"{name:<20} {version:<12} {hostname:<25} {description}")


def cmd_info(proxy_port, plugin_name):
    """Show details for a specific plugin."""
    response = _curl("GET", "/plugins", proxy_port)
    plugins = response.get("plugins", [])

    plugin = next((p for p in plugins if p.get("name") == plugin_name), None)
    if not plugin:
        print(f"Plugin '{plugin_name}' not found.")
        return

    print(f"Name:        {plugin.get('name', '?')}")
    print(f"Version:     {plugin.get('version', '?')}")
    print(f"Hostname:    {plugin.get('hostname', '?')}")
    print(f"Description: {plugin.get('description', '')}")
    repo = plugin.get("repo_url", "")
    if repo:
        print(f"Repository:  {repo}")


def cmd_install(proxy_port, repo_url, plugin_name):
    """Install a plugin from a git repository."""
    _validate_plugin_name(plugin_name)

    print(f"Cloning {repo_url}...")
    repo_dir = _clone_repo(repo_url)

    try:
        plugin_dir = repo_dir / plugin_name
        if plugin_dir.is_symlink():
            raise ValueError(f"Plugin directory '{plugin_name}' is a symlink — rejected")
        if not plugin_dir.is_dir():
            available = [d.name for d in repo_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
            raise FileNotFoundError(
                f"Plugin directory '{plugin_name}' not found in repository. "
                f"Available: {available}"
            )

        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest.json not found in {plugin_name}/")

        with open(manifest_path) as f:
            manifest = json.load(f)

        required_fields = ["name", "hostname", "description", "version", "entry_point"]
        for field in required_fields:
            if field not in manifest:
                raise ValueError(f"manifest.json missing required field: {field}")

        hostname = manifest["hostname"]
        if not hostname.startswith("netbridge-"):
            raise ValueError(f"hostname must start with 'netbridge-', got '{hostname}'")

        # Store repo_url in manifest for later updates (strip credentials)
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(repo_url)
        safe_url = urlunparse(parsed._replace(netloc=parsed.hostname or parsed.netloc))
        manifest["repo_url"] = safe_url
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"Installing plugin '{manifest['name']}' v{manifest['version']}...")

        remote_base = _get_remote_plugins_dir(proxy_port)
        remote_plugin_dir = f"{remote_base}\\{plugin_name}"

        for file_path in sorted(plugin_dir.rglob("*")):
            if file_path.is_symlink():
                continue
            rel_path = file_path.relative_to(plugin_dir)
            if rel_path.parts[0] == "laptop":
                continue
            if file_path.is_file() and not file_path.name.startswith("."):
                remote_path = f"{remote_plugin_dir}\\{str(rel_path).replace('/', chr(92))}"

                with open(file_path, "rb") as f:
                    file_data = f.read()

                _curl("PUT", f"/files/{quote(remote_path, safe='')}", proxy_port, data=file_data)
                print(f"  Uploaded: {rel_path}")

        if (plugin_dir / "install.py").exists():
            print("  Running install.py (this may take a while for pip installs)...")
            install_path = f"{remote_plugin_dir}\\install.py"
            exec_response = _curl(
                "POST", "/exec", proxy_port,
                json_body={
                    "cmd": f'python "{install_path}"',
                    "cwd": remote_plugin_dir,
                    "timeout": 300,
                },
                timeout=300,
            )
            if exec_response.get("exit_code") != 0:
                stderr = exec_response.get("stderr", "")
                raise RuntimeError(f"install.py failed: {stderr}")
            stdout = exec_response.get("stdout", "").strip()
            if stdout:
                print(f"  {stdout}")

        print("  Reloading plugins...")
        reload_response = _curl("POST", "/plugins/reload", proxy_port)

        added = reload_response.get("added", [])
        if hostname in added:
            print(f"\nPlugin '{manifest['name']}' installed and loaded!")
            print(f"Access via: curl --proxy socks5h://localhost:{proxy_port} http://{hostname}/")
        else:
            print(f"\nPlugin '{manifest['name']}' files uploaded but failed to load.")
            print("Check agent logs on VDI for details.")

        _install_laptop_files(plugin_dir, plugin_name)

    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def cmd_uninstall(proxy_port, plugin_name):
    """Uninstall a plugin from VDI."""
    _validate_plugin_name(plugin_name)

    print(f"Uninstalling plugin '{plugin_name}'...")
    try:
        response = _curl("POST", f"/plugins/uninstall/{quote(plugin_name, safe='')}", proxy_port)
    except (ConnectionError, RuntimeError) as e:
        err = str(e).lower()
        if "404" in err or "not found" in err:
            print(f"Plugin '{plugin_name}' not found on VDI.")
            return
        raise

    output = response.get("uninstall_output", "").strip()
    if output:
        print(f"  {output}")

    removed = response.get("removed", [])
    print(f"\nPlugin '{plugin_name}' uninstalled.")
    if removed:
        print(f"Removed: {', '.join(removed)}")


def cmd_update(proxy_port, plugin_name):
    """Update a plugin using the repo_url stored in its manifest."""
    _validate_plugin_name(plugin_name)

    # Get repo_url from installed manifest
    response = _curl("GET", "/plugins", proxy_port)
    plugins = response.get("plugins", [])
    plugin = next((p for p in plugins if p.get("name") == plugin_name), None)

    if not plugin:
        print(f"Plugin '{plugin_name}' not found.")
        return

    repo_url = plugin.get("repo_url", "")
    if not repo_url:
        print(f"Plugin '{plugin_name}' has no repo_url stored.")
        print("Use 'netbridge-socks plugin install <repo_url> <name>' instead.")
        return

    print(f"Updating plugin '{plugin_name}' from {repo_url}...")
    cmd_uninstall(proxy_port, plugin_name)
    print()
    cmd_install(proxy_port, repo_url, plugin_name)


def add_plugin_subparser(subparsers):
    """Register the 'plugin' subcommand and its sub-subcommands."""
    plugin_parser = subparsers.add_parser(
        "plugin",
        help="Manage VDI plugins",
    )
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_command")

    plugin_sub.add_parser("list", help="List installed plugins on VDI")

    install_p = plugin_sub.add_parser("install", help="Install a plugin from a git repo")
    install_p.add_argument("repo_url", help="Git repo URL")
    install_p.add_argument("plugin_name", help="Plugin directory name in the repo")

    uninstall_p = plugin_sub.add_parser("uninstall", help="Uninstall a plugin from VDI")
    uninstall_p.add_argument("plugin_name", help="Plugin name to uninstall")

    update_p = plugin_sub.add_parser("update", help="Update a plugin from its stored repo")
    update_p.add_argument("plugin_name", help="Plugin name to update")

    info_p = plugin_sub.add_parser("info", help="Show plugin details")
    info_p.add_argument("plugin_name", help="Plugin name")

    plugin_parser.add_argument(
        "--proxy-port",
        type=int,
        default=1080,
        help="Local SOCKS proxy port (default: 1080)",
    )


def plugin_main(args):
    """Entry point for plugin subcommands."""
    if not args.plugin_command:
        print("Usage: netbridge-socks plugin {list,install,uninstall,update,info}")
        print("Run 'netbridge-socks plugin --help' for details.")
        return

    try:
        if args.plugin_command == "list":
            cmd_list(args.proxy_port)
        elif args.plugin_command == "install":
            cmd_install(args.proxy_port, args.repo_url, args.plugin_name)
        elif args.plugin_command == "uninstall":
            cmd_uninstall(args.proxy_port, args.plugin_name)
        elif args.plugin_command == "update":
            cmd_update(args.proxy_port, args.plugin_name)
        elif args.plugin_command == "info":
            cmd_info(args.proxy_port, args.plugin_name)
    except PermissionError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ConnectionError as e:
        print(f"Error: {e}")
        print("Make sure netbridge-socks proxy is running and the VDI agent is connected.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
