"""Plugin management CLI for NetBridge VDI plugins."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REMOTE_PLUGINS_DIR = "%LOCALAPPDATA%\\NetBridge\\plugins"


def _curl(method, path, proxy_port=1080, json_body=None, data=None, timeout=30):
    """HTTP request to netbridge-exec through the SOCKS proxy via curl."""
    url = f"http://netbridge-exec{path}"
    cmd = [
        "curl", "-sS", "--max-time", str(timeout),
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
        raise ConnectionError(f"Failed to connect: {stderr}")
    if not result.stdout:
        return {}
    return json.loads(result.stdout)


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
    print(f"Entry Point: {plugin.get('entry_point', '?')}")


def cmd_install(proxy_port, repo_url, plugin_name):
    """Install a plugin from a git repository."""
    print(f"Cloning {repo_url}...")
    repo_dir = _clone_repo(repo_url)

    try:
        plugin_dir = repo_dir / plugin_name
        if not plugin_dir.exists():
            raise FileNotFoundError(f"Plugin directory '{plugin_name}' not found in repository")

        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"manifest.json not found in {plugin_name}/")

        # Validate manifest
        with open(manifest_path) as f:
            manifest = json.load(f)

        required_fields = ["name", "hostname", "version", "entry_point"]
        for field in required_fields:
            if field not in manifest:
                raise ValueError(f"manifest.json missing required field: {field}")

        print(f"Installing plugin '{manifest['name']}' v{manifest['version']}...")

        # Upload all files in the plugin directory
        remote_base = f"{REMOTE_PLUGINS_DIR}\\{plugin_name}"
        for file_path in plugin_dir.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(plugin_dir)
                remote_path = f"{remote_base}\\{str(rel_path).replace('/', chr(92))}"

                with open(file_path, "rb") as f:
                    file_data = f.read()

                _curl("PUT", f"/files/{remote_path}", proxy_port, data=file_data)
                print(f"  Uploaded: {rel_path}")

        # Run install.py if it exists
        install_script = plugin_dir / "install.py"
        if install_script.exists():
            print("  Running install.py (this may take a while for pip installs)...")
            install_path = f"{remote_base}\\install.py"
            exec_response = _curl(
                "POST", "/exec", proxy_port,
                json_body={"cmd": f"python {install_path}", "cwd": remote_base},
                timeout=300,
            )
            if exec_response.get("exit_code") != 0:
                stderr = exec_response.get("stderr", "")
                raise RuntimeError(f"install.py failed: {stderr}")

        # Reload plugins
        print("  Reloading plugins...")
        reload_response = _curl("POST", "/plugins/reload", proxy_port)

        print(f"\nPlugin '{manifest['name']}' installed successfully!")
        print(f"Access via hostname: {manifest['hostname']}")

        if reload_response.get("added"):
            print(f"Loaded: {', '.join(reload_response['added'])}")

    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def cmd_uninstall(proxy_port, plugin_name):
    """Uninstall a plugin from VDI."""
    remote_path = f"{REMOTE_PLUGINS_DIR}\\{plugin_name}"

    # Check if plugin directory exists
    try:
        list_response = _curl("GET", f"/files?dir={remote_path}", proxy_port)
        entries = list_response.get("entries", [])
    except Exception:
        print(f"Plugin '{plugin_name}' not found or already uninstalled.")
        return

    # Run uninstall.py if it exists
    if any(e.get("name") == "uninstall.py" for e in entries):
        print(f"Running uninstall.py for '{plugin_name}'...")
        uninstall_script = f"{remote_path}\\uninstall.py"
        try:
            exec_response = _curl(
                "POST", "/exec", proxy_port,
                json_body={"cmd": f"python {uninstall_script}", "cwd": remote_path},
                timeout=300,
            )
            if exec_response.get("exit_code") != 0:
                print(f"  Warning: uninstall.py exited with code {exec_response.get('exit_code')}")
        except Exception as e:
            print(f"  Warning: uninstall.py failed: {e}")

    # Delete the plugin directory
    print(f"Removing plugin directory...")
    _curl("DELETE", f"/files/{remote_path}", proxy_port)

    # Reload plugins
    print("Reloading plugins...")
    reload_response = _curl("POST", "/plugins/reload", proxy_port)

    print(f"\nPlugin '{plugin_name}' uninstalled successfully.")
    if reload_response.get("removed"):
        print(f"Removed: {', '.join(reload_response['removed'])}")


def cmd_update(proxy_port, repo_url, plugin_name):
    """Update a plugin by reinstalling from repository."""
    print(f"Updating plugin '{plugin_name}'...")
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

    update_p = plugin_sub.add_parser("update", help="Update a plugin (reinstall from repo)")
    update_p.add_argument("repo_url", help="Git repo URL")
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
            cmd_update(args.proxy_port, args.repo_url, args.plugin_name)
        elif args.plugin_command == "info":
            cmd_info(args.proxy_port, args.plugin_name)
    except ConnectionError as e:
        print(f"Error: {e}")
        print("Make sure netbridge-socks proxy is running and remote exec is enabled on the VDI.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
