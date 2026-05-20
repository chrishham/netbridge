"""Plugin management CLI for NetBridge VDI plugins."""


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

    print(f"Plugin command '{args.plugin_command}' not yet implemented.")
