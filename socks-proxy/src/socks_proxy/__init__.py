"""SOCKS5 proxy for Network Bridge."""

try:
    from importlib.metadata import version
    __version__ = version("netbridge-socks")
except Exception:
    # PyInstaller bundles lack package metadata; CI injects via sed before build
    __version__ = "0.0.0"
