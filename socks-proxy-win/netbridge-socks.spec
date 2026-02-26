# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for NetBridge Socks (Windows).

Build with:
    cd socks-proxy-win
    uv run pyinstaller netbridge-socks.spec

Output: dist/netbridge-socks.exe
"""

import os

# SPECPATH is provided by PyInstaller - points to directory containing this spec file
shared_path = os.path.join(SPECPATH, "..", "shared", "src")
socks_path = os.path.join(SPECPATH, "..", "socks-proxy", "src")
win_path = os.path.join(SPECPATH, "src")

a = Analysis(
    ["entry.py"],
    pathex=[win_path, socks_path, shared_path],
    binaries=[],
    datas=[],
    hiddenimports=[
        "aiohttp",
        "orjson",
        # Core proxy modules (from socks-proxy package)
        "socks_proxy",
        "socks_proxy.socks5",
        "socks_proxy.http_proxy",
        "socks_proxy.tunnel",
        "socks_proxy.auth",
        # Windows tray modules (from socks-proxy-win package)
        "socks_proxy_win",
        "socks_proxy_win.app",
        "socks_proxy_win.config",
        "socks_proxy_win.tray",
        "socks_proxy_win.installer",
        "socks_proxy_win.dialogs",
        # Shared auth
        "shared_auth",
        "shared_auth.token",
        "shared_auth.connection",
        "shared_auth.session",
        "shared_auth.validate",
        # Dependencies
        "pystray",
        "PIL",
        "packaging",
        "packaging.version",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="netbridge-socks",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disable UPX - can trigger antivirus false positives
    console=True,  # Console hidden at runtime; needed for --version output
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
