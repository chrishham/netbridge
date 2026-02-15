# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for NetBridge Agent.

Build with:
    cd netbridge-agent
    uv run pyinstaller netbridge-agent.spec

Output: dist/netbridge.exe (Windows) or dist/netbridge (Linux/macOS)
"""

import os

# SPECPATH is provided by PyInstaller - points to directory containing this spec file
shared_path = os.path.join(SPECPATH, "..", "shared", "src")
agent_path = os.path.join(SPECPATH, "src")

a = Analysis(
    ["entry.py"],
    pathex=[agent_path, shared_path],
    binaries=[],
    datas=[],
    hiddenimports=[
        "aiohttp",
        "netbridge_agent",
        "netbridge_agent.auth",
        "netbridge_agent.tunnel",
        "netbridge_agent.winproxy",

        "shared_auth",
        "shared_auth.token",
        "shared_auth.connection",
        "shared_auth.session",
        "shared_auth.validate",
        "azure.storage.blob",
        "azure.core",
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
    name="netbridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disable UPX - can trigger antivirus false positives
    console=True,  # Console hidden at runtime; needed for --version output
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    # TODO: Procure a code signing certificate for production builds
    codesign_identity=None,
    entitlements_file=None,
)
