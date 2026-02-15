# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['launcher.py'],
    pathex=['src'],
    binaries=[],
    datas=[],
    hiddenimports=['netbridge_agent', 'netbridge_agent.config', 'netbridge_agent.app', 'netbridge_agent.tray',
                   'netbridge_agent.agent', 'netbridge_agent.auth', 'netbridge_agent.installer',
                   'netbridge_agent.legacy', 'pystray', 'PIL'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='netbridge',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    # TODO: Procure a code signing certificate for production builds
    codesign_identity=None,
    entitlements_file=None,
)
