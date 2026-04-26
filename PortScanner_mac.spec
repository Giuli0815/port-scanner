# -*- mode: python ; coding: utf-8 -*-
# macOS build spec — run on a Mac with:
#   pip install pyinstaller customtkinter
#   pyinstaller PortScanner_mac.spec

a = Analysis(
    ['port_scanner.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
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
    [],
    exclude_binaries=True,
    name='PortScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PortScanner',
)
app = BUNDLE(
    coll,
    name='PortScanner.app',
    icon=None,
    bundle_identifier='com.giuli.portscanner',
    info_plist={
        'CFBundleName': 'Port Scanner',
        'CFBundleDisplayName': 'Port Scanner',
        'CFBundleShortVersionString': '1.0.0',
        'CFBundleVersion': '1.0.0',
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '11.0',
    },
)
