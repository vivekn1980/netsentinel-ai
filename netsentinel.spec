# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for NetSentinel AI single-file portable executable."""

import sys
from pathlib import Path

block_cipher = None

# Project paths
spec_root = Path.cwd().resolve()
src_dir = spec_root / "src"

added_files = [
    (str(spec_root / "README.md"), "."),
    (str(spec_root / "requirements.txt"), "."),
]

# Include bin directory if present (e.g. bundled portable tools)
bin_dir = spec_root / "bin"
if bin_dir.is_dir():
    added_files.append((str(bin_dir), "bin"))

a = Analysis(
    [str(src_dir / "netsentinel" / "app.py")],
    pathex=[str(src_dir)],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        "PySide6",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "sqlite3",
        "ctypes",
        "ctypes.wintypes",
        "winreg",
        "ipaddress",
        "json",
        "netsentinel",
        "netsentinel.core",
        "netsentinel.core.config",
        "netsentinel.core.database",
        "netsentinel.core.dependencies",
        "netsentinel.core.models",
        "netsentinel.core.validator",
        "netsentinel.core.nmap_engine",
        "netsentinel.core.xml_parser",
        "netsentinel.core.scan_worker",
        "netsentinel.core.security_rules",
        "netsentinel.core.risk_engine",
        "netsentinel.core.remediation",
        "netsentinel.core.security_analyzer",
        "xml.etree.ElementTree",
        "netsentinel.ui",
        "netsentinel.ui.theme",
        "netsentinel.ui.main_window",
        "netsentinel.ui.views",
        "netsentinel.ui.views.dashboard_view",
        "netsentinel.ui.views.inventory_view",
        "netsentinel.core.reporting",
        "netsentinel.core.reporting.report_paths",
        "netsentinel.core.reporting.csv_export",
        "netsentinel.core.reporting.json_export",
        "netsentinel.core.reporting.html_report",
        "netsentinel.core.reporting.diff_engine",
        "netsentinel.core.reporting.report_generator",
        "netsentinel.ui.dialogs",
        "netsentinel.ui.dialogs.export_dialog",
        "netsentinel.ui.dialogs.scan_compare_dialog",
        "netsentinel.ui.views.history_view",
        "netsentinel.ui.views.findings_view",
        "netsentinel.ui.views.dependencies_view",
        "netsentinel.ui.views.settings_view",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "scipy",
        "pandas",
        "numpy",
        "PIL",
        "cv2",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NetSentinelAI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
