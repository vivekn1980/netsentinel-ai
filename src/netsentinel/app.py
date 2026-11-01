"""Application entry point and CLI runner for NetSentinel AI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from netsentinel import __app_name__, __version__
from netsentinel.core.config import ConfigManager
from netsentinel.core.database import DatabaseManager
from netsentinel.core.dependencies import DependencyDetector
from netsentinel.ui.main_window import MainWindow
from netsentinel.ui.theme import LIGHT_THEME_QSS


def attach_parent_console_if_needed() -> None:
    """Attaches to caller's console if executed from terminal in GUI mode."""
    if sys.platform == "win32":
        try:
            import ctypes
            # ATTACH_PARENT_PROCESS = -1
            if ctypes.windll.kernel32.AttachConsole(-1):
                try:
                    if sys.stdout is None or not hasattr(sys.stdout, "write"):
                        sys.stdout = open("CONOUT$", "w", encoding="utf-8")
                    if sys.stderr is None or not hasattr(sys.stderr, "write"):
                        sys.stderr = open("CONOUT$", "w", encoding="utf-8")
                except Exception:
                    pass
        except Exception:
            pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="NetSentinelAI",
        description="NetSentinel AI - Standalone Windows Network Discovery & AI Security Auditing",
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Run in portable mode (stores data in 'data/' adjacent to the executable).",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Specify an explicit directory for local application data and database.",
    )
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="Run automated diagnostics and self-test without launching GUI; exits with code 0 on success.",
    )
    parser.add_argument(
        "--test-gui",
        action="store_true",
        help="Launches the full GUI event loop and cleanly shuts down after initialization; exits with code 0 on success.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} v{__version__}",
    )
    return parser.parse_args(argv)


def run_health_check(config_mgr: ConfigManager, db_mgr: DatabaseManager) -> int:
    """Executes headless health check verifying config, DB WAL, and dependencies."""
    print("=" * 60)
    print(f"{__app_name__} v{__version__} - System Health Check")
    print("=" * 60)

    # 1. Check storage and configuration
    print(f"[*] Storage Mode:   {config_mgr.storage_mode_label}")
    print(f"[*] Data Directory: {config_mgr.data_dir}")
    print(f"[*] Database Path:  {config_mgr.db_file}")

    # 2. Check database integrity
    db_ok = db_mgr.check_integrity()
    print(f"[*] Database Health: {'OK (Integrity Verified)' if db_ok else 'FAILED'}")
    if not db_ok:
        print("[!] Error: SQLite database integrity check failed.", file=sys.stderr)
        return 1

    # 3. Check dependencies
    report = DependencyDetector.run_diagnostics()
    print(f"[*] Summary Status:  {report.summary_status}")
    print(f"[*] Bundled Bundle:  {'Yes' if report.is_frozen_bundle else 'No (Development Mode)'}")
    print(f"[*] Elevation:       {'Elevated Admin' if report.is_elevated else 'Standard User'}")
    print(f"[*] Nmap Binary:     {report.nmap_executable or 'Not Detected (Fallback Active)'}")
    print(f"[*] Npcap Driver:    {'Detected' if report.npcap_installed else 'Not Installed'}")

    # 4. Check Scanner & XML Subsystems
    from netsentinel.core.nmap_engine import NmapEngine
    from netsentinel.core.xml_parser import NmapXmlParser
    xml_test = NmapXmlParser.parse("<nmaprun><host><status state='up'/><address addr='127.0.0.1'/></host></nmaprun>")
    xml_ok = xml_test.success and len(xml_test.hosts) == 1
    print(f"[*] XML Parser:      {'OK (Self-test verified)' if xml_ok else 'FAILED'}")
    if not xml_ok:
        print("[!] Error: XML parser self-test failed.", file=sys.stderr)
        return 1

    engine = NmapEngine()
    print(f"[*] Scanner Engine:  {'Ready (' + engine.version + ')' if engine.is_ready else 'Engine Framework Ready (' + engine.readiness_state.value + ')'}")

    print("-" * 60)
    print("[+] Core subsystem self-test passed successfully.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Primary application entry point."""
    attach_parent_console_if_needed()

    if argv is None:
        argv = sys.argv[1:]

    args = parse_args(argv)

    # Initialize configuration manager
    try:
        explicit_dir = Path(args.data_dir) if args.data_dir else None
        config_mgr = ConfigManager(
            portable_requested=args.portable,
            explicit_data_dir=explicit_dir,
        )
    except Exception as e:
        print(f"[FATAL ERROR] Failed to initialize storage directory: {e}", file=sys.stderr)
        return 1

    # Initialize local SQLite database
    try:
        db_mgr = DatabaseManager(config_mgr.db_file)
    except Exception as e:
        print(f"[FATAL ERROR] Failed to initialize SQLite database: {e}", file=sys.stderr)
        return 1

    # Handle --health-check mode
    if args.health_check:
        return run_health_check(config_mgr, db_mgr)

    # Launch PySide6 GUI desktop interface
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv[:1])

    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("NetSentinel")
    app.setStyleSheet(LIGHT_THEME_QSS)

    window = MainWindow(config_mgr, db_mgr)
    window.show()

    if getattr(args, "test_gui", False):
        from PySide6.QtCore import QTimer
        # Schedule clean window close once event loop starts
        QTimer.singleShot(1000, window.close)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
