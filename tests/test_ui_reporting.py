"""Headless UI tests for ExportDialog and ScanCompareDialog."""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    Asset,
    Port,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
    STATUS_RESOLVED,
)
from netsentinel.ui.dialogs.export_dialog import ExportDialog
from netsentinel.ui.dialogs.scan_compare_dialog import ScanCompareDialog


@pytest.fixture(scope="session")
def qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def reporting_db(tmp_path: Path) -> DatabaseManager:
    db = DatabaseManager(tmp_path / "reporting_test.db")
    aid = db.upsert_asset(Asset(ip_address="192.168.1.50", hostname="gateway"))

    sid1 = db.create_scan_session(
        ScanSession(target_input="192.168.1.50", profile="tcp_connect", status="completed", hosts_discovered=1, ports_found=1)
    )
    sid2 = db.create_scan_session(
        ScanSession(target_input="192.168.1.50", profile="tcp_connect", status="completed", hosts_discovered=1, ports_found=2)
    )

    f1 = SecurityFinding(
        asset_id=aid,
        session_id=sid1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet exposed",
        description="",
        recommendation="",
        severity="High",
        risk_score=70.0,
        risk_tier="High",
        status=STATUS_OPEN,
        port_number=23,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-TELNET:tcp:23",
    )
    f2 = SecurityFinding(
        asset_id=aid,
        session_id=sid2,
        rule_id="RULE-EXP-HTTP-CLEAR",
        title="HTTP exposed",
        description="",
        recommendation="",
        severity="Medium",
        risk_score=36.0,
        risk_tier="Medium",
        status=STATUS_OPEN,
        port_number=80,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-HTTP-CLEAR:tcp:80",
    )
    db.upsert_security_finding(f1)
    db.upsert_security_finding(f2)

    db.add_port(Port(asset_id=aid, session_id=sid1, port_number=23, protocol="tcp", state="open"))
    db.add_port(Port(asset_id=aid, session_id=sid2, port_number=80, protocol="tcp", state="open"))

    return db


def test_export_dialog_initialization_and_format_toggle(qapp, reporting_db: DatabaseManager):
    dlg = ExportDialog(db_mgr=reporting_db, session_id=1, target_name="gateway")
    assert dlg.windowTitle().startswith("Export Security Findings")
    assert dlg.radio_html.isChecked()
    assert dlg.path_input.text().endswith(".html")

    # Toggle to CSV
    dlg.radio_csv.setChecked(True)
    assert dlg.path_input.text().endswith(".csv")

    # Toggle to JSON
    dlg.radio_json.setChecked(True)
    assert dlg.path_input.text().endswith(".json")


def test_scan_compare_dialog_headless(qapp, reporting_db: DatabaseManager):
    dlg = ScanCompareDialog(db_mgr=reporting_db)
    assert dlg.windowTitle().startswith("Historical Scan Comparison")
    assert dlg.combo_baseline.count() == 2
    assert dlg.combo_current.count() == 2

    # Run comparison
    dlg.combo_baseline.setCurrentIndex(1)  # Scan 1
    dlg.combo_current.setCurrentIndex(0)   # Scan 2
    dlg.btn_compare.click()

    assert dlg.current_comparison is not None
    assert dlg.btn_export_diff.isEnabled()
    # In Scan 2, HTTP is new
    assert len(dlg.current_comparison.new_findings) == 1
    assert dlg.current_comparison.new_findings[0].rule_id == "RULE-EXP-HTTP-CLEAR"
