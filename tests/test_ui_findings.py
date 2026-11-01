"""Headless UI tests for FindingsView and FindingDetailDialog."""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from PySide6.QtWidgets import QApplication

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    Asset,
    STATUS_ACKNOWLEDGED,
    STATUS_NEW,
    SecurityFinding,
)
from netsentinel.ui.views.findings_view import FindingDetailDialog, FindingsView


@pytest.fixture(scope="session")
def qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    return DatabaseManager(tmp_path / "ui_test.db")


def test_findings_view_initialization_and_filtering(qapp, test_db: DatabaseManager):
    aid = test_db.upsert_asset(Asset(ip_address="192.168.1.20", hostname="file-server"))

    f1 = SecurityFinding(
        asset_id=aid,
        severity="High",
        title="Telnet service observed",
        description="Cleartext protocol",
        recommendation="Use SSH",
        rule_id="RULE-EXP-TELNET",
        confidence=1.0,
        risk_score=70.0,
        risk_tier="High",
        status=STATUS_NEW,
        port_number=23,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-TELNET:tcp:23",
    )
    f2 = SecurityFinding(
        asset_id=aid,
        severity="Medium",
        title="HTTP service observed",
        description="Cleartext web server",
        recommendation="Use HTTPS",
        rule_id="RULE-EXP-HTTP-CLEAR",
        confidence=0.9,
        risk_score=36.0,
        risk_tier="Medium",
        status=STATUS_ACKNOWLEDGED,
        port_number=80,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-HTTP-CLEAR:tcp:80",
    )
    test_db.upsert_security_finding(f1)
    test_db.upsert_security_finding(f2)

    view = FindingsView(db_mgr=test_db)
    assert view.stack.currentIndex() == 1  # Not empty
    assert len(view.all_findings) == 2

    # Test Severity Filter UI reaction
    view.severity_filter.setCurrentText("High")
    assert view.cards_layout.count() >= 1

    # Test Search Query reaction
    view.severity_filter.setCurrentText("All Severities")
    view.search_input.setText("file-server")
    assert view.cards_layout.count() >= 2

    view.search_input.setText("nonexistent_host_query")
    assert view.stack.currentIndex() == 0  # Empty state triggered


def test_finding_detail_dialog_headless(qapp, test_db: DatabaseManager):
    aid = test_db.upsert_asset(Asset(ip_address="192.168.1.30"))
    finding = SecurityFinding(
        asset_id=aid,
        severity="High",
        title="Telnet service observed",
        description="Test description",
        recommendation="Test recommendation",
        rule_id="RULE-EXP-TELNET",
        rule_version="1.0",
        confidence=1.0,
        risk_score=70.0,
        risk_tier="High",
        scoring_explanation="Base: 70 * 1.0 * 1.0 = 70.0",
        evidence="Port 23 open",
        status=STATUS_NEW,
        port_number=23,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-TELNET:tcp:23",
    )
    fid = test_db.upsert_security_finding(finding)
    finding.id = fid

    dialog = FindingDetailDialog(finding=finding, db_mgr=test_db)
    assert dialog.windowTitle().startswith("Finding Details")
    assert dialog.finding.status == STATUS_NEW


def test_finding_detail_dialog_status_transition(qapp, test_db: DatabaseManager, monkeypatch):
    from PySide6.QtWidgets import QInputDialog, QMessageBox

    aid = test_db.upsert_asset(Asset(ip_address="192.168.1.35"))
    finding = SecurityFinding(
        asset_id=aid,
        severity="High",
        title="FTP service observed",
        description="Cleartext FTP",
        recommendation="Use SFTP",
        rule_id="RULE-EXP-FTP",
        confidence=1.0,
        risk_score=70.0,
        risk_tier="High",
        evidence="Port 21 open",
        status=STATUS_NEW,
        port_number=21,
        protocol="tcp",
        finding_key=f"{aid}:RULE-EXP-FTP:tcp:21",
    )
    fid = test_db.upsert_security_finding(finding)
    finding.id = fid

    callback_called = False

    def on_changed():
        nonlocal callback_called
        callback_called = True

    dialog = FindingDetailDialog(finding=finding, db_mgr=test_db, on_status_changed_cb=on_changed)

    monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Risk accepted for legacy scanner", True))
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)

    dialog.btn_ack.click()

    assert callback_called is True
    assert dialog.finding.status == STATUS_ACKNOWLEDGED
    updated = test_db.get_security_finding(fid)
    assert updated.status == STATUS_ACKNOWLEDGED
    assert "Risk accepted for legacy scanner" in updated.user_notes
