"""Unit tests for ReportGenerator coordinator and export audit logging."""

from __future__ import annotations

from pathlib import Path
import pytest

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    Asset,
    Port,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
    STATUS_RESOLVED,
)
from netsentinel.core.reporting.report_generator import ReportGenerator


@pytest.fixture
def generator_db(tmp_path: Path) -> DatabaseManager:
    db = DatabaseManager(tmp_path / "gen_test.db")
    aid = db.upsert_asset(Asset(ip_address="192.168.1.10", hostname="workstation-1"))
    sid = db.create_scan_session(
        ScanSession(
            target_input="192.168.1.10",
            profile="tcp_connect",
            status="completed",
            hosts_discovered=1,
            ports_found=1,
            duration_seconds=5.2,
        )
    )
    f = SecurityFinding(
        asset_id=aid,
        session_id=sid,
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
    db.upsert_security_finding(f)
    return db


def test_report_generator_html_csv_json_and_audit(generator_db: DatabaseManager, tmp_path: Path):
    generator = ReportGenerator(generator_db)

    # 1. HTML generation
    html_path = tmp_path / "out_report.html"
    res_html = generator.generate_html_report(session_id=1, output_path=html_path)
    assert res_html.exists()
    assert res_html.stat().st_size > 0

    # 2. CSV generation
    csv_path = tmp_path / "out_report.csv"
    res_csv = generator.export_findings_csv(output_path=csv_path, session_id=1)
    assert res_csv.exists()
    assert res_csv.stat().st_size > 0

    # 3. JSON generation
    json_path = tmp_path / "out_report.json"
    res_json = generator.export_findings_json(output_path=json_path, session_id=1)
    assert res_json.exists()
    assert res_json.stat().st_size > 0

    # 4. Verify audit log recorded "report_exported" events
    logs = generator_db.list_audit_logs()
    export_logs = [log for log in logs if log.event_type == "report_exported"]
    assert len(export_logs) == 3
    targets = [l.target for l in export_logs]
    assert "file:out_report.html" in targets
    assert "file:out_report.csv" in targets
    assert "file:out_report.json" in targets
