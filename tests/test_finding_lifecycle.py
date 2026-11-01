"""Unit tests for SecurityFinding database persistence, deduplication, and lifecycle management."""

from __future__ import annotations

from pathlib import Path
import pytest

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    Asset,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_RESOLVED,
    ScanSession,
    SecurityFinding,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_lifecycle.db"
    return DatabaseManager(db_file)


def test_finding_upsert_and_user_status_preservation(temp_db: DatabaseManager):
    # 1. Create asset and scan sessions
    asset = Asset(ip_address="192.168.1.15", hostname="nas-storage")
    asset_id = temp_db.upsert_asset(asset)

    sid1 = temp_db.create_scan_session(ScanSession(target_input="192.168.1.15"))
    sid2 = temp_db.create_scan_session(ScanSession(target_input="192.168.1.15"))

    # 2. First scan creates a Telnet finding
    finding1 = SecurityFinding(
        asset_id=asset_id,
        session_id=sid1,
        severity="High",
        title="Telnet service observed",
        description="Telnet listener exposed",
        recommendation="Disable telnet",
        rule_id="RULE-EXP-TELNET",
        confidence=1.0,
        risk_score=70.0,
        risk_tier="High",
        evidence="Port 23/tcp is open",
        status=STATUS_NEW,
        port_number=23,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-TELNET:tcp:23",
    )
    fid1 = temp_db.upsert_security_finding(finding1)
    assert fid1 > 0
    saved = temp_db.get_security_finding(fid1)
    assert saved.status == STATUS_NEW
    assert saved.finding_key == f"{asset_id}:RULE-EXP-TELNET:tcp:23"

    # 3. Operator acknowledges the finding
    success = temp_db.update_finding_status(
        finding_id=fid1,
        new_status=STATUS_ACKNOWLEDGED,
        notes="Risk accepted: internal isolated lab network",
        user_confirmed=True,
    )
    assert success is True
    saved_ack = temp_db.get_security_finding(fid1)
    assert saved_ack.status == STATUS_ACKNOWLEDGED
    assert "Risk accepted" in saved_ack.user_notes

    # Verify audit log entry was written
    logs = temp_db.list_audit_logs()
    assert any(log.event_type == "finding_status_changed" and f"finding:{fid1}" in log.target for log in logs)

    # 4. Second scan discovers the same Telnet service again
    finding2 = SecurityFinding(
        asset_id=asset_id,
        session_id=sid2,  # New session
        severity="High",
        title="Telnet service observed",
        description="Telnet listener exposed",
        recommendation="Disable telnet",
        rule_id="RULE-EXP-TELNET",
        confidence=1.0,
        risk_score=70.0,
        risk_tier="High",
        evidence="Port 23/tcp is open (scan 2)",
        status=STATUS_NEW,
        port_number=23,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-TELNET:tcp:23",
    )
    fid2 = temp_db.upsert_security_finding(finding2)
    assert fid2 == fid1  # Same identity deduplicated

    # CRITICAL: Operator's 'Acknowledged' status MUST be strictly preserved!
    rechecked = temp_db.get_security_finding(fid1)
    assert rechecked.status == STATUS_ACKNOWLEDGED
    assert rechecked.session_id == sid2  # Updated to latest session
    assert "scan 2" in rechecked.evidence


def test_false_positive_preservation(temp_db: DatabaseManager):
    asset_id = temp_db.upsert_asset(Asset(ip_address="10.0.0.2"))
    sid1 = temp_db.create_scan_session(ScanSession(target_input="10.0.0.2"))
    sid2 = temp_db.create_scan_session(ScanSession(target_input="10.0.0.2"))

    finding = SecurityFinding(
        asset_id=asset_id,
        session_id=sid1,
        severity="Medium",
        title="Administrative interface observed",
        description="",
        recommendation="",
        rule_id="RULE-EXP-ADMIN",
        port_number=5900,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-ADMIN:tcp:5900",
    )
    fid = temp_db.upsert_security_finding(finding)

    # Operator marks as False Positive
    temp_db.update_finding_status(fid, STATUS_FALSE_POSITIVE, notes="Approved internal test runner")
    assert temp_db.get_security_finding(fid).status == STATUS_FALSE_POSITIVE

    # Re-scan occurs
    finding_rescan = SecurityFinding(
        asset_id=asset_id,
        session_id=sid2,
        severity="Medium",
        title="Administrative interface observed",
        description="",
        recommendation="",
        rule_id="RULE-EXP-ADMIN",
        port_number=5900,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-ADMIN:tcp:5900",
    )
    temp_db.upsert_security_finding(finding_rescan)
    assert temp_db.get_security_finding(fid).status == STATUS_FALSE_POSITIVE


def test_resolved_finding_reopening(temp_db: DatabaseManager):
    asset_id = temp_db.upsert_asset(Asset(ip_address="10.0.0.3"))
    sid1 = temp_db.create_scan_session(ScanSession(target_input="10.0.0.3"))
    sid2 = temp_db.create_scan_session(ScanSession(target_input="10.0.0.3"))

    finding = SecurityFinding(
        asset_id=asset_id,
        session_id=sid1,
        severity="High",
        title="FTP service observed",
        description="",
        recommendation="",
        rule_id="RULE-EXP-FTP",
        port_number=21,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-FTP:tcp:21",
    )
    fid = temp_db.upsert_security_finding(finding)

    # Mark as Resolved
    temp_db.update_finding_status(fid, STATUS_RESOLVED, notes="FTP disabled on host")
    assert temp_db.get_security_finding(fid).status == STATUS_RESOLVED

    # Later scan re-observes FTP service -> Automatically reopened to Open
    finding_reobserved = SecurityFinding(
        asset_id=asset_id,
        session_id=sid2,
        severity="High",
        title="FTP service observed",
        description="",
        recommendation="",
        rule_id="RULE-EXP-FTP",
        port_number=21,
        protocol="tcp",
        finding_key=f"{asset_id}:RULE-EXP-FTP:tcp:21",
    )
    temp_db.upsert_security_finding(finding_reobserved)
    reopened = temp_db.get_security_finding(fid)
    assert reopened.status == STATUS_OPEN
    assert "Reopened" in reopened.user_notes

    # Verify audit log recorded finding_reopened
    logs = temp_db.list_audit_logs()
    assert any(log.event_type == "finding_reopened" and f"finding:{fid}" in log.target for log in logs)


def test_invalid_status_transition_rejected(temp_db: DatabaseManager):
    asset_id = temp_db.upsert_asset(Asset(ip_address="10.0.0.4"))
    sid = temp_db.create_scan_session(ScanSession(target_input="10.0.0.4"))

    finding = SecurityFinding(
        asset_id=asset_id,
        session_id=sid,
        severity="Low",
        title="SSH service exposed",
        description="",
        recommendation="",
        rule_id="RULE-EXP-SSH",
        status=STATUS_FALSE_POSITIVE,
        finding_key=f"{asset_id}:RULE-EXP-SSH:host",
    )
    fid = temp_db.upsert_security_finding(finding)

    # False Positive cannot transition directly to Resolved
    with pytest.raises(ValueError):
        temp_db.update_finding_status(fid, STATUS_RESOLVED, notes="Direct transition illegal")


def test_list_findings_filtering_and_metrics(temp_db: DatabaseManager):
    aid = temp_db.upsert_asset(Asset(ip_address="172.16.0.10", hostname="gateway.corp"))
    sid = temp_db.create_scan_session(ScanSession(target_input="172.16.0.10"))

    # Add findings of various severities and statuses
    f1 = SecurityFinding(
        asset_id=aid,
        session_id=sid,
        severity="Critical",
        risk_score=95.0,
        risk_tier="Critical",
        title="SMBv1 Legacy Protocol",
        description="",
        recommendation="",
        rule_id="RULE-OBS-LEGACY-VERSION",
        status=STATUS_NEW,
        finding_key=f"{aid}:RULE-OBS-LEGACY-VERSION:tcp:445",
    )
    f2 = SecurityFinding(
        asset_id=aid,
        session_id=sid,
        severity="High",
        risk_score=70.0,
        risk_tier="High",
        title="Database Listener",
        description="",
        recommendation="",
        rule_id="RULE-EXP-DB",
        status=STATUS_ACKNOWLEDGED,
        finding_key=f"{aid}:RULE-EXP-DB:tcp:3306",
    )
    f3 = SecurityFinding(
        asset_id=aid,
        session_id=sid,
        severity="Medium",
        risk_score=40.0,
        risk_tier="Medium",
        title="HTTP Cleartext",
        description="",
        recommendation="",
        rule_id="RULE-EXP-HTTP-CLEAR",
        status=STATUS_RESOLVED,
        finding_key=f"{aid}:RULE-EXP-HTTP-CLEAR:tcp:80",
    )

    temp_db.upsert_security_finding(f1)
    temp_db.upsert_security_finding(f2)
    temp_db.upsert_security_finding(f3)

    # Test severity filter
    crit_list = temp_db.list_security_findings(severity="Critical")
    assert len(crit_list) == 1
    assert crit_list[0].title == "SMBv1 Legacy Protocol"

    # Test status filter
    ack_list = temp_db.list_security_findings(status=STATUS_ACKNOWLEDGED)
    assert len(ack_list) == 1
    assert ack_list[0].title == "Database Listener"

    # Test search query
    search_list = temp_db.list_security_findings(search_term="gateway.corp")
    assert len(search_list) == 3

    # Test dashboard aggregation metrics
    metrics = temp_db.get_dashboard_metrics()
    assert metrics["critical_findings"] == 1
    assert metrics["high_findings"] == 1
    assert metrics["medium_findings"] == 1
    assert metrics["tier_critical"] == 1
    assert metrics["active_findings"] == 1  # Only f1 is New
    assert metrics["acknowledged_findings"] == 1  # f2
    assert metrics["resolved_findings"] == 1  # f3
    assert metrics["total_findings"] == 3
