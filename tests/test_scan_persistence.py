"""Unit tests for SQLite scan result persistence, asset deduplication, and migrations."""

from pathlib import Path
import sqlite3
import pytest

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import DiscoveredHost, DiscoveredPort, ScanResult, ScanSession


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    return DatabaseManager(tmp_path / "test_persistence.db")


def test_save_scan_results_end_to_end(db: DatabaseManager):
    """Test full persistence of parsed ScanResult into SQLite."""
    # Create initial pending session
    session = ScanSession(
        target_input="192.168.1.0/24",
        profile="tcp_connect",
        status="running",
    )
    sid = db.create_scan_session(session)

    # Mock scan result
    h1 = DiscoveredHost(
        ip_address="192.168.1.10",
        hostname="server.local",
        mac_address="00:11:22:33:44:55",
        os_name="Ubuntu Linux",
        os_accuracy=90,
        ports=[
            DiscoveredPort(port_number=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH"),
            DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="nginx"),
            DiscoveredPort(port_number=443, protocol="tcp", state="closed"),
        ],
    )
    result = ScanResult(
        success=True,
        hosts=[h1],
        elapsed_seconds=5.25,
        nmap_version="7.94",
    )

    db.save_scan_results(sid, result, command_str="nmap -sT 192.168.1.0/24")

    # Verify session update
    updated_session = db.get_scan_session(sid)
    assert updated_session.status == "completed"
    assert updated_session.hosts_discovered == 1
    assert updated_session.ports_found == 2  # 2 open ports
    assert updated_session.duration_seconds == 5.25
    assert updated_session.nmap_version == "7.94"

    # Verify asset created
    asset = db.get_asset_by_ip("192.168.1.10")
    assert asset is not None
    assert asset.hostname == "server.local"
    assert asset.mac_address == "00:11:22:33:44:55"
    assert asset.open_ports_count == 2

    # Verify ports saved
    ports = db.get_ports_for_asset(asset.id)
    assert len(ports) == 3
    port_nums = {p.port_number for p in ports}
    assert port_nums == {22, 80, 443}


def test_asset_deduplication(db: DatabaseManager):
    """Verify that multiple scans updating the same IP do not create duplicate assets."""
    s1 = db.create_scan_session(ScanSession(target_input="10.0.0.5", status="running"))

    # First scan: host found with no hostname
    r1 = ScanResult(
        success=True,
        hosts=[DiscoveredHost(ip_address="10.0.0.5", hostname="")],
        elapsed_seconds=1.0,
    )
    db.save_scan_results(s1, r1)

    assert len(db.list_assets()) == 1
    initial_asset = db.get_asset_by_ip("10.0.0.5")
    assert initial_asset.hostname == ""

    # Second scan: same IP discovered later with hostname and OS
    s2 = db.create_scan_session(ScanSession(target_input="10.0.0.5", status="running"))
    r2 = ScanResult(
        success=True,
        hosts=[DiscoveredHost(
            ip_address="10.0.0.5",
            hostname="nas.corp",
            os_name="FreeBSD",
            os_accuracy=95,
        )],
        elapsed_seconds=2.0,
    )
    db.save_scan_results(s2, r2)

    # Must still be exactly 1 asset, but updated
    assets = db.list_assets()
    assert len(assets) == 1
    updated_asset = db.get_asset_by_ip("10.0.0.5")
    assert updated_asset.id == initial_asset.id
    assert updated_asset.hostname == "nas.corp"
    assert updated_asset.os_name == "FreeBSD"


def test_get_session_details(db: DatabaseManager):
    """Verify retrieval of detailed session report for inspect dialog."""
    sid = db.create_scan_session(ScanSession(target_input="172.16.1.1", status="running"))
    h = DiscoveredHost(
        ip_address="172.16.1.1",
        hostname="firewall",
        ports=[DiscoveredPort(port_number=443, state="open", service_name="https")],
    )
    db.save_scan_results(sid, ScanResult(success=True, hosts=[h]))

    details = db.get_session_details(sid)
    assert details["session"].id == sid
    assert len(details["ports"]) == 1
    assert details["ports"][0]["port_number"] == 443
    assert details["ports"][0]["ip_address"] == "172.16.1.1"


def test_schema_migration_on_legacy_db(tmp_path: Path):
    """Test non-destructive migration on a legacy database without Milestone 2 columns."""
    legacy_db_file = tmp_path / "legacy.db"

    # Create legacy table manually without duration_seconds, nmap_version, error_message
    conn = sqlite3.connect(str(legacy_db_file))
    conn.execute(
        """
        CREATE TABLE scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_input TEXT NOT NULL,
            profile TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            status TEXT NOT NULL,
            command_executed TEXT DEFAULT '',
            hosts_discovered INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0,
            risk_summary TEXT DEFAULT ''
        )
        """
    )
    conn.execute("INSERT INTO scan_sessions (target_input, profile, start_time, status) VALUES ('1.1.1.1', 'tcp', 'now', 'completed')")
    conn.commit()
    conn.close()

    # Initialize DatabaseManager on legacy file to trigger migration
    mgr = DatabaseManager(legacy_db_file)
    assert mgr.check_integrity() is True

    # Check migrated row preserves old data
    sessions = mgr.list_scan_sessions()
    assert len(sessions) == 1
    assert sessions[0].target_input == "1.1.1.1"
    assert sessions[0].duration_seconds == 0.0


def test_schema_migration_m3_findings(tmp_path: Path):
    """Test non-destructive migration on a legacy database without Milestone 3 finding columns."""
    legacy_db_file = tmp_path / "legacy_m2.db"

    # Create legacy table manually matching Milestone 1/2 schema without M3 columns
    conn = sqlite3.connect(str(legacy_db_file))
    conn.execute(
        """
        CREATE TABLE security_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            session_id INTEGER,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            cve_references TEXT DEFAULT '',
            timestamp TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        INSERT INTO security_findings (severity, title, description, recommendation, timestamp)
        VALUES ('High', 'Legacy Finding', 'Pre-M3 description', 'Pre-M3 recommendation', '2026-01-01T00:00:00')
        """
    )
    conn.commit()
    conn.close()

    # Initialize DatabaseManager to trigger M3 ALTER TABLE migrations
    mgr = DatabaseManager(legacy_db_file)
    assert mgr.check_integrity() is True

    # Check migrated row preserves historical data while having defaults for M3 fields
    findings = mgr.list_security_findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "Legacy Finding"
    assert f.severity == "High"
    assert f.rule_id == ""
    assert f.risk_score == 0.0
    assert f.status == "New"
