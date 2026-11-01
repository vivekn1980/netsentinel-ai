"""Tests for SQLite DatabaseManager operations and schema constraints."""

from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import pytest

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import Asset, AuditLogEntry, Port, ScanSession, SecurityFinding


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    """Provides a fresh temporary SQLite database."""
    db_file = tmp_path / "test_netsentinel.db"
    return DatabaseManager(db_file)


def test_database_initialization_and_integrity(db: DatabaseManager):
    """Test schema creation and integrity check."""
    assert db.db_path.exists()
    assert db.check_integrity() is True

    # Check WAL mode
    with db.get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.lower() == "wal"


def test_scan_session_crud(db: DatabaseManager):
    """Test inserting, updating, and querying scan sessions."""
    session = ScanSession(
        target_input="192.168.1.0/24",
        profile="tcp_connect",
        status="running",
    )
    sid = db.create_scan_session(session)
    assert sid > 0
    assert session.id == sid

    # Retrieve
    retrieved = db.get_scan_session(sid)
    assert retrieved is not None
    assert retrieved.target_input == "192.168.1.0/24"
    assert retrieved.status == "running"

    # Update
    retrieved.status = "completed"
    retrieved.hosts_discovered = 5
    retrieved.ports_found = 12
    db.update_scan_session(retrieved)

    # Verify update
    updated = db.get_scan_session(sid)
    assert updated.status == "completed"
    assert updated.hosts_discovered == 5
    assert updated.ports_found == 12

    # List
    sessions = db.list_scan_sessions()
    assert len(sessions) == 1
    assert sessions[0].id == sid


def test_asset_and_port_operations(db: DatabaseManager):
    """Test asset upsert, port creation, and foreign key cascades."""
    asset = Asset(
        ip_address="192.168.1.50",
        hostname="gateway.local",
        os_name="Linux 5.15",
        os_accuracy=95,
        risk_level="Medium",
    )
    aid = db.upsert_asset(asset)
    assert aid > 0

    # Add open ports
    port80 = Port(
        asset_id=aid,
        port_number=80,
        protocol="tcp",
        service_name="http",
        product="nginx",
        version="1.24.0",
    )
    db.add_port(port80)

    port443 = Port(
        asset_id=aid,
        port_number=443,
        protocol="tcp",
        service_name="https",
        product="nginx",
        version="1.24.0",
    )
    db.add_port(port443)

    # Check ports for asset
    ports = db.get_ports_for_asset(aid)
    assert len(ports) == 2
    assert [p.port_number for p in ports] == [80, 443]

    # Verify asset open port count calculation
    fetched_asset = db.get_asset(aid)
    assert fetched_asset.open_ports_count == 2
    assert fetched_asset.hostname == "gateway.local"


def test_security_findings_and_metrics(db: DatabaseManager):
    """Test security findings recording and real dashboard metrics calculation."""
    # Empty DB metrics should be zero
    metrics = db.get_dashboard_metrics()
    assert metrics["total_assets"] == 0
    assert metrics["open_ports"] == 0
    assert metrics["total_scans"] == 0
    assert metrics["total_findings"] == 0

    # Insert an asset
    asset = Asset(ip_address="10.0.0.1", hostname="router.lan")
    aid = db.upsert_asset(asset)

    # Insert a finding
    finding = SecurityFinding(
        asset_id=aid,
        severity="High",
        title="Unencrypted Telnet Exposed",
        description="Port 23 is open and running unencrypted cleartext Telnet service.",
        recommendation="Disable Telnet service and migrate to SSH (TCP 22) with key-based authentication.",
    )
    fid = db.add_security_finding(finding)
    assert fid > 0

    # Query findings
    findings = db.list_security_findings()
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].title == "Unencrypted Telnet Exposed"

    # Verify metrics updated with real DB count
    m2 = db.get_dashboard_metrics()
    assert m2["total_assets"] == 1
    assert m2["high_findings"] == 1
    assert m2["total_findings"] == 1


def test_audit_log_recording(db: DatabaseManager):
    """Test audit log creation and query."""
    entry = AuditLogEntry(
        event_type="scan_authorized",
        target="192.168.1.1",
        details="User approved TCP connect scan.",
        user_confirmed=True,
    )
    eid = db.add_audit_log(entry)
    assert eid > 0

    logs = db.list_audit_logs()
    assert len(logs) == 1
    assert logs[0].event_type == "scan_authorized"
    assert logs[0].target == "192.168.1.1"


def test_clear_all_data_success_and_sequence_reset(db: DatabaseManager):
    """Test that clear_all_data removes all records across 5 tables, resets sequence, and vacuums."""
    # Pre-populate all 5 tables
    sid = db.create_scan_session(ScanSession(target_input="10.0.0.1", profile="tcp_connect", status="completed"))
    aid = db.upsert_asset(Asset(ip_address="10.0.0.1", hostname="test.lan"))
    db.add_port(Port(asset_id=aid, session_id=sid, port_number=80, service_name="http"))
    db.add_security_finding(
        SecurityFinding(
            asset_id=aid,
            session_id=sid,
            severity="Low",
            title="Test Finding",
            description="Desc",
            recommendation="Rec",
        )
    )
    db.add_audit_log(AuditLogEntry(event_type="test", target="10.0.0.1", details="Details"))

    # Verify counts before clear
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_sessions;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM assets;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM ports;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM security_findings;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0] == 1

    # Execute complete data clear
    res = db.clear_all_data()
    assert res.records_cleared is True
    assert res.compaction_succeeded is True
    assert res.error is None
    assert res.compaction_error is None

    # Verify all 5 tables are empty
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_sessions;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM assets;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ports;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM security_findings;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0] == 0

        # Check WAL mode is intact
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.lower() == "wal"

    # Integrity check passes
    assert db.check_integrity() is True

    # Next inserted scan session must restart ID counter at 1 (due to sequence reset)
    new_sid = db.create_scan_session(ScanSession(target_input="192.168.1.1", profile="fast_syn", status="completed"))
    assert new_sid == 1


def test_clear_all_data_transaction_rollback_on_failure(db: DatabaseManager, monkeypatch):
    """Test that a failure during the deletion transaction rolls back atomically without orphaned records."""
    aid = db.upsert_asset(Asset(ip_address="192.168.1.10", hostname="rollback.lan"))
    db.add_port(Port(asset_id=aid, port_number=443, service_name="https"))
    db.add_audit_log(AuditLogEntry(event_type="test", target="192.168.1.10", details="Rollback test"))

    original_conn_context = db.get_connection

    # Simulate error halfway through deletion
    class FaultyConnection:
        def __init__(self, real_conn):
            self.real_conn = real_conn
        def execute(self, sql, *args):
            if "DELETE FROM assets" in sql:
                raise sqlite3.OperationalError("Simulated disk error during assets deletion")
            return self.real_conn.execute(sql, *args)
        def __getattr__(self, name):
            return getattr(self.real_conn, name)

    import contextlib
    @contextlib.contextmanager
    def faulty_get_connection():
        with original_conn_context() as conn:
            yield FaultyConnection(conn)

    monkeypatch.setattr(db, "get_connection", faulty_get_connection)

    res = db.clear_all_data()
    assert res.records_cleared is False
    assert "Simulated disk error" in res.error

    # Restore real connection and verify data was rolled back and preserved
    monkeypatch.setattr(db, "get_connection", original_conn_context)
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM assets;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM ports;").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log;").fetchone()[0] == 1

    assert db.check_integrity() is True


def test_clear_all_data_compaction_failure_reported_separately(db: DatabaseManager, monkeypatch):
    """Test that if deletion commits but vacuum fails, compaction error is reported separately."""
    aid = db.upsert_asset(Asset(ip_address="192.168.1.20"))
    db.add_port(Port(asset_id=aid, port_number=22, service_name="ssh"))

    real_sqlite_connect = sqlite3.connect
    class FaultyConnWrapper:
        def __init__(self, c):
            self._c = c
        def execute(self, sql, *args, **kwargs):
            if "VACUUM" in sql:
                raise sqlite3.OperationalError("Simulated vacuum failure (disk full)")
            return self._c.execute(sql, *args, **kwargs)
        def close(self):
            return self._c.close()
        def __getattr__(self, name):
            return getattr(self._c, name)

    def faulty_sqlite_connect(path, *args, **kwargs):
        conn = real_sqlite_connect(path, *args, **kwargs)
        return FaultyConnWrapper(conn)

    # Patch sqlite3.connect in netsentinel.core.database module
    monkeypatch.setattr("netsentinel.core.database.sqlite3.connect", faulty_sqlite_connect)

    res = db.clear_all_data()
    # Records were committed and deleted
    assert res.records_cleared is True
    # Compaction failed and reported separately
    assert res.compaction_succeeded is False
    assert "Simulated vacuum failure" in res.compaction_error

    # Verify tables are still completely cleared
    monkeypatch.setattr(sqlite3, "connect", real_sqlite_connect)
    with db.get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM assets;").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM ports;").fetchone()[0] == 0


def test_concurrency_guard_scan_vs_clear(db: DatabaseManager):
    """Test bidirectional scan vs clear concurrency protection."""
    # 1. Active scan blocks clear_all_data
    assert db.start_scan_operation() is True
    assert db.is_scan_active is True

    res = db.clear_all_data()
    assert res.records_cleared is False
    assert "actively running" in res.error

    db.end_scan_operation()
    assert db.is_scan_active is False

    # 2. Active clear blocks scan startup and session creation
    assert db.acquire_clear_lock() is True
    assert db.is_clearing is True

    assert db.start_scan_operation() is False

    with pytest.raises(RuntimeError, match="database clearing is in progress"):
        db.create_scan_session(ScanSession(target_input="10.0.0.1", profile="tcp_connect", status="running"))

    db.release_clear_lock()
    assert db.is_clearing is False
    assert db.start_scan_operation() is True
    db.end_scan_operation()


def test_scan_session_assets_junction_zero_port_sweep(db: DatabaseManager):
    """Verifies that 0-port discovery scans (e.g. ping sweeps) properly link assets via scan_session_assets."""
    from netsentinel.core.models import DiscoveredHost, ScanResult

    session = ScanSession(target_input="192.168.1.1", profile="ping_sweep", status="running")
    sid = db.create_scan_session(session)
    assert sid > 0
    assert session.process_id > 0

    # Simulate discovery of a host with 0 open ports (ping sweep)
    host = DiscoveredHost(
        ip_address="192.168.1.1",
        hostname="router.local",
        status="up",
        ports=[],
    )
    result = ScanResult(
        success=True,
        hosts=[host],
        elapsed_seconds=1.5,
        nmap_version="7.94",
    )

    db.save_scan_results(sid, result, command_str="nmap -sn 192.168.1.1")

    # Verify session details includes the discovered host
    details = db.get_session_details(sid)
    assert details["session"].status == "completed"
    assert len(details["assets"]) == 1
    assert details["assets"][0]["ip_address"] == "192.168.1.1"
    assert details["assets"][0]["hostname"] == "router.local"
    assert len(details["ports"]) == 0

    # Direct junction table check
    with db.get_connection() as conn:
        junction_rows = conn.execute(
            "SELECT session_id, asset_id FROM scan_session_assets WHERE session_id = ?",
            (sid,),
        ).fetchall()
        assert len(junction_rows) == 1
        asset_id = details["assets"][0]["id"]
        assert junction_rows[0]["asset_id"] == asset_id


def test_scan_session_assets_multi_host_and_repeat_scan(db: DatabaseManager):
    """Verifies junction table correctly associates multiple hosts across multiple scan sessions."""
    from netsentinel.core.models import DiscoveredHost, Port, ScanResult

    # Session 1: discovers Host A and Host B
    s1 = ScanSession(target_input="10.0.0.0/24", profile="quick", status="running")
    sid1 = db.create_scan_session(s1)

    host_a = DiscoveredHost(ip_address="10.0.0.1", hostname="gw", status="up", ports=[Port(port_number=80, service_name="http")])
    host_b = DiscoveredHost(ip_address="10.0.0.2", hostname="dns", status="up", ports=[Port(port_number=53, service_name="domain")])
    res1 = ScanResult(success=True, hosts=[host_a, host_b], elapsed_seconds=2.0)
    db.save_scan_results(sid1, res1)

    # Session 2: discovers Host B and Host C
    s2 = ScanSession(target_input="10.0.0.0/24", profile="deep", status="running")
    sid2 = db.create_scan_session(s2)

    host_c = DiscoveredHost(ip_address="10.0.0.3", hostname="db", status="up", ports=[Port(port_number=5432, service_name="postgresql")])
    res2 = ScanResult(success=True, hosts=[host_b, host_c], elapsed_seconds=3.0)
    db.save_scan_results(sid2, res2)

    # Session 1 should have hosts A and B
    det1 = db.get_session_details(sid1)
    ips1 = {a["ip_address"] for a in det1["assets"]}
    assert ips1 == {"10.0.0.1", "10.0.0.2"}

    # Session 2 should have hosts B and C
    det2 = db.get_session_details(sid2)
    ips2 = {a["ip_address"] for a in det2["assets"]}
    assert ips2 == {"10.0.0.2", "10.0.0.3"}


def test_recover_interrupted_sessions_dead_pid(db: DatabaseManager):
    """Verifies that abandoned sessions with terminated/dead PIDs are recovered to inconclusive."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions (target_input, profile, status, start_time, process_id)
            VALUES ('192.168.1.1', 'quick', 'running', '2026-01-01T00:00:00', 999999);
            """
        )
        sid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]

    # Run recovery assuming current PID is 1111 (not 999999)
    recovered = db.recover_interrupted_sessions(current_pid=1111)
    assert recovered == 1

    session = db.get_scan_session(sid)
    assert session.status == "inconclusive"
    assert "terminated unexpectedly" in session.error_message

    # Verify audit log recorded the recovery
    with db.get_connection() as conn:
        logs = conn.execute(
            "SELECT * FROM audit_log WHERE event_type = 'session_interrupted_recovery';"
        ).fetchall()
        assert len(logs) == 1
        assert f"#{sid}" in logs[0]["details"]


def test_recover_interrupted_sessions_running_pid(db: DatabaseManager, monkeypatch):
    """Verifies that sessions owned by another live PID are NOT touched."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions (target_input, profile, status, start_time, process_id)
            VALUES ('192.168.1.1', 'quick', 'running', '2026-01-01T00:00:00', 88888);
            """
        )
        sid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]

    # Mock is_pid_running to report 88888 is active
    monkeypatch.setattr("netsentinel.core.database.is_pid_running", lambda pid: pid == 88888)

    recovered = db.recover_interrupted_sessions(current_pid=1111)
    assert recovered == 0

    session = db.get_scan_session(sid)
    assert session.status == "running"


def test_database_migration_backfills_scan_session_assets(tmp_path: Path):
    """Verifies that running migrations on a pre-existing database backfills scan_session_assets."""
    db_file = tmp_path / "legacy_netsentinel.db"
    # Create legacy database without scan_session_assets
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        """
        CREATE TABLE scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_input TEXT NOT NULL,
            profile TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            status TEXT NOT NULL,
            command_executed TEXT,
            hosts_discovered INTEGER DEFAULT 0,
            ports_found INTEGER DEFAULT 0,
            risk_summary TEXT,
            duration_seconds REAL DEFAULT 0.0,
            nmap_version TEXT,
            error_message TEXT,
            configured_ports TEXT
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            hostname TEXT,
            mac_address TEXT,
            os_name TEXT,
            os_accuracy INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'Low',
            first_seen TEXT,
            last_seen TEXT
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            session_id INTEGER,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service_name TEXT,
            product TEXT,
            version TEXT,
            risk_note TEXT,
            UNIQUE(asset_id, port_number, protocol)
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE security_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            session_id INTEGER,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT,
            cve_references TEXT,
            timestamp TEXT NOT NULL
        );
        """
    )
    # Insert legacy records
    conn.execute("INSERT INTO scan_sessions (target_input, profile, start_time, status) VALUES ('192.168.1.1', 'quick', '2026-01-01', 'completed');")
    conn.execute("INSERT INTO assets (ip_address, hostname) VALUES ('192.168.1.1', 'legacy-host');")
    conn.execute("INSERT INTO ports (asset_id, session_id, port_number, protocol, state) VALUES (1, 1, 80, 'tcp', 'open');")
    conn.commit()
    conn.close()

    # Open with DatabaseManager which executes initialize() and _run_migrations()
    db_mgr = DatabaseManager(db_file)
    with db_mgr.get_connection() as c:
        rows = c.execute("SELECT session_id, asset_id FROM scan_session_assets;").fetchall()
        assert len(rows) == 1
        assert rows[0]["session_id"] == 1
        assert rows[0]["asset_id"] == 1

        # Check process_id and instance_id columns were added
        cols = [col["name"] for col in c.execute("PRAGMA table_info(scan_sessions);").fetchall()]
        assert "process_id" in cols
        assert "instance_id" in cols


def test_recover_interrupted_sessions_pid_reuse_non_netsentinel(db: DatabaseManager, monkeypatch):
    """Verifies that an abandoned session whose PID was recycled by an unrelated system process is recovered."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions (target_input, profile, status, start_time, process_id, instance_id)
            VALUES ('10.0.0.1', 'quick', 'running', '2026-01-01T10:00:00', 77777, 'other-inst-123');
            """
        )
        sid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]

    # Mock get_process_metadata to report PID 77777 is svchost.exe
    monkeypatch.setattr(
        "netsentinel.core.database.get_process_metadata",
        lambda pid: (True, "svchost.exe", None) if pid == 77777 else (False, None, None),
    )

    recovered = db.recover_interrupted_sessions(current_pid=1111)
    assert recovered == 1

    session = db.get_scan_session(sid)
    assert session.status == "inconclusive"
    assert "reused by non-NetSentinel process" in session.error_message


def test_recover_interrupted_sessions_pid_reuse_newer_instance(db: DatabaseManager, monkeypatch):
    """Verifies that if PID was recycled by a newer NetSentinel instance created after session start, it recovers."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions (target_input, profile, status, start_time, process_id, instance_id)
            VALUES ('10.0.0.1', 'quick', 'running', '2026-01-01T10:00:00', 66666, 'old-inst-999');
            """
        )
        sid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]

    # Creation time: 30 minutes after session start
    session_dt = datetime.fromisoformat("2026-01-01T10:00:00")
    newer_dt = session_dt + timedelta(minutes=30)
    newer_posix = newer_dt.timestamp()
    newer_100ns = int((newer_posix + 11644473600.0) * 10_000_000)

    monkeypatch.setattr(
        "netsentinel.core.database.get_process_metadata",
        lambda pid: (True, "netsentinelai.exe", newer_100ns) if pid == 66666 else (False, None, None),
    )

    recovered = db.recover_interrupted_sessions(current_pid=1111)
    assert recovered == 1

    session = db.get_scan_session(sid)
    assert session.status == "inconclusive"
    assert "reused by newer application instance" in session.error_message


def test_recover_interrupted_sessions_preserves_live_concurrent_netsentinel(db: DatabaseManager, monkeypatch):
    """Verifies that an active scan owned by a live concurrent NetSentinel instance is preserved untouched."""
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_sessions (target_input, profile, status, start_time, process_id, instance_id)
            VALUES ('10.0.0.1', 'quick', 'running', '2026-01-01T10:00:00', 55555, 'concurrent-active-uuid');
            """
        )
        sid = conn.execute("SELECT last_insert_rowid();").fetchone()[0]

    # Process created 5 minutes before session start
    session_dt = datetime.fromisoformat("2026-01-01T10:00:00")
    older_dt = session_dt - timedelta(minutes=5)
    older_posix = older_dt.timestamp()
    older_100ns = int((older_posix + 11644473600.0) * 10_000_000)

    monkeypatch.setattr(
        "netsentinel.core.database.get_process_metadata",
        lambda pid: (True, "netsentinelai.exe", older_100ns) if pid == 55555 else (False, None, None),
    )

    recovered = db.recover_interrupted_sessions(current_pid=1111, current_instance_id="my-own-new-inst")
    assert recovered == 0

    session = db.get_scan_session(sid)
    assert session.status == "running"


def test_database_migration_backfills_single_target_zero_port_discovery(tmp_path: Path):
    """Verifies that historical 0-port discovery scans with matching target IP or hostname are backfilled."""
    db_file = tmp_path / "legacy_discovery.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        """
        CREATE TABLE scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_input TEXT NOT NULL,
            profile TEXT NOT NULL,
            start_time TEXT NOT NULL,
            status TEXT NOT NULL,
            hosts_discovered INTEGER DEFAULT 0
        );
        """
    )
    conn.execute(
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            hostname TEXT DEFAULT '',
            risk_level TEXT DEFAULT 'Low',
            first_seen TEXT DEFAULT '2026-01-01',
            last_seen TEXT DEFAULT '2026-01-01'
        );
        """
    )
    # Insert 0-port discovery scan matching IP
    conn.execute("INSERT INTO scan_sessions (target_input, profile, start_time, status, hosts_discovered) VALUES ('10.20.30.40', 'discovery', '2026-01-01', 'completed', 1);")
    conn.execute("INSERT INTO assets (ip_address, hostname) VALUES ('10.20.30.40', 'host40.local');")
    # Insert 0-port discovery scan matching Hostname
    conn.execute("INSERT INTO scan_sessions (target_input, profile, start_time, status, hosts_discovered) VALUES ('printer.corp.local', 'discovery', '2026-01-01', 'completed', 1);")
    conn.execute("INSERT INTO assets (ip_address, hostname) VALUES ('10.20.30.50', 'printer.corp.local');")
    conn.commit()
    conn.close()

    # Open with DatabaseManager to trigger migration
    db_mgr = DatabaseManager(db_file)
    with db_mgr.get_connection() as c:
        links = c.execute("SELECT session_id, asset_id FROM scan_session_assets ORDER BY session_id;").fetchall()
        assert len(links) == 2
        assert links[0]["session_id"] == 1
        assert links[0]["asset_id"] == 1
        assert links[1]["session_id"] == 2
        assert links[1]["asset_id"] == 2


def test_concurrent_database_manager_instances_live_session_isolation(tmp_path: Path):
    """Verifies that a second DatabaseManager instance never interrupts an active scan of another live instance."""
    import subprocess
    import sys
    import time

    db_file = tmp_path / "concurrent_app.db"

    # Instance 1 runs in a separate process and keeps running
    worker_code = (
        "import sys, time; "
        "from netsentinel.core.database import DatabaseManager, ScanSession; "
        "db = DatabaseManager(sys.argv[1], instance_id='inst-proc-1'); "
        "sid = db.create_scan_session(ScanSession(target_input='192.168.1.1', profile='quick', status='running')); "
        "print(sid, flush=True); "
        "time.sleep(15)"
    )

    proc = subprocess.Popen(
        [sys.executable, "-c", worker_code, str(db_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # Read the session ID created by Instance 1
        stdout_line = proc.stdout.readline()
        sid = int(stdout_line.strip())
        assert sid > 0

        # Instance 2 starts in the current process with its own instance ID
        inst2 = DatabaseManager(db_file, instance_id="inst-proc-2")

        # Instance 2 runs recovery
        recovered = inst2.recover_interrupted_sessions()
        assert recovered == 0

        # Instance 1's scan session MUST remain running
        sess = inst2.get_scan_session(sid)
        assert sess is not None
        assert sess.status == "running"
        assert sess.error_message == ""
    finally:
        # Clean up subprocess
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Now that Instance 1 is confirmed terminated, a subsequent recovery should recover it
    recovered_after = inst2.recover_interrupted_sessions()
    assert recovered_after == 1
    sess_after = inst2.get_scan_session(sid)
    assert sess_after.status == "inconclusive"
    assert "terminated unexpectedly" in sess_after.error_message


def test_repeat_scan_foreign_key_integrity_and_returning_id(db: DatabaseManager):
    """Verifies that repeat scans against existing assets do not fail with FOREIGN KEY constraint failed.
    
    Ensures that RETURNING id correctly resolves asset and port IDs on ON CONFLICT DO UPDATE
    rather than stale cursor.lastrowid from preceding junction table inserts.
    """
    from netsentinel.core.models import DiscoveredHost, DiscoveredPort, ScanResult

    # Session 1: Discovers 3 hosts
    s1 = ScanSession(target_input="192.168.1.0/24", profile="Host Discovery Ping Sweep (-sn)", status="running")
    sid1 = db.create_scan_session(s1)
    res1 = ScanResult(
        success=True,
        hosts=[
            DiscoveredHost(ip_address="192.168.1.1", hostname="router.local", status="up"),
            DiscoveredHost(ip_address="192.168.1.10", hostname="phone.local", status="up"),
            DiscoveredHost(ip_address="192.168.1.15", hostname="desktop.local", status="up", ports=[
                DiscoveredPort(port_number=445, protocol="tcp", state="open", service_name="microsoft-ds")
            ]),
        ],
    )
    db.save_scan_results(sid1, res1)

    details1 = db.get_session_details(sid1)
    assert len(details1["assets"]) == 3
    assert len(details1["ports"]) == 1

    # Session 2: Repeat scan on same subnet with overlapping existing hosts and 1 new host
    s2 = ScanSession(target_input="192.168.1.0/24", profile="Host Discovery Ping Sweep (-sn)", status="running")
    sid2 = db.create_scan_session(s2)
    res2 = ScanResult(
        success=True,
        hosts=[
            DiscoveredHost(ip_address="192.168.1.1", hostname="router.local", status="up"),
            DiscoveredHost(ip_address="192.168.1.10", hostname="phone.local", status="up"),
            DiscoveredHost(ip_address="192.168.1.15", hostname="desktop.local", status="up", ports=[
                DiscoveredPort(port_number=445, protocol="tcp", state="open", service_name="microsoft-ds")
            ]),
            DiscoveredHost(ip_address="192.168.1.20", hostname="printer.local", status="up"),
        ],
    )
    # This must complete cleanly without FOREIGN KEY constraint failed
    db.save_scan_results(sid2, res2)

    details2 = db.get_session_details(sid2)
    assert len(details2["assets"]) == 4
    assert len(details2["ports"]) == 1

    # Verify upsert_asset returns stable ID on update
    a1 = db.get_asset_by_ip("192.168.1.1")
    assert a1 is not None
    orig_id = a1.id
    updated_id = db.upsert_asset(a1)
    assert updated_id == orig_id

    # Verify upsert_port returns stable ID on update
    ports = db.get_ports_for_asset(details2["assets"][0]["id"])
    if not ports:
        # Check desktop asset
        desktop_asset = [a for a in details2["assets"] if a["ip_address"] == "192.168.1.15"][0]
        ports = db.get_ports_for_asset(desktop_asset["id"])
    assert len(ports) >= 1
    p = ports[0]
    p_orig_id = p.id
    p_updated_id = db.add_port(p)
    assert p_updated_id == p_orig_id
