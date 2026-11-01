"""Unit tests for ScanWorker lifecycle, signals, and cancellation."""

import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock

# Offscreen Qt for testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication

from netsentinel.core.config import ConfigManager
from netsentinel.core.database import DatabaseManager
from netsentinel.core.dependencies import NmapReadinessState, NmapVerificationResult
from netsentinel.core.nmap_engine import NmapEngine, NmapExecutionResult
from netsentinel.core.scan_worker import ScanWorker
from netsentinel.ui.main_window import MainWindow


SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" startstr="Sat Oct 31 06:00:00 2026">
<host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="test-host.local" type="user"/></hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.24"/>
        </port>
    </ports>
</host>
<runstats><finished elapsed="1.5"/></runstats>
</nmaprun>
"""


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    yield app


def test_scan_worker_successful_lifecycle(qapp, tmp_path: Path):
    """Test full background worker lifecycle state transitions and persistence."""
    db_file = tmp_path / "worker_test.db"
    db_mgr = DatabaseManager(db_file)

    # Mock NmapEngine
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.is_available = True
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.version = "Nmap 7.94"
    mock_engine.build_args.return_value = ["nmap", "-sT", "192.168.1.10"]
    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=True,
        command=["nmap", "-sT", "192.168.1.10"],
        xml_output=SAMPLE_XML,
        duration_seconds=1.5,
        nmap_version="Nmap 7.94",
    )

    worker = ScanWorker(
        target="192.168.1.10",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))

    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    # Run synchronously in test
    worker.run()

    # Verify lifecycle states sequence
    assert "VALIDATING" in states
    assert "AUTHORIZED" in states
    assert "RUNNING" in states
    assert "PARSING" in states
    assert "SAVING" in states
    assert "COMPLETED" in states

    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert success is True
    assert session_id > 0
    assert len(res.hosts) == 1
    assert res.hosts[0].ip_address == "192.168.1.10"

    # Verify database was updated
    session = db_mgr.get_scan_session(session_id)
    assert session.status == "completed"
    assert session.hosts_discovered == 1
    assert session.ports_found == 1


def test_scan_worker_invalid_target(qapp, tmp_path: Path):
    """Test worker rejects invalid targets immediately with session ID 0 and no DB records."""
    db_mgr = DatabaseManager(tmp_path / "invalid_target.db")
    worker = ScanWorker(
        target="192.168.1.1; whoami",
        profile="tcp_connect",
        db_mgr=db_mgr,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "FAILED" in states
    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert session_id == 0
    assert success is False
    assert "Security Alert" in msg
    assert len(db_mgr.list_scan_sessions()) == 0


def test_scan_worker_cancellation(qapp, tmp_path: Path):
    """Test worker handles cancellation cleanly."""
    db_mgr = DatabaseManager(tmp_path / "cancel_test.db")

    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.is_available = True
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.version = "Nmap 7.94"
    mock_engine.build_args.return_value = ["nmap", "-sT", "192.168.1.1"]
    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=False,
        command=["nmap", "-sT", "192.168.1.1"],
        xml_output="<nmaprun></nmaprun>",
        was_cancelled=True,
        duration_seconds=2.0,
    )

    worker = ScanWorker(
        target="192.168.1.1",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "CANCELLED" in states
    assert len(finish_results) == 1
    assert finish_results[0][1] is False
    assert "cancelled" in finish_results[0][2].lower()

    # Session in DB must be cancelled, not failed or completed
    session = db_mgr.get_scan_session(finish_results[0][0])
    assert session.status == "cancelled"


def test_scan_worker_preflight_missing_engine_emits_zero_and_no_db(qapp, tmp_path: Path):
    """Verify preflight failure when Nmap is missing emits session ID 0 and creates no DB session."""
    db_mgr = DatabaseManager(tmp_path / "preflight_missing.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.MISSING
    mock_engine.is_available = False
    mock_engine.verification_result = NmapVerificationResult(
        state=NmapReadinessState.MISSING,
        error_message="Nmap executable not found.",
    )

    worker = ScanWorker(
        target="192.168.1.1",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "FAILED" in states
    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert session_id == 0
    assert success is False
    assert "Nmap discovery engine executable not found" in msg
    assert len(db_mgr.list_scan_sessions()) == 0
    assert len(db_mgr.list_security_findings()) == 0


def test_scan_worker_preflight_launch_error_emits_zero_and_no_db(qapp, tmp_path: Path):
    """Verify preflight failure on launch error emits session ID 0 and creates no DB session."""
    db_mgr = DatabaseManager(tmp_path / "preflight_launch.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.LAUNCH_ERROR
    mock_engine.is_available = True
    mock_engine.verification_result = NmapVerificationResult(
        state=NmapReadinessState.LAUNCH_ERROR,
        error_message="Executable timed out during version probe ('nmap.exe -V').",
    )

    worker = ScanWorker(
        target="10.0.0.1",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))
    worker.run()

    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert session_id == 0
    assert success is False
    assert "failed to launch" in msg
    assert len(db_mgr.list_scan_sessions()) == 0


def test_scan_worker_preflight_data_files_missing_emits_zero_and_no_db(qapp, tmp_path: Path):
    """Verify preflight failure on missing data files emits session ID 0 and creates no DB session."""
    db_mgr = DatabaseManager(tmp_path / "preflight_data.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.DATA_FILES_MISSING
    mock_engine.is_available = True
    mock_engine.verification_result = NmapVerificationResult(
        state=NmapReadinessState.DATA_FILES_MISSING,
        error_message="Required data file 'nmap-services' is missing.",
    )

    worker = ScanWorker(
        target="10.0.0.1",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))
    worker.run()

    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert session_id == 0
    assert success is False
    assert "incomplete" in msg.lower()
    assert len(db_mgr.list_scan_sessions()) == 0


def test_main_window_status_bar_formats_preflight_failure_cleanly(qapp, tmp_path: Path):
    """Verify MainWindow formats unstarted scans as 'Scan failed to start' without negative or zero session."""
    cfg = ConfigManager(explicit_data_dir=tmp_path / "ui_data")
    db = DatabaseManager(cfg.db_file)
    window = MainWindow(cfg, db)

    # Simulate preflight failure finished callback
    err_msg = "Nmap discovery engine executable not found."
    window._on_scan_finished(session_id=0, success=False, message=err_msg, scan_result=None)

    status_text = window.statusBar.currentMessage()
    assert status_text.startswith("⚠️ Scan failed to start:")
    assert err_msg in status_text
    assert "Scan #0" not in status_text
    assert "Scan #-1" not in status_text

    window.close()


def test_enrich_hostnames_fallback():
    """Verify _enrich_hostnames populates empty hostnames and resolves localhost to system hostname."""
    import socket
    from netsentinel.core.models import DiscoveredHost, ScanResult

    res = ScanResult(
        success=True,
        hosts=[
            DiscoveredHost(ip_address="127.0.0.1", hostname="kubernetes.docker.internal"),
            DiscoveredHost(ip_address="192.168.1.15", hostname=""),
            DiscoveredHost(ip_address="8.8.8.8", hostname="dns.google"),
        ],
    )

    ScanWorker._enrich_hostnames(res)

    # 127.0.0.1 replaced with machine hostname and native OS
    assert res.hosts[0].hostname == socket.gethostname()
    assert res.hosts[0].os_name != ""
    assert res.hosts[0].os_accuracy == 100
    # 192.168.1.15 is on local machine so enriched with hostname & OS
    assert res.hosts[1].hostname == socket.gethostname()
    assert res.hosts[1].os_name != ""
    # Preserves existing valid non-docker hostnames
    assert res.hosts[2].hostname == "dns.google"


def test_scan_worker_exception_recovery_terminates_engine_and_fails_db_session(qapp, tmp_path: Path):
    """Verifies that unexpected worker exceptions cancel child processes, update DB session to failed, and emit scan_finished once."""
    db_file = tmp_path / "crash_recovery_test.db"
    db_mgr = DatabaseManager(db_file)

    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.is_available = True
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.version = "Nmap 7.94"
    mock_engine.build_args.return_value = ["nmap", "-sT", "192.168.1.10"]
    # Simulate unexpected crash during scanner execution
    mock_engine.execute_scan.side_effect = RuntimeError("Simulated scanner crash during execution")

    worker = ScanWorker(
        target="192.168.1.10",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    # 1. State must transition to FAILED
    assert "FAILED" in states

    # 2. Child engine cancel() must be invoked
    assert mock_engine.cancel.called

    # 3. scan_finished must be emitted exactly once
    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert success is False
    assert session_id > 0
    assert "Simulated scanner crash" in msg

    # 4. Database session must NOT remain running (ghost session avoided)
    session = db_mgr.get_scan_session(session_id)
    assert session is not None
    assert session.status == "failed"
    assert "Simulated scanner crash" in session.error_message
    assert session.end_time != ""

    # 5. Scan operation lock must be released
    assert db_mgr.is_scan_active is False


def test_scan_worker_exception_before_session_creation(qapp, tmp_path: Path, monkeypatch):
    """Verifies that crashes occurring before session creation emit session 0 and leave DB clean."""
    db_file = tmp_path / "pre_session_crash.db"
    db_mgr = DatabaseManager(db_file)

    # Monkeypatch TargetValidator.validate to raise unexpected error
    monkeypatch.setattr(
        "netsentinel.core.scan_worker.TargetValidator.validate",
        MagicMock(side_effect=TypeError("Unexpected type error in validator")),
    )

    worker = ScanWorker(
        target="192.168.1.10",
        profile="tcp_connect",
        db_mgr=db_mgr,
    )

    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert len(finish_results) == 1
    session_id, success, msg, res = finish_results[0]
    assert session_id == 0
    assert success is False
    assert "Unexpected type error" in msg
    assert len(db_mgr.list_scan_sessions()) == 0
    assert db_mgr.is_scan_active is False


def test_scan_worker_safe_emit_finished_idempotence(qapp, tmp_path: Path):
    """Verifies _safe_emit_finished emits scan_finished only once even if called multiple times."""
    db_mgr = DatabaseManager(tmp_path / "idempotence.db")
    worker = ScanWorker(target="127.0.0.1", profile="quick", db_mgr=db_mgr)

    emissions = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: emissions.append(sid))

    worker._safe_emit_finished(1, True, "Done 1", None)
    worker._safe_emit_finished(1, False, "Done 2", None)
    worker._safe_emit_finished(0, False, "Done 3", None)

    assert len(emissions) == 1
    assert emissions[0] == 1


def test_scan_worker_saving_exception_marks_db_session_failed(qapp, tmp_path: Path):
    """Verifies that an exception during save_scan_results marks the DB session failed rather than running."""
    db_file = tmp_path / "saving_crash.db"
    db_mgr = DatabaseManager(db_file)

    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True
    mock_engine.version = "7.95"
    mock_engine.build_args.return_value = ["nmap", "-sT", "192.168.1.1"]

    valid_xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.95">
      <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host>
    </nmaprun>
    """
    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=True,
        command=["nmap", "-sT", "192.168.1.1"],
        stdout="done",
        stderr="",
        xml_output=valid_xml,
        duration_seconds=1.2,
        was_cancelled=False,
        error_message="",
        nmap_version="7.95",
    )

    # Monkeypatch save_scan_results to raise an exception
    orig_save = db_mgr.save_scan_results
    call_count = [0]
    def mock_save(*args, **kwargs):
        call_count[0] += 1
        raise RuntimeError("Simulated DB write failure during saving")

    db_mgr.save_scan_results = mock_save

    worker = ScanWorker(
        target="192.168.1.1",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "FAILED" in states
    assert len(finish_results) == 1
    sid, succ, msg, res = finish_results[0]
    assert succ is False
    assert "Simulated DB write failure" in msg

    # Verify DB session was marked as failed
    session = db_mgr.get_scan_session(sid)
    assert session is not None
    assert session.status == "failed"
    assert "Simulated DB write failure" in session.error_message
    assert session.end_time != ""
    assert db_mgr.is_scan_active is False


def test_scan_worker_incomplete_scan_never_resolves_findings(qapp, tmp_path: Path):
    """Verifies that cancelled or failed scans never resolve existing active security findings."""
    db_file = tmp_path / "finding_safety.db"
    db_mgr = DatabaseManager(db_file)

    # Insert an asset with an active high finding
    from netsentinel.core.models import Asset, SecurityFinding, STATUS_NEW
    aid = db_mgr.upsert_asset(Asset(ip_address="192.168.1.50", hostname="srv.local"))
    fid = db_mgr.upsert_security_finding(
        SecurityFinding(
            asset_id=aid,
            severity="High",
            title="Exposed Database Port",
            description="MySQL port 3306 is reachable without authentication.",
            recommendation="Restrict firewall access.",
            status=STATUS_NEW,
            rule_id="RULE_DATABASE_EXPOSURE",
            finding_key="192.168.1.50:3306:tcp:RULE_DATABASE_EXPOSURE",
        )
    )

    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True
    mock_engine.version = "7.95"
    mock_engine.build_args.return_value = ["nmap", "-sT", "192.168.1.50"]
    # Engine execution fails / cancelled
    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=False,
        command=["nmap", "-sT", "192.168.1.50"],
        stdout="",
        stderr="Scan aborted",
        xml_output="",
        duration_seconds=0.5,
        was_cancelled=True,
        error_message="Scan cancelled by user.",
        nmap_version="7.95",
    )

    worker = ScanWorker(
        target="192.168.1.50",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )
    worker.run()

    # The finding MUST remain in status New
    findings = db_mgr.list_security_findings()
    assert len(findings) == 1
    assert findings[0].status == STATUS_NEW


def test_scan_worker_rejects_dns_scope_overflow_before_execution(qapp, tmp_path: Path, monkeypatch):
    """Verifies that DNS resolving to >65,536 hosts halts worker with session 0 before scanner execution."""
    db_mgr = DatabaseManager(tmp_path / "dns_overflow.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True

    # Monkeypatch resolve_dns_target to simulate 70,000 addresses
    monkeypatch.setattr(
        "netsentinel.core.validator.TargetValidator.resolve_dns_target",
        MagicMock(side_effect=ValueError("Hostname 'overflow.corp' resolved to 70,000 IP addresses, exceeding maximum permitted scope of 65,536 hosts.")),
    )

    worker = ScanWorker(
        target="overflow.corp",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "FAILED" in states
    assert len(finish_results) == 1
    sid, succ, msg, res = finish_results[0]
    assert sid == 0
    assert succ is False
    assert "exceeding maximum permitted scope" in msg
    # Verify Nmap scanner was NEVER executed
    mock_engine.execute_scan.assert_not_called()
    assert len(db_mgr.list_scan_sessions()) == 0


def test_scan_worker_rejects_dns_failure_before_execution(qapp, tmp_path: Path, monkeypatch):
    """Verifies that DNS failure halts worker with session 0 before scanner execution."""
    db_mgr = DatabaseManager(tmp_path / "dns_failure.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True

    monkeypatch.setattr(
        "netsentinel.core.validator.TargetValidator.resolve_dns_target",
        MagicMock(side_effect=ValueError("DNS resolution failed for 'badhost.invalid': [Errno 11001] getaddrinfo failed")),
    )

    worker = ScanWorker(
        target="badhost.invalid",
        profile="tcp_connect",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "FAILED" in states
    assert len(finish_results) == 1
    sid, succ, msg, res = finish_results[0]
    assert sid == 0
    assert succ is False
    assert "DNS resolution failed" in msg
    mock_engine.execute_scan.assert_not_called()
    assert len(db_mgr.list_scan_sessions()) == 0


def test_scan_worker_host_discovery_zero_ports_persists_asset(qapp, tmp_path: Path):
    """Regression test: Host discovery finding a host with 0 open ports persists asset and scan_session_assets."""
    db_mgr = DatabaseManager(tmp_path / "host_disc_zero_ports.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True
    mock_engine.version = "7.80"
    mock_engine.build_args.return_value = ["nmap", "-sn", "-T3", "192.168.1.16"]

    xml_with_zero_ports = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.80" startstr="Sun Nov 01 10:29:11 2026">
    <host>
        <status state="up" reason="arp-response" reason_ttl="0"/>
        <address addr="192.168.1.16" addrtype="ipv4"/>
        <address addr="BC:D2:2C:1B:24:C0" addrtype="mac"/>
        <hostnames/>
    </host>
    <runstats><finished elapsed="1.31" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
    </nmaprun>"""

    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=True,
        command=["nmap", "-sn", "-T3", "192.168.1.16"],
        stdout=xml_with_zero_ports,
        stderr="",
        xml_output=xml_with_zero_ports,
        duration_seconds=1.31,
        was_cancelled=False,
        error_message="",
        nmap_version="7.80",
    )

    worker = ScanWorker(
        target="192.168.1.16",
        profile="ping_sweep",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "COMPLETED" in states
    assert len(finish_results) == 1
    sid, succ, msg, res = finish_results[0]
    assert sid > 0
    assert succ is True
    assert "1 host(s) discovered" in msg

    # Verify session in DB
    session = db_mgr.get_scan_session(sid)
    assert session.status == "completed"
    assert session.hosts_discovered == 1
    assert session.ports_found == 0

    # Verify asset was persisted
    asset = db_mgr.get_asset_by_ip("192.168.1.16")
    assert asset is not None
    assert asset.mac_address == "BC:D2:2C:1B:24:C0"

    # Verify scan_session_assets junction table contains the link
    with db_mgr.get_connection() as conn:
        links = conn.execute("SELECT * FROM scan_session_assets WHERE session_id = ?;", (sid,)).fetchall()
        assert len(links) == 1
        assert links[0]["asset_id"] == asset.id


def test_scan_worker_host_discovery_zero_hosts_marked_completed_not_failed(qapp, tmp_path: Path):
    """Regression test: Successful scan discovering 0 hosts is marked completed, not failed."""
    db_mgr = DatabaseManager(tmp_path / "zero_hosts.db")
    mock_engine = MagicMock(spec=NmapEngine)
    mock_engine.readiness_state = NmapReadinessState.READY_STANDARD
    mock_engine.is_available = True
    mock_engine.version = "7.80"
    mock_engine.build_args.return_value = ["nmap", "-sn", "-T3", "192.168.1.99"]

    empty_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.80" startstr="Sun Nov 01 10:29:14 2026">
    <runstats><finished elapsed="3.03" exit="success"/><hosts up="0" down="1" total="1"/></runstats>
    </nmaprun>"""

    mock_engine.execute_scan.return_value = NmapExecutionResult(
        success=True,
        command=["nmap", "-sn", "-T3", "192.168.1.99"],
        stdout=empty_xml,
        stderr="",
        xml_output=empty_xml,
        duration_seconds=3.03,
        was_cancelled=False,
        error_message="",
        nmap_version="7.80",
    )

    worker = ScanWorker(
        target="192.168.1.99",
        profile="ping_sweep",
        db_mgr=db_mgr,
        engine=mock_engine,
    )

    states = []
    worker.state_changed.connect(lambda s: states.append(s))
    finish_results = []
    worker.scan_finished.connect(lambda sid, succ, msg, res: finish_results.append((sid, succ, msg, res)))

    worker.run()

    assert "COMPLETED" in states
    assert "FAILED" not in states
    assert len(finish_results) == 1
    sid, succ, msg, res = finish_results[0]
    assert sid > 0
    assert succ is True
    assert "0 host(s) discovered" in msg

    session = db_mgr.get_scan_session(sid)
    assert session.status == "completed"
    assert session.hosts_discovered == 0
    assert len(db_mgr.list_assets()) == 0





