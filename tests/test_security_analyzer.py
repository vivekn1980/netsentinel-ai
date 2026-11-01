"""Unit tests for SecurityAnalyzer coordinator and resolution evaluation."""

from __future__ import annotations

import pytest

from netsentinel.core.models import (
    STATUS_NEW,
    STATUS_OPEN,
    DiscoveredHost,
    DiscoveredPort,
    ScanResult,
    SecurityFinding,
)
from netsentinel.core.security_analyzer import SecurityAnalyzer


def test_security_analyzer_analyze_host():
    analyzer = SecurityAnalyzer()
    host = DiscoveredHost(
        ip_address="192.168.1.100",
        hostname="web-db-server",
        status="up",
        ports=[
            DiscoveredPort(port_number=23, protocol="tcp", state="open", service_name="telnet", product="BusyBox telnetd"),
            DiscoveredPort(port_number=3306, protocol="tcp", state="open", service_name="mysql", product="MySQL", version="8.0.32"),
            DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="nginx", version="1.24.0"),
        ],
    )

    findings = analyzer.analyze_host(host, asset_id=42, session_id=10)
    assert len(findings) == 3

    # Check Telnet finding
    telnet_f = next(f for f in findings if f.rule_id == "RULE-EXP-TELNET")
    assert telnet_f.asset_id == 42
    assert telnet_f.session_id == 10
    assert telnet_f.severity == "High"
    assert telnet_f.risk_score == 70.0  # 70 * 1.0 * 1.0 = 70.0
    assert telnet_f.risk_tier == "High"
    assert telnet_f.finding_key == "42:RULE-EXP-TELNET:tcp:23"
    assert "telnet" in telnet_f.evidence.lower()
    assert "CIS Controls" in telnet_f.recommendation

    # Check MySQL finding
    db_f = next(f for f in findings if f.rule_id == "RULE-EXP-DB")
    assert db_f.finding_key == "42:RULE-EXP-DB:tcp:3306"
    assert db_f.severity == "High"

    # Check HTTP finding
    http_f = next(f for f in findings if f.rule_id == "RULE-EXP-HTTP-CLEAR")
    assert http_f.finding_key == "42:RULE-EXP-HTTP-CLEAR:tcp:80"


def test_security_analyzer_host_level_rule():
    analyzer = SecurityAnalyzer()
    open_ports = [DiscoveredPort(port_number=p, protocol="tcp", state="open") for p in range(1000, 1015)]
    host = DiscoveredHost(
        ip_address="10.0.0.99",
        status="up",
        ports=open_ports,
    )

    findings = analyzer.analyze_host(host, asset_id=7, session_id=5)
    broad_f = next((f for f in findings if f.rule_id == "RULE-OBS-BROAD-PORTS"), None)
    assert broad_f is not None
    assert broad_f.finding_key == "7:RULE-OBS-BROAD-PORTS:host"
    assert broad_f.severity == "Medium"
    assert "15 open ports" in broad_f.evidence


def test_resolution_evaluation_verified_closed():
    analyzer = SecurityAnalyzer()

    # Previous active finding: Telnet on port 23
    prior_finding = SecurityFinding(
        id=101,
        asset_id=1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet service observed",
        description="",
        recommendation="",
        severity="High",
        status=STATUS_OPEN,
        port_number=23,
        protocol="tcp",
    )

    # Subsequent successful scan examined port 23 and reports it as closed
    scan_res = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[
            DiscoveredHost(
                ip_address="192.168.1.5",
                status="up",
                ports=[
                    DiscoveredPort(port_number=23, protocol="tcp", state="closed"),
                    DiscoveredPort(port_number=80, protocol="tcp", state="open"),
                ],
            )
        ],
    )

    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_res,
        session_id=12,
        existing_active_findings=[prior_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )

    assert len(resolutions) == 1
    f_res, reason = resolutions[0]
    assert f_res.id == 101
    assert "verified closed in scan session #12" in reason


def test_resolution_not_triggered_on_cancelled_or_failed_scan():
    analyzer = SecurityAnalyzer()
    prior_finding = SecurityFinding(
        id=102,
        asset_id=1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet service observed",
        description="",
        recommendation="",
        severity="High",
        status=STATUS_OPEN,
        port_number=23,
        protocol="tcp",
    )

    # Cancelled scan should NEVER resolve findings
    scan_cancelled = ScanResult(
        success=False,
        was_cancelled=True,
        hosts=[
            DiscoveredHost(
                ip_address="192.168.1.5",
                status="up",
                ports=[DiscoveredPort(port_number=23, protocol="tcp", state="closed")],
            )
        ],
    )

    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_cancelled,
        session_id=13,
        existing_active_findings=[prior_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    assert len(resolutions) == 0


def test_resolution_not_triggered_when_port_was_not_examined():
    analyzer = SecurityAnalyzer()
    prior_finding = SecurityFinding(
        id=103,
        asset_id=1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet service observed",
        description="",
        recommendation="",
        severity="High",
        status=STATUS_OPEN,
        port_number=23,
        protocol="tcp",
    )

    # Scan only checked port 80; port 23 was not examined
    scan_partial = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[
            DiscoveredHost(
                ip_address="192.168.1.5",
                status="up",
                ports=[DiscoveredPort(port_number=80, protocol="tcp", state="open")],
            )
        ],
    )

    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_partial,
        session_id=14,
        existing_active_findings=[prior_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    # Finding must be preserved since evidence is inconclusive
    assert len(resolutions) == 0


def test_resolution_broad_ports_all_reassessed_and_verified_closed():
    """1. All original offending ports reassessed and verified closed -> resolves."""
    analyzer = SecurityAnalyzer()
    broad_finding = SecurityFinding(
        id=104,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Host 192.168.1.5 exposes 13 open ports (1/tcp, 2/tcp, 3/tcp, 4/tcp, 5/tcp, 6/tcp, 7/tcp, 8/tcp, 9/tcp, 10/tcp, 11/tcp, 12/tcp, 13/tcp). [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12,13]",
        severity="Medium",
        status=STATUS_OPEN,
    )

    # Follow-up scan explicitly examines all 13 ports and confirms them closed
    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(1, 14)]
    ports.extend([
        DiscoveredPort(port_number=80, protocol="tcp", state="open"),
        DiscoveredPort(port_number=443, protocol="tcp", state="open"),
    ])
    scan_comp = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_comp,
        session_id=21,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    assert len(resolutions) == 1
    assert "verified closed/filtered" in resolutions[0][1]


def test_resolution_broad_ports_some_unexamined_does_not_resolve():
    """2. Some original offending ports remain unexamined -> does NOT resolve."""
    analyzer = SecurityAnalyzer()
    broad_finding = SecurityFinding(
        id=105,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Host 192.168.1.5 exposes 20 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]",
        severity="Medium",
        status=STATUS_OPEN,
    )

    # Follow-up scan only reassesses 10 ports (1..10) as closed; ports 11..20 unexamined
    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(1, 11)]
    scan_partial = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_partial,
        session_id=22,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    # Must NOT resolve because ports 11..20 remain unexamined
    assert len(resolutions) == 0


def test_resolution_broad_ports_arbitrary_unrelated_ports_scanned_does_not_resolve():
    """3. Arbitrary unrelated ports scanned -> does NOT resolve."""
    analyzer = SecurityAnalyzer()
    broad_finding = SecurityFinding(
        id=106,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Host 192.168.1.5 exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        severity="Medium",
        status=STATUS_OPEN,
    )

    # Follow-up scan tests 15 arbitrary ports (9000..9014), all closed, but NONE of original 1..12
    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(9000, 9015)]
    scan_unrelated = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_unrelated,
        session_id=23,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    # Must NOT resolve from unrelated ports alone
    assert len(resolutions) == 0


def test_resolution_broad_ports_missing_or_malformed_evidence_does_not_resolve():
    """4. Missing or malformed evidence -> does NOT resolve."""
    analyzer = SecurityAnalyzer()
    finding_missing_evidence = SecurityFinding(
        id=107,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="",  # Missing evidence
        severity="Medium",
        status=STATUS_OPEN,
    )
    finding_malformed_evidence = SecurityFinding(
        id=108,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Corrupt malformed garbage with no valid port numbers",
        severity="Medium",
        status=STATUS_OPEN,
    )

    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(1, 20)]
    scan_comp = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_comp,
        session_id=24,
        existing_active_findings=[finding_missing_evidence, finding_malformed_evidence],
        discovered_assets_map={"192.168.1.5": 1},
    )
    assert len(resolutions) == 0


def test_resolution_broad_ports_cancelled_or_incomplete_scan_does_not_resolve():
    """5. Cancelled or incomplete follow-up scan -> does NOT resolve."""
    analyzer = SecurityAnalyzer()
    broad_finding = SecurityFinding(
        id=109,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Host 192.168.1.5 exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        severity="Medium",
        status=STATUS_OPEN,
    )

    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(1, 13)]
    scan_cancelled = ScanResult(
        success=False,
        was_cancelled=True,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_cancelled,
        session_id=25,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    assert len(resolutions) == 0


def test_resolution_broad_ports_original_ports_still_open_does_not_resolve():
    """6. Original offending ports still open -> does NOT resolve."""
    analyzer = SecurityAnalyzer()
    broad_finding = SecurityFinding(
        id=110,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        title="Broad open-port exposure",
        description="",
        recommendation="",
        evidence="Host 192.168.1.5 exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        severity="Medium",
        status=STATUS_OPEN,
    )

    # Ports 1..11 closed, but port 12 is STILL OPEN
    ports = [DiscoveredPort(port_number=p, protocol="tcp", state="closed") for p in range(1, 12)]
    ports.append(DiscoveredPort(port_number=12, protocol="tcp", state="open"))
    scan_with_open = ScanResult(
        success=True,
        was_cancelled=False,
        hosts=[DiscoveredHost(ip_address="192.168.1.5", status="up", ports=ports)],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_with_open,
        session_id=26,
        existing_active_findings=[broad_finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    # Must NOT resolve because port 12 is still open
    assert len(resolutions) == 0


def test_resolution_not_triggered_on_failed_scan():
    analyzer = SecurityAnalyzer()
    finding = SecurityFinding(
        id=105,
        asset_id=1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet service exposed",
        description="",
        recommendation="",
        severity="High",
        status=STATUS_OPEN,
        port_number=23,
    )
    scan_failed = ScanResult(
        success=False,
        error_message="Host unreachable",
        hosts=[],
    )
    resolutions = analyzer.evaluate_finding_resolutions(
        scan_result=scan_failed,
        session_id=22,
        existing_active_findings=[finding],
        discovered_assets_map={"192.168.1.5": 1},
    )
    assert len(resolutions) == 0


def test_analyzer_handles_empty_or_malformed_host():
    analyzer = SecurityAnalyzer()
    # Host with empty ip_address and empty ports
    host = DiscoveredHost(ip_address="", status="down", ports=[])
    findings = analyzer.analyze_host(host=host, asset_id=1, session_id=1)
    assert findings == []

    # Host with port having None/empty values
    host2 = DiscoveredHost(
        ip_address="192.168.1.99",
        status="up",
        ports=[
            DiscoveredPort(port_number=0, protocol="", state="", service_name="", version="")
        ],
    )
    findings2 = analyzer.analyze_host(host=host2, asset_id=2, session_id=1)
    assert isinstance(findings2, list)
