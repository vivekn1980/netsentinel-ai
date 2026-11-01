"""Unit tests for DiffEngine historical scan comparison and resolution verification."""

from __future__ import annotations

import pytest

from netsentinel.core.models import (
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_FAILED,
    ScanSession,
    SecurityFinding,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
    STATUS_OPEN,
    STATUS_RESOLVED,
)
from netsentinel.core.reporting.diff_engine import DiffEngine


def test_diff_stable_identity_matching():
    f1 = SecurityFinding(id=1, asset_id=10, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="")
    f2 = SecurityFinding(id=2, asset_id=10, rule_id="RULE-OBS-BROAD-PORTS", protocol="tcp", port_number=None, severity="Medium", risk_score=40.0, status=STATUS_OPEN, title="Broad Ports", description="", recommendation="")

    assert DiffEngine.get_finding_key(f1) == "10:RULE-EXP-TELNET:tcp:23"
    assert DiffEngine.get_finding_key(f2) == "10:RULE-OBS-BROAD-PORTS:host"


def test_diff_categories_new_persistent_and_resolved():
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    # Baseline has Telnet (port 23) and FTP (port 21)
    f_telnet = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")
    f_ftp = SecurityFinding(id=2, asset_id=1, rule_id="RULE-EXP-FTP", protocol="tcp", port_number=21, severity="High", risk_score=70.0, status=STATUS_OPEN, title="FTP", description="", recommendation="", finding_key="1:RULE-EXP-FTP:tcp:21")

    # Current has Telnet (port 23) persistent, HTTP (port 80) new, and FTP was closed
    f_telnet_curr = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")
    f_http_curr = SecurityFinding(id=3, asset_id=1, rule_id="RULE-EXP-HTTP-CLEAR", protocol="tcp", port_number=80, severity="Medium", risk_score=36.0, status=STATUS_OPEN, title="HTTP", description="", recommendation="", finding_key="1:RULE-EXP-HTTP-CLEAR:tcp:80")

    # Current scan actively probed ports 21, 23, and 80 on asset 1
    scanned_ports = {1: {21, 23, 80}}
    scanned_assets = {1}

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[f_telnet, f_ftp],
        current_findings=[f_telnet_curr, f_http_curr],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets=scanned_assets,
    )

    assert len(result.new_findings) == 1
    assert result.new_findings[0].rule_id == "RULE-EXP-HTTP-CLEAR"

    assert len(result.persistent_findings) == 1
    assert result.persistent_findings[0].rule_id == "RULE-EXP-TELNET"

    assert len(result.resolved_findings) == 1
    assert result.resolved_findings[0].rule_id == "RULE-EXP-FTP"

    assert len(result.not_reassessed_findings) == 0


def test_diff_omitted_port_is_not_resolved():
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    # Current session only scanned port 80 (-p 80)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", configured_ports="80", hosts_discovered=1)

    f_telnet = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")

    # Current scan only examined port 80, NOT port 23
    scanned_ports = {1: {80}}
    scanned_assets = {1}

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[f_telnet],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets=scanned_assets,
    )

    # CRITICAL: Since port 23 was omitted, it MUST NOT be marked resolved!
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1
    assert result.not_reassessed_findings[0].rule_id == "RULE-EXP-TELNET"


def test_diff_cancelled_or_failed_scan_does_not_resolve_findings():
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_cancelled = ScanSession(id=2, target_input="192.168.1.1", status="cancelled", hosts_discovered=1)

    f_telnet = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_cancelled,
        baseline_findings=[f_telnet],
        current_findings=[],
        current_scanned_ports_by_asset={1: {23}},
        current_scanned_assets={1},
    )

    # Cancelled scan cannot resolve anything
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1
    assert result.has_scope_limitations is True
    assert result.assessment_completeness == ASSESSMENT_STATUS_CANCELLED


def test_diff_reopened_finding_detection():
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    # In baseline, Telnet was resolved
    f_telnet_base = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_RESOLVED, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")
    # In current scan, Telnet is re-detected
    f_telnet_curr = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", protocol="tcp", port_number=23, severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="", finding_key="1:RULE-EXP-TELNET:tcp:23")

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[f_telnet_base],
        current_findings=[f_telnet_curr],
        current_scanned_ports_by_asset={1: {23}},
        current_scanned_assets={1},
    )

    assert len(result.reopened_findings) == 1
    assert result.reopened_findings[0].rule_id == "RULE-EXP-TELNET"
    assert len(result.new_findings) == 0


def test_diff_broad_ports_all_reassessed_and_verified_closed():
    """1. All original offending ports reassessed and verified closed -> resolves."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    base_finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="Host exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    scanned_ports = {1: set(range(1, 13))}
    port_states = {1: {p: "closed" for p in range(1, 13)}}

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets={1},
        current_port_states_by_asset=port_states,
    )
    assert len(result.resolved_findings) == 1
    assert len(result.not_reassessed_findings) == 0


def test_diff_broad_ports_some_unexamined_does_not_resolve():
    """2. Some original offending ports remain unexamined -> does NOT resolve."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    base_finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="Host exposes 20 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    # Only 10 of 20 ports examined
    scanned_ports = {1: set(range(1, 11))}
    port_states = {1: {p: "closed" for p in range(1, 11)}}

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets={1},
        current_port_states_by_asset=port_states,
    )
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1


def test_diff_broad_ports_arbitrary_unrelated_ports_scanned_does_not_resolve():
    """3. Arbitrary unrelated ports scanned -> does NOT resolve."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    base_finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="Host exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    # 15 unrelated ports scanned (9000..9014)
    scanned_ports = {1: set(range(9000, 9015))}
    port_states = {1: {p: "closed" for p in range(9000, 9015)}}

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets={1},
        current_port_states_by_asset=port_states,
    )
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1


def test_diff_broad_ports_missing_or_malformed_evidence_does_not_resolve():
    """4. Missing or malformed evidence -> does NOT resolve."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    finding_missing = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    scanned_ports = {1: set(range(1, 25))}
    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[finding_missing],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets={1},
    )
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1


def test_diff_broad_ports_cancelled_or_incomplete_scan_does_not_resolve():
    """5. Cancelled or incomplete follow-up scan -> does NOT resolve."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_cancelled = ScanSession(id=2, target_input="192.168.1.1", status="cancelled", hosts_discovered=1)

    base_finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="Host exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_cancelled,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={1: set(range(1, 13))},
        current_scanned_assets={1},
    )
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1


def test_diff_broad_ports_original_ports_still_open_does_not_resolve():
    """6. Original offending ports still open -> does NOT resolve."""
    base_session = ScanSession(id=1, target_input="192.168.1.1", status="completed", hosts_discovered=1)
    curr_session = ScanSession(id=2, target_input="192.168.1.1", status="completed", hosts_discovered=1)

    base_finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-OBS-BROAD-PORTS",
        protocol="tcp",
        severity="Medium",
        title="Excessive Open Ports",
        description="",
        recommendation="",
        evidence="Host exposes 12 open ports. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        status=STATUS_OPEN,
        finding_key="1:RULE-OBS-BROAD-PORTS:host",
    )

    scanned_ports = {1: set(range(1, 13))}
    # Port 12 is still "open"
    port_states = {1: {p: "closed" for p in range(1, 12)}}
    port_states[1][12] = "open"

    result = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset=scanned_ports,
        current_scanned_assets={1},
        current_port_states_by_asset=port_states,
    )
    assert len(result.resolved_findings) == 0
    assert len(result.not_reassessed_findings) == 1
