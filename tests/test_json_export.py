"""Unit tests for versioned JSON export (Schema 1.0.0)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from netsentinel.core.models import (
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
    STATUS_RESOLVED,
)
from netsentinel.core.reporting.json_export import SCHEMA_VERSION, JsonExporter


def test_json_export_structure_and_schema(tmp_path: Path):
    session = ScanSession(
        id=10,
        target_input="192.168.1.0/24",
        profile="tcp_connect",
        status="completed",
        command_executed="nmap -sT 192.168.1.0/24",
        hosts_discovered=2,
        ports_found=4,
        duration_seconds=12.4,
        configured_ports="22,80,443",
    )

    finding = SecurityFinding(
        id=101,
        asset_id=5,
        rule_id="RULE-EXP-HTTP-CLEAR",
        rule_version="1.0",
        title="Cleartext HTTP service observed",
        description="Port 80 cleartext protocol",
        recommendation="Enable TLS",
        severity="Medium",
        risk_score=36.0,
        risk_tier="Medium",
        confidence=0.9,
        scoring_explanation="Base: 40 * 0.9 * 1.0 = 36.0",
        status=STATUS_OPEN,
        port_number=80,
        protocol="tcp",
        evidence="HTTP/1.1 200 OK",
        ip_address="192.168.1.15",
        hostname="intranet.local",
    )

    out_file = tmp_path / "test_export.json"
    json_str = JsonExporter.export(
        findings=[finding],
        session=session,
        output_file=out_file,
    )

    data = json.loads(json_str)

    # 1. Metadata verification
    assert data["metadata"]["schema_version"] == SCHEMA_VERSION
    assert data["metadata"]["generator"] == "NetSentinel AI"
    assert "export_timestamp" in data["metadata"]
    assert data["metadata"]["storage_mode"] in ("portable", "standard")

    # 2. Risk summary verification
    assert data["risk_summary"]["total_findings"] == 1
    assert data["risk_summary"]["active_findings"] == 1
    assert data["risk_summary"]["max_risk_score"] == 36.0
    assert data["risk_summary"]["severity_distribution"]["Medium"] == 1

    # 3. Scan context verification
    assert data["scan_context"]["session_id"] == 10
    assert data["scan_context"]["target_input"] == "192.168.1.0/24"
    assert data["scan_context"]["completion_status"] == "Completed for configured scope"
    assert data["scan_context"]["configured_ports"] == "22,80,443"

    # 4. Findings array verification
    assert len(data["findings"]) == 1
    f_item = data["findings"][0]
    assert f_item["finding_id"] == 101
    assert f_item["rule_id"] == "RULE-EXP-HTTP-CLEAR"
    assert f_item["asset"]["ip_address"] == "192.168.1.15"
    assert f_item["network_target"]["port_number"] == 80


def test_json_export_with_comparison_payload(tmp_path: Path):
    f_new = SecurityFinding(id=1, asset_id=1, rule_id="RULE-EXP-TELNET", severity="High", risk_score=70.0, status=STATUS_OPEN, title="Telnet", description="", recommendation="")
    f_res = SecurityFinding(id=2, asset_id=1, rule_id="RULE-EXP-FTP", severity="High", risk_score=70.0, status=STATUS_RESOLVED, title="FTP", description="", recommendation="")

    comp = ScanComparisonResult(
        baseline_session_id=1,
        current_session_id=2,
        baseline_target="10.0.0.1",
        current_target="10.0.0.1",
        new_findings=[f_new],
        resolved_findings=[f_res],
        persistent_findings=[],
        not_reassessed_findings=[],
        has_scope_limitations=False,
    )

    json_str = JsonExporter.export(
        findings=[f_new],
        comparison_result=comp,
    )
    data = json.loads(json_str)

    assert "historical_comparison" in data
    assert data["historical_comparison"]["baseline_session_id"] == 1
    assert data["historical_comparison"]["current_session_id"] == 2
    assert data["historical_comparison"]["counts"]["new"] == 1
    assert data["historical_comparison"]["counts"]["resolved"] == 1
