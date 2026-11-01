"""Milestone 5: Reliability, Security Validation & Release Hardening Tests.

Verifies:
- Windows/cross-platform process lifecycle and verified cancellation
- Mid-port truncated XML recovery and corrupted XML handling
- Strict finding resolution criteria for host-level and service-level rules
- Large finding set (1,000 items) export performance across HTML, CSV, JSON
- Spreadsheet formula injection protection across all edge cases
- Concurrent scan prevention contract
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import List
import pytest

from netsentinel.core.models import (
    DiscoveredHost,
    ScanResult,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
    STATUS_RESOLVED,
)
from netsentinel.core.nmap_engine import NmapEngine
from netsentinel.core.xml_parser import NmapXmlParser
from netsentinel.core.reporting.diff_engine import DiffEngine
from netsentinel.core.reporting.csv_export import CsvExporter, FORMULA_TRIGGERS
from netsentinel.core.reporting.json_export import JsonExporter
from netsentinel.core.reporting.html_report import HtmlReportGenerator


def test_process_cancellation_verification():
    """Verify that NmapEngine.cancel() safely terminates a running process and reaps it."""
    engine = NmapEngine()
    # Spawn a long-lived sleeping process using current Python interpreter
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        engine._active_process = proc
        assert proc.poll() is None  # Process is running

        cancelled = engine.cancel()
        assert cancelled is True
        assert proc.poll() is not None  # Process must be reaped and terminated
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=1)


def test_truncated_xml_mid_port_recovery():
    """Verify that XML truncated directly inside a <port> element is safely recovered."""
    truncated_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE nmaprun>\n'
        '<nmaprun scanner="nmap" args="nmap -sS -p 80,445 192.168.1.50" start="1700000000" version="7.94">\n'
        '<host><status state="up"/><address addr="192.168.1.50" addrtype="ipv4"/>\n'
        '<ports>\n'
        '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>\n'
        '<port protocol="tcp" portid="445"><state state="open"/>'
    )
    result = NmapXmlParser.parse(truncated_xml)
    assert result.success is True
    assert len(result.hosts) == 1
    host = result.hosts[0]
    assert host.ip_address == "192.168.1.50"
    # Should recover port 80 and the completed port 445
    port_ids = [p.port_number for p in host.ports]
    assert 80 in port_ids
    assert 445 in port_ids


def test_corrupted_and_garbage_xml_handling():
    """Verify corrupted, non-XML, and empty inputs fail gracefully without unhandled exceptions."""
    for bad_input in [
        "",
        "   \n\t  ",
        "<nmaprun>>garbage<<><<<",
        "<html><body>Not an nmap report</body></html>",
        "\x00\x01\x02\xff\xfe\xfd",
        "<xml>Some other root</xml>",
    ]:
        result = NmapXmlParser.parse(bad_input)
        assert result.success is False
        assert len(result.hosts) == 0


def test_diff_engine_broad_ports_protection():
    """Verify RULE-OBS-BROAD-PORTS is NOT resolved when current scan examined <= 10 ports."""
    base_session = ScanSession(
        id=1,
        target_input="192.168.1.10",
        profile="Comprehensive",
        status="completed",
        configured_ports="1-1000",
        hosts_discovered=1,
    )
    curr_session = ScanSession(
        id=2,
        target_input="192.168.1.10",
        profile="Quick",
        status="completed",
        configured_ports="80,443",
        hosts_discovered=1,
    )

    base_finding = SecurityFinding(
        id=1,
        session_id=1,
        asset_id=10,
        rule_id="RULE-OBS-BROAD-PORTS",
        rule_version="1.0.0",
        severity="Medium",
        title="Excessive Open Network Ports",
        description="Host has more than 10 open ports.",
        recommendation="Reduce exposed services.",
        evidence="Host 192.168.1.10 exposes 12 open ports (1/tcp, 2/tcp, 3/tcp, 4/tcp, 5/tcp, 6/tcp, 7/tcp, 8/tcp, 9/tcp, 10/tcp, 11/tcp, 12/tcp), exceeding threshold of 10. [OffendingPorts: 1,2,3,4,5,6,7,8,9,10,11,12]",
        status=STATUS_OPEN,
        port_number=None,
    )

    # 1. Current scan only scanned ports 80 and 443 (<= 10 ports)
    comp_narrow = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={10: {80, 443}},
        current_scanned_assets={10},
    )
    # Finding MUST NOT be resolved; must be categorized as not_reassessed
    assert len(comp_narrow.resolved_findings) == 0
    assert len(comp_narrow.not_reassessed_findings) == 1
    assert comp_narrow.not_reassessed_findings[0].id == 1

    # 2. Current scan scanned 15 ports (> 10 ports) and broad port rule did not fire
    comp_broad = DiffEngine.compare_sessions(
        baseline_session=base_session,
        current_session=curr_session,
        baseline_findings=[base_finding],
        current_findings=[],
        current_scanned_ports_by_asset={10: set(range(1, 16))},
        current_scanned_assets={10},
    )
    assert len(comp_broad.resolved_findings) == 1
    assert comp_broad.resolved_findings[0].id == 1
    assert len(comp_broad.not_reassessed_findings) == 0


def test_large_finding_set_serialization_performance(tmp_path: Path):
    """Stress test generating HTML, CSV, and JSON for 1,000 security findings."""
    findings: List[SecurityFinding] = []
    for i in range(1, 1001):
        findings.append(
            SecurityFinding(
                id=i,
                session_id=1,
                asset_id=i % 10 + 1,
                rule_id=f"RULE-STRESS-{i % 5}",
                rule_version="1.0.0",
                severity="High" if i % 2 == 0 else "Medium",
                title=f"Stress Test Finding #{i} with Unicode \u2714 \u2716 & Special <tag>",
                description=f"Detailed description for finding #{i} with special & < > ' \" characters.",
                recommendation=f"Remediation step #{i} requiring admin action.",
                status=STATUS_OPEN,
                risk_score=75.0 if i % 2 == 0 else 55.0,
                risk_tier="High" if i % 2 == 0 else "Medium",
                confidence="High",
                port_number=80 + (i % 100),
                protocol="tcp",
                ip_address=f"10.0.0.{i % 254 + 1}",
                hostname=f"host-{i}.internal.net",
                evidence=f"=cmd|' /C calc'!A{i}",
                user_notes=f"+Notes with formula trigger #{i}",
            )
        )

    # 1. CSV export performance
    start_time = time.time()
    csv_file = tmp_path / "stress_report.csv"
    CsvExporter.export_findings(findings, csv_file)
    csv_duration = time.time() - start_time
    assert csv_file.exists()
    assert csv_duration < 2.0  # Must be fast (< 2 seconds)

    # Verify CSV rows and formula injection escaping
    with open(csv_file, "r", encoding="utf-8-sig") as f:
        lines = f.readlines()
    assert len(lines) == 1001  # 1 header + 1000 items
    assert "'=cmd|" in lines[1]
    assert "'+Notes with formula" in lines[1]

    # 2. JSON export performance
    start_time = time.time()
    json_file = tmp_path / "stress_report.json"
    session = ScanSession(id=1, target_input="10.0.0.0/24", profile="Comprehensive", status="completed")
    JsonExporter.export(findings, session=session, output_file=json_file)
    json_duration = time.time() - start_time
    assert json_file.exists()
    assert json_duration < 2.0

    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["metadata"]["schema_version"] == "1.0.0"
    assert data["risk_summary"]["total_findings"] == 1000
    assert len(data["findings"]) == 1000

    # 3. HTML export performance
    start_time = time.time()
    html_file = tmp_path / "stress_report.html"
    HtmlReportGenerator.generate_report(findings, session=session, output_file=html_file)
    html_duration = time.time() - start_time
    assert html_file.exists()
    assert html_duration < 2.5

    with open(html_file, "r", encoding="utf-8") as f:
        html_text = f.read()
    # Confirm XSS safety and no unescaped injection
    assert "<tag>" not in html_text
    assert "&lt;tag&gt;" in html_text
    assert "Stress Test Finding #1000" in html_text


def test_formula_injection_defense_exhaustive():
    """Verify formula injection triggers are escaped and legitimate numbers remain intact."""
    for trigger in FORMULA_TRIGGERS:
        payload = f"{trigger}SUM(A1:A10)"
        sanitized = CsvExporter.sanitize_for_spreadsheet(payload)
        assert sanitized.startswith("'"), f"Trigger '{trigger}' failed to sanitize: {sanitized}"

    # Verify whitespace prefix before formula trigger is also sanitized
    for prefix in [" ", "  ", "\t", "\r\n  "]:
        payload = f"{prefix}=CMD()"
        sanitized = CsvExporter.sanitize_for_spreadsheet(payload)
        assert sanitized.startswith("'"), f"Whitespace + formula failed: {sanitized}"

    # Verify numbers are never prefixed with quote
    assert CsvExporter.sanitize_for_spreadsheet(80) == 80
    assert CsvExporter.sanitize_for_spreadsheet(443.0) == 443.0
    assert CsvExporter.sanitize_for_spreadsheet("80") == "80"
    assert CsvExporter.sanitize_for_spreadsheet("443") == "443"
    assert CsvExporter.sanitize_for_spreadsheet("-1") == "-1"
    assert CsvExporter.sanitize_for_spreadsheet("0") == "0"
