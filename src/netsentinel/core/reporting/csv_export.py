"""RFC 4180 compliant CSV export with spreadsheet formula injection protection.

Exports NetSentinel AI security findings with UTF-8 BOM encoding for Excel,
stable column ordering, unicode preservation, and defensive cell sanitization.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from netsentinel.core.models import SecurityFinding

CSV_COLUMNS = [
    "finding_id",
    "rule_id",
    "title",
    "severity",
    "risk_score",
    "risk_tier",
    "confidence",
    "status",
    "asset_ip",
    "hostname",
    "port",
    "protocol",
    "service",
    "evidence",
    "remediation",
    "first_seen",
    "last_seen",
    "user_notes",
]

# Triggers for CSV formula injection in spreadsheet applications (Excel, Calc)
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
NUMERIC_REGEX = re.compile(r"^-?\d+(\.\d+)?$")


class CsvExporter:
    """Exports findings to RFC 4180 CSV with injection protection and UTF-8 BOM."""

    @staticmethod
    def sanitize_for_spreadsheet(value: Any) -> Any:
        """Sanitizes text cells against spreadsheet formula injection without corrupting numeric fields.
        
        If a text field begins with =, +, -, @, Tab, or Carriage Return (even after leading whitespace),
        prefixes with a single quote (') to instruct spreadsheets to treat it as a literal string.
        """
        if value is None:
            return ""

        # Preserve genuine numeric types
        if isinstance(value, (int, float)):
            return value

        val_str = str(value)
        if not val_str:
            return ""

        # Check if the string is purely numeric (e.g. "80", "443", "-10", "3.14")
        trimmed = val_str.strip()
        if NUMERIC_REGEX.match(trimmed):
            # Genuine numeric string - do not sanitize
            return val_str

        # Check for dangerous trigger characters directly at start (including tab, CR)
        if val_str and val_str[0] in FORMULA_TRIGGERS:
            return "'" + val_str

        # Check for dangerous trigger characters after leading whitespace
        lstripped = val_str.lstrip(" \t\r\n")
        if lstripped and lstripped[0] in FORMULA_TRIGGERS:
            # Prefix single quote to force spreadsheet text evaluation
            return "'" + val_str

        return val_str

    @classmethod
    def export_findings(
        cls,
        findings: List[SecurityFinding],
        output_file: Optional[Union[str, Path]] = None,
        asset_details_map: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> str:
        """Serializes findings into RFC 4180 compliant CSV string or writes to output_file.
        
        Uses UTF-8 BOM (utf-8-sig) and windows line endings (\\r\\n) for maximum Excel fidelity.
        """
        asset_map = asset_details_map or {}
        output = io.StringIO()
        writer = csv.writer(
            output,
            dialect="excel",
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\r\n",
        )

        # Write header row
        writer.writerow(CSV_COLUMNS)

        # Write data rows
        for f in findings:
            asset_info = asset_map.get(f.asset_id or 0, {})
            asset_ip = f.ip_address or asset_info.get("ip_address", "")
            hostname = f.hostname or asset_info.get("hostname", "")
            service = asset_info.get("service", "")
            first_seen = asset_info.get("first_seen", f.timestamp)
            last_seen = asset_info.get("last_seen", f.timestamp)

            row = [
                cls.sanitize_for_spreadsheet(f.id or ""),
                cls.sanitize_for_spreadsheet(f.rule_id),
                cls.sanitize_for_spreadsheet(f.title),
                cls.sanitize_for_spreadsheet(f.severity),
                cls.sanitize_for_spreadsheet(f.risk_score),
                cls.sanitize_for_spreadsheet(f.risk_tier),
                cls.sanitize_for_spreadsheet(f.confidence),
                cls.sanitize_for_spreadsheet(f.status),
                cls.sanitize_for_spreadsheet(asset_ip),
                cls.sanitize_for_spreadsheet(hostname),
                cls.sanitize_for_spreadsheet(f.port_number if f.port_number is not None else ""),
                cls.sanitize_for_spreadsheet(f.protocol),
                cls.sanitize_for_spreadsheet(service),
                cls.sanitize_for_spreadsheet(f.evidence),
                cls.sanitize_for_spreadsheet(f.recommendation),
                cls.sanitize_for_spreadsheet(first_seen),
                cls.sanitize_for_spreadsheet(last_seen),
                cls.sanitize_for_spreadsheet(f.user_notes),
            ]
            writer.writerow(row)

        csv_content = output.getvalue()
        output.close()

        if output_file:
            target_path = Path(output_file).resolve()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            # Write with UTF-8 BOM for Microsoft Excel compatibility
            with open(target_path, "w", encoding="utf-8-sig", newline="") as f:
                f.write(csv_content)

        return csv_content
