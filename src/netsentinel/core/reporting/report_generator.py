"""Unified reporting coordinator for NetSentinel AI.

Coordinates the generation of HTML reports, CSV spreadsheets, versioned JSON exports,
and historical differential reports with audit logging and database integration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    AuditLogEntry,
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
)
from netsentinel.core.reporting.csv_export import CsvExporter
from netsentinel.core.reporting.diff_engine import DiffEngine
from netsentinel.core.reporting.html_report import HtmlReportGenerator
from netsentinel.core.reporting.json_export import JsonExporter
from netsentinel.core.reporting.report_paths import ReportPaths


class ReportGenerator:
    """Master reporting orchestrator coordinating file generation and audit logging."""

    def __init__(self, db_mgr: DatabaseManager):
        self.db_mgr = db_mgr

    def _get_asset_details_map(self) -> Dict[int, Dict[str, Any]]:
        """Builds an asset_id -> asset dict map for rich metadata serialization."""
        assets = self.db_mgr.list_assets(limit=5000)
        return {
            a.id: {
                "ip_address": a.ip_address,
                "hostname": a.hostname,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
                "os_name": a.os_name,
            }
            for a in assets if a.id is not None
        }

    def _log_export_event(self, format_type: str, output_path: Path, count: int, session_id: Optional[int] = None) -> None:
        """Records an immutable audit log entry for the export action."""
        session_str = f"session #{session_id}" if session_id else "all sessions"
        details = (
            f"Exported {count} finding(s) as {format_type.upper()} for {session_str}. "
            f"Destination: {output_path.name}"
        )
        self.db_mgr.add_audit_log(
            AuditLogEntry(
                event_type="report_exported",
                target=f"file:{output_path.name}",
                details=details,
                user_confirmed=True,
            )
        )

    def generate_html_report(
        self,
        session_id: Optional[int],
        output_path: Union[str, Path],
        include_resolved: bool = True,
        comparison_result: Optional[ScanComparisonResult] = None,
    ) -> Path:
        """Generates a standalone, offline HTML assessment report."""
        target_path = Path(output_path).resolve()
        session: Optional[ScanSession] = None

        if session_id is not None:
            session = self.db_mgr.get_scan_session(session_id)
            findings = self.db_mgr.list_security_findings(session_id=session_id, limit=5000)
        else:
            findings = self.db_mgr.list_security_findings(limit=5000)

        asset_map = self._get_asset_details_map()
        HtmlReportGenerator.generate_report(
            findings=findings,
            session=session,
            comparison_result=comparison_result,
            output_file=target_path,
            include_resolved=include_resolved,
            asset_details_map=asset_map,
        )

        self._log_export_event("html", target_path, len(findings), session_id)
        return target_path

    def export_findings_csv(
        self,
        output_path: Union[str, Path],
        session_id: Optional[int] = None,
        include_resolved: bool = True,
        severity_filter: Optional[str] = None,
    ) -> Path:
        """Exports findings to RFC 4180 CSV with formula injection protection."""
        target_path = Path(output_path).resolve()

        findings = self.db_mgr.list_security_findings(
            session_id=session_id,
            severity=severity_filter,
            limit=5000,
        )
        if not include_resolved:
            from netsentinel.core.models import STATUS_FALSE_POSITIVE, STATUS_RESOLVED
            findings = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]

        asset_map = self._get_asset_details_map()
        CsvExporter.export_findings(
            findings=findings,
            output_file=target_path,
            asset_details_map=asset_map,
        )

        self._log_export_event("csv", target_path, len(findings), session_id)
        return target_path

    def export_findings_json(
        self,
        output_path: Union[str, Path],
        session_id: Optional[int] = None,
        include_resolved: bool = True,
        comparison_result: Optional[ScanComparisonResult] = None,
    ) -> Path:
        """Exports findings and session metadata to schema-versioned JSON."""
        target_path = Path(output_path).resolve()
        session: Optional[ScanSession] = None

        if session_id is not None:
            session = self.db_mgr.get_scan_session(session_id)
            findings = self.db_mgr.list_security_findings(session_id=session_id, limit=5000)
        else:
            findings = self.db_mgr.list_security_findings(limit=5000)

        if not include_resolved:
            from netsentinel.core.models import STATUS_FALSE_POSITIVE, STATUS_RESOLVED
            findings = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]

        asset_map = self._get_asset_details_map()
        JsonExporter.export(
            findings=findings,
            session=session,
            comparison_result=comparison_result,
            output_file=target_path,
            asset_details_map=asset_map,
        )

        self._log_export_event("json", target_path, len(findings), session_id)
        return target_path

    def compare_scans(
        self,
        baseline_session_id: int,
        current_session_id: int,
    ) -> ScanComparisonResult:
        """Performs historical differential comparison between two scan sessions."""
        base_session = self.db_mgr.get_scan_session(baseline_session_id)
        if not base_session:
            raise ValueError(f"Baseline scan session #{baseline_session_id} not found.")

        curr_session = self.db_mgr.get_scan_session(current_session_id)
        if not curr_session:
            raise ValueError(f"Current scan session #{current_session_id} not found.")

        base_findings = self.db_mgr.list_security_findings(session_id=baseline_session_id, limit=5000)
        curr_findings = self.db_mgr.list_security_findings(session_id=current_session_id, limit=5000)

        # Retrieve ports and assets evaluated during current scan
        curr_details = self.db_mgr.get_session_details(current_session_id)
        scanned_assets: Set[int] = set()
        scanned_ports_by_asset: Dict[int, Set[int]] = {}
        scanned_port_states_by_asset: Dict[int, Dict[int, str]] = {}

        for asset in curr_details.get("assets", []):
            if "id" in asset:
                scanned_assets.add(asset["id"])

        for port in curr_details.get("ports", []):
            a_id = port.get("asset_id")
            p_num = port.get("port_number")
            p_state = port.get("state", "open")
            if a_id and p_num:
                scanned_ports_by_asset.setdefault(a_id, set()).add(p_num)
                scanned_port_states_by_asset.setdefault(a_id, {})[p_num] = p_state

        return DiffEngine.compare_sessions(
            baseline_session=base_session,
            current_session=curr_session,
            baseline_findings=base_findings,
            current_findings=curr_findings,
            current_scanned_ports_by_asset=scanned_ports_by_asset,
            current_scanned_assets=scanned_assets,
            current_port_states_by_asset=scanned_port_states_by_asset,
        )

    def generate_differential_report(
        self,
        baseline_session_id: int,
        current_session_id: int,
        output_path: Union[str, Path],
        format_type: str = "html",
    ) -> Path:
        """Generates a comparison report between two sessions in HTML or JSON format."""
        target_path = Path(output_path).resolve()
        comp = self.compare_scans(baseline_session_id, current_session_id)

        if format_type.lower() == "json":
            self.export_findings_json(
                output_path=target_path,
                session_id=current_session_id,
                comparison_result=comp,
            )
        else:
            self.generate_html_report(
                session_id=current_session_id,
                output_path=target_path,
                comparison_result=comp,
            )

        return target_path
