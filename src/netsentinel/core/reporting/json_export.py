"""Versioned JSON export for NetSentinel AI security findings and scan sessions.

Produces schema-versioned (1.0.0), deterministic JSON structures suitable for SIEM,
data pipelines, compliance archives, and programmatic consumption.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from netsentinel.core.config import APP_VERSION, ConfigManager
from netsentinel.core.models import (
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
    STATUS_FALSE_POSITIVE,
    STATUS_RESOLVED,
)
from netsentinel.core.reporting.diff_engine import DiffEngine

SCHEMA_VERSION = "1.0.0"


class JsonExporter:
    """Serializes security findings and scan context into versioned JSON documents."""

    @classmethod
    def export(
        cls,
        findings: List[SecurityFinding],
        session: Optional[ScanSession] = None,
        comparison_result: Optional[ScanComparisonResult] = None,
        output_file: Optional[Union[str, Path]] = None,
        is_portable: Optional[bool] = None,
        asset_details_map: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> str:
        """Constructs a deterministic JSON structure and optionally writes to file.
        
        Args:
            findings: List of SecurityFinding entities
            session: Optional ScanSession entity for context
            comparison_result: Optional historical comparison payload
            output_file: Optional filepath to persist the JSON output
            is_portable: Optional override for storage mode reporting
            asset_details_map: Optional map of asset_id -> asset metadata dict
        """
        asset_map = asset_details_map or {}

        # 1. Determine storage mode
        if is_portable is None:
            cfg = ConfigManager()
            is_portable = cfg.is_portable
        storage_mode_str = "portable" if is_portable else "standard"

        # 2. Risk summary calculations
        active = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]
        scores = [f.risk_score for f in active]

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        status_counts: Dict[str, int] = {}

        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1
            if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE):
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                tier_counts[f.risk_tier] = tier_counts.get(f.risk_tier, 0) + 1

        risk_summary = {
            "total_findings": len(findings),
            "active_findings": len(active),
            "severity_distribution": sev_counts,
            "risk_tier_distribution": tier_counts,
            "status_distribution": status_counts,
            "max_risk_score": max(scores) if scores else 0.0,
            "average_risk_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
        }

        # 3. Document Structure
        doc: Dict[str, Any] = {
            "metadata": {
                "generator": "NetSentinel AI",
                "application_version": APP_VERSION,
                "schema_version": SCHEMA_VERSION,
                "export_timestamp": datetime.now().isoformat(timespec="seconds"),
                "storage_mode": storage_mode_str,
            },
            "risk_summary": risk_summary,
        }

        # 4. Scan Context (if session provided)
        if session:
            completeness, has_limitations, notice = DiffEngine.evaluate_completeness(session)
            doc["scan_context"] = {
                "session_id": session.id,
                "target_input": session.target_input,
                "scan_profile": session.profile,
                "command_executed": session.command_executed,
                "start_time": session.start_time,
                "end_time": session.end_time,
                "duration_seconds": session.duration_seconds,
                "completion_status": completeness,
                "has_scope_limitations": has_limitations,
                "scope_limitation_notice": notice,
                "configured_ports": session.configured_ports or "Default Profile Ports",
                "hosts_discovered": session.hosts_discovered,
                "ports_found": session.ports_found,
                "nmap_version": session.nmap_version or "Bundled Nmap",
                "error_message": session.error_message or None,
            }

        # 5. Detailed Findings Array
        serialized_findings = []
        for f in findings:
            asset_info = asset_map.get(f.asset_id or 0, {})
            serialized_findings.append({
                "finding_id": f.id,
                "finding_key": DiffEngine.get_finding_key(f),
                "rule_id": f.rule_id,
                "rule_version": f.rule_version,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "risk_tier": f.risk_tier,
                "confidence": f.confidence,
                "scoring_explanation": f.scoring_explanation,
                "status": f.status,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "asset": {
                    "asset_id": f.asset_id,
                    "ip_address": f.ip_address or asset_info.get("ip_address", ""),
                    "hostname": f.hostname or asset_info.get("hostname", ""),
                },
                "network_target": {
                    "port_number": f.port_number,
                    "protocol": f.protocol,
                },
                "first_observed": asset_info.get("first_seen", f.timestamp),
                "last_observed": asset_info.get("last_seen", f.timestamp),
                "user_notes": f.user_notes or None,
                "resolution_reason": f.resolution_reason or None,
            })

        doc["findings"] = serialized_findings

        # 6. Optional Comparison Payload
        if comparison_result:
            def serialize_finding_stub(f_item: SecurityFinding) -> Dict[str, Any]:
                return {
                    "finding_id": f_item.id,
                    "finding_key": DiffEngine.get_finding_key(f_item),
                    "rule_id": f_item.rule_id,
                    "title": f_item.title,
                    "severity": f_item.severity,
                    "risk_score": f_item.risk_score,
                    "ip_address": f_item.ip_address,
                    "port_number": f_item.port_number,
                    "status": f_item.status,
                }

            doc["historical_comparison"] = {
                "baseline_session_id": comparison_result.baseline_session_id,
                "current_session_id": comparison_result.current_session_id,
                "baseline_target": comparison_result.baseline_target,
                "current_target": comparison_result.current_target,
                "assessment_completeness": comparison_result.assessment_completeness,
                "has_scope_limitations": comparison_result.has_scope_limitations,
                "limitation_notice": comparison_result.limitation_notice,
                "scope_differences": comparison_result.scope_differences,
                "risk_changes": comparison_result.risk_changes,
                "severity_distribution_changes": comparison_result.severity_distribution_changes,
                "counts": {
                    "new": len(comparison_result.new_findings),
                    "reopened": len(comparison_result.reopened_findings),
                    "resolved": len(comparison_result.resolved_findings),
                    "persistent": len(comparison_result.persistent_findings),
                    "not_reassessed": len(comparison_result.not_reassessed_findings),
                },
                "new_findings": [serialize_finding_stub(f) for f in comparison_result.new_findings],
                "reopened_findings": [serialize_finding_stub(f) for f in comparison_result.reopened_findings],
                "resolved_findings": [serialize_finding_stub(f) for f in comparison_result.resolved_findings],
                "persistent_findings": [serialize_finding_stub(f) for f in comparison_result.persistent_findings],
                "not_reassessed_findings": [serialize_finding_stub(f) for f in comparison_result.not_reassessed_findings],
            }

        json_text = json.dumps(doc, indent=2, ensure_ascii=False)

        if output_file:
            target_path = Path(output_file).resolve()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(json_text)

        return json_text
