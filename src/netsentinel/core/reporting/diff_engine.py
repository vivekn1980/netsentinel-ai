"""Historical scan comparison engine for NetSentinel AI.

Compares two scan sessions using stable finding identity to categorize:
- New findings
- Reopened findings
- Resolved findings (strictly verified, never assumed from absence)
- Persistent findings
- Not reassessed / Out of scope findings

Calculates transparent risk deltas, severity distribution changes,
and explicit scope limitation notices.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from netsentinel.core.models import (
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_FAILED,
    ASSESSMENT_STATUS_INCONCLUSIVE,
    ASSESSMENT_STATUS_PARTIAL,
    DIFF_NEW,
    DIFF_NOT_REASSESSED,
    DIFF_PERSISTENT,
    DIFF_REOPENED,
    DIFF_RESOLVED,
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_RESOLVED,
)


class DiffEngine:
    """Historical differential engine comparing baseline and current scan sessions."""

    @staticmethod
    def get_finding_key(finding: SecurityFinding) -> str:
        """Derives or returns stable finding identity.
        
        Service-level: asset_id:rule_id:protocol:port_number
        Host-level:    asset_id:rule_id:host
        """
        if finding.finding_key and finding.finding_key.strip():
            return finding.finding_key.strip()
        asset_id = finding.asset_id or 0
        rule_id = finding.rule_id or "UNKNOWN"
        protocol = finding.protocol or "tcp"
        if finding.port_number is not None and finding.port_number > 0:
            return f"{asset_id}:{rule_id}:{protocol}:{finding.port_number}"
        return f"{asset_id}:{rule_id}:host"

    @classmethod
    def evaluate_completeness(cls, session: ScanSession) -> Tuple[str, bool, str]:
        """Evaluates scan completion status and generates limitation notices.
        
        Returns: (completeness_status, has_limitations, limitation_notice)
        """
        status_lower = (session.status or "").lower()
        if status_lower == "cancelled":
            return (
                ASSESSMENT_STATUS_CANCELLED,
                True,
                "Scan was cancelled by the user before completion. Results are partial.",
            )
        if status_lower == "failed" or (status_lower != "completed" and bool(session.error_message)):
            return (
                ASSESSMENT_STATUS_FAILED,
                True,
                f"Scan execution failed or encountered fatal errors ({session.error_message or 'Unknown failure'}). Results are incomplete.",
            )
        if status_lower == "completed":
            if session.hosts_discovered == 0:
                return (
                    ASSESSMENT_STATUS_INCONCLUSIVE,
                    True,
                    "Scan completed but discovered zero responsive hosts. Targets may be offline, filtering ICMP/TCP probes, or unreachable.",
                )
            # Check if ports were specifically configured
            if session.configured_ports:
                return (
                    ASSESSMENT_STATUS_COMPLETED,
                    False,
                    f"Completed for configured port scope ({session.configured_ports}). Unexamined ports are not assessed.",
                )
            return (
                ASSESSMENT_STATUS_COMPLETED,
                False,
                f"Completed for configured profile '{session.profile}'. Unexamined ports or unprobed services are not assessed.",
            )
        if status_lower == "partial":
            return (
                ASSESSMENT_STATUS_PARTIAL,
                True,
                "Scan completed partially. Some targets or port ranges were omitted.",
            )

        return (
            ASSESSMENT_STATUS_INCONCLUSIVE,
            True,
            f"Scan session status '{session.status}' is inconclusive.",
        )

    @classmethod
    def compare_sessions(
        cls,
        baseline_session: ScanSession,
        current_session: ScanSession,
        baseline_findings: List[SecurityFinding],
        current_findings: List[SecurityFinding],
        current_scanned_ports_by_asset: Optional[Dict[int, Set[int]]] = None,
        current_scanned_assets: Optional[Set[int]] = None,
        current_port_states_by_asset: Optional[Dict[int, Dict[int, str]]] = None,
    ) -> ScanComparisonResult:
        """Compares baseline findings against current findings using strict reassessment rules.
        
        Args:
            baseline_session: Prior ScanSession model
            current_session: Current ScanSession model
            baseline_findings: List of SecurityFinding from baseline session
            current_findings: List of SecurityFinding from current session
            current_scanned_ports_by_asset: Dict mapping asset_id -> set of port numbers actively examined in current scan
            current_scanned_assets: Set of asset_ids actively examined in current scan
            current_port_states_by_asset: Optional dict mapping asset_id -> {port_number: state} ("open", "closed", "filtered")
        """
        completeness, has_limitations, limitation_notice = cls.evaluate_completeness(current_session)
        is_current_valid = completeness == ASSESSMENT_STATUS_COMPLETED

        # Maps of findings by stable key
        baseline_map: Dict[str, SecurityFinding] = {
            cls.get_finding_key(f): f for f in baseline_findings
        }
        current_map: Dict[str, SecurityFinding] = {
            cls.get_finding_key(f): f for f in current_findings
        }

        new_findings: List[SecurityFinding] = []
        reopened_findings: List[SecurityFinding] = []
        resolved_findings: List[SecurityFinding] = []
        persistent_findings: List[SecurityFinding] = []
        not_reassessed_findings: List[SecurityFinding] = []

        # 1. Analyze findings observed in Current scan
        for key, curr_f in current_map.items():
            if key in baseline_map:
                base_f = baseline_map[key]
                if base_f.status == STATUS_RESOLVED:
                    # Was previously resolved in baseline, now re-detected
                    reopened_findings.append(curr_f)
                else:
                    # Present in both and unresolved
                    persistent_findings.append(curr_f)
            else:
                # Not present in baseline
                if curr_f.status == STATUS_RESOLVED:
                    resolved_findings.append(curr_f)
                else:
                    new_findings.append(curr_f)

        # 2. Analyze findings present in Baseline scan but absent from Current scan
        # CRITICAL: Do NOT automatically resolve absent findings!
        # Must verify that the asset and port were actually reassessed.
        scanned_assets = current_scanned_assets or set()
        scanned_ports = current_scanned_ports_by_asset or {}

        for key, base_f in baseline_map.items():
            if key not in current_map:
                # If baseline finding was already Resolved or False Positive, handle appropriately
                if base_f.status == STATUS_RESOLVED:
                    # Already resolved previously, remain resolved
                    continue

                if not is_current_valid:
                    # Scan was cancelled, failed, or inconclusive -> CANNOT resolve anything!
                    not_reassessed_findings.append(base_f)
                    continue

                asset_id = base_f.asset_id or 0
                if asset_id not in scanned_assets and scanned_assets:
                    # Asset was not even part of current scan
                    not_reassessed_findings.append(base_f)
                    continue

                # Check if port was evaluated
                if base_f.port_number is not None and base_f.port_number > 0:
                    asset_ports = scanned_ports.get(asset_id, set())
                    if base_f.port_number in asset_ports:
                        port_states = (current_port_states_by_asset or {}).get(asset_id, {})
                        if port_states and port_states.get(base_f.port_number) not in ("closed", "filtered"):
                            not_reassessed_findings.append(base_f)
                        else:
                            # Port was probed in current scan and service is closed or finding no longer triggers -> Verified Resolved!
                            resolved_findings.append(base_f)
                    else:
                        # Port was omitted from current scan scope (e.g. -p 80 when finding was on port 23)
                        not_reassessed_findings.append(base_f)
                else:
                    # Host-level finding (e.g. broad ports or host config)
                    if asset_id in scanned_assets:
                        # For broad ports finding, ensure original port scope was verified
                        if base_f.rule_id == "RULE-OBS-BROAD-PORTS":
                            asset_ports = scanned_ports.get(asset_id, set())
                            m_ports = re.search(r"\[OffendingPorts:\s*([0-9, ]+)\]", base_f.evidence or "")
                            if m_ports:
                                original_ports = set(int(x.strip()) for x in m_ports.group(1).split(",") if x.strip().isdigit())
                            else:
                                original_ports = set(int(p) for p in re.findall(r"(\d+)/(?:tcp|udp)", base_f.evidence or ""))

                            # Malformed or missing evidence does not cause premature resolution
                            if not original_ports:
                                not_reassessed_findings.append(base_f)
                                continue

                            # Every single original offending port must be explicitly reassessed
                            unexamined = original_ports - asset_ports
                            if unexamined:
                                not_reassessed_findings.append(base_f)
                                continue

                            # Verify none of the original offending ports are still open
                            port_states = (current_port_states_by_asset or {}).get(asset_id, {})
                            if port_states:
                                still_open_or_unconfirmed = {
                                    p for p in original_ports
                                    if port_states.get(p) not in ("closed", "filtered")
                                }
                                if still_open_or_unconfirmed:
                                    not_reassessed_findings.append(base_f)
                                    continue

                            curr_open_ports = {
                                cf.port_number for cf in current_findings
                                if (cf.asset_id or 0) == asset_id and cf.port_number in original_ports
                            }
                            if curr_open_ports:
                                not_reassessed_findings.append(base_f)
                                continue

                            resolved_findings.append(base_f)
                        else:
                            # Host was evaluated and rule did not fire
                            resolved_findings.append(base_f)
                    else:
                        not_reassessed_findings.append(base_f)

        # 3. Calculate scope differences
        scope_diff = {
            "baseline_target": baseline_session.target_input,
            "current_target": current_session.target_input,
            "targets_match": baseline_session.target_input.strip() == current_session.target_input.strip(),
            "baseline_profile": baseline_session.profile,
            "current_profile": current_session.profile,
            "profiles_match": baseline_session.profile == current_session.profile,
            "baseline_ports": baseline_session.configured_ports or "Default",
            "current_ports": current_session.configured_ports or "Default",
            "ports_match": (baseline_session.configured_ports or "") == (current_session.configured_ports or ""),
        }
        if not scope_diff["targets_match"] or not scope_diff["ports_match"]:
            has_limitations = True
            scope_mismatch_msg = "Scan scope differed between baseline and current sessions. Some findings could not be reassessed."
            limitation_notice = f"{limitation_notice} {scope_mismatch_msg}".strip()

        # 4. Calculate Risk and Severity Distributions
        def get_metrics(findings: List[SecurityFinding]) -> Dict[str, Any]:
            active = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]
            scores = [f.risk_score for f in active]
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in active:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                tier_counts[f.risk_tier] = tier_counts.get(f.risk_tier, 0) + 1
            return {
                "active_count": len(active),
                "total_count": len(findings),
                "max_score": max(scores) if scores else 0.0,
                "avg_score": round(sum(scores) / len(scores), 1) if scores else 0.0,
                "severities": sev_counts,
                "tiers": tier_counts,
            }

        base_metrics = get_metrics(baseline_findings)
        curr_metrics = get_metrics(current_findings)

        risk_changes = {
            "baseline_active_count": base_metrics["active_count"],
            "current_active_count": curr_metrics["active_count"],
            "active_count_delta": curr_metrics["active_count"] - base_metrics["active_count"],
            "baseline_max_score": base_metrics["max_score"],
            "current_max_score": curr_metrics["max_score"],
            "max_score_delta": round(curr_metrics["max_score"] - base_metrics["max_score"], 1),
            "baseline_avg_score": base_metrics["avg_score"],
            "current_avg_score": curr_metrics["avg_score"],
            "avg_score_delta": round(curr_metrics["avg_score"] - base_metrics["avg_score"], 1),
        }

        sev_changes = {}
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            b_cnt = base_metrics["severities"].get(s, 0)
            c_cnt = curr_metrics["severities"].get(s, 0)
            sev_changes[s] = {
                "baseline": b_cnt,
                "current": c_cnt,
                "delta": c_cnt - b_cnt,
            }

        return ScanComparisonResult(
            baseline_session_id=baseline_session.id or 0,
            current_session_id=current_session.id or 0,
            baseline_target=baseline_session.target_input,
            current_target=current_session.target_input,
            new_findings=new_findings,
            reopened_findings=reopened_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            not_reassessed_findings=not_reassessed_findings,
            scope_differences=scope_diff,
            risk_changes=risk_changes,
            severity_distribution_changes=sev_changes,
            assessment_completeness=completeness,
            has_scope_limitations=has_limitations,
            limitation_notice=limitation_notice,
        )
