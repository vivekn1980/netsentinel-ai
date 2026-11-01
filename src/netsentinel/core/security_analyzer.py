"""Security analysis coordinator for NetSentinel AI.

Evaluates discovered hosts and ports using offline, deterministic observation rules,
calculates transparent risk scores, links defensive remediation guidance,
and manages finding resolution based on verifiable evidence.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from netsentinel.core.models import (
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_RESOLVED,
    DiscoveredHost,
    DiscoveredPort,
    ScanResult,
    SecurityFinding,
)
from netsentinel.core.remediation import RemediationProvider
from netsentinel.core.risk_engine import RiskEngine
from netsentinel.core.security_rules import RuleMatch, RuleRegistry, SecurityRule

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """Coordinates deterministic security analysis on network discovery scan results."""

    def __init__(self, rule_registry: Optional[RuleRegistry] = None):
        self.registry = rule_registry or RuleRegistry()

    def analyze_host(
        self,
        host: DiscoveredHost,
        asset_id: Optional[int] = None,
        session_id: Optional[int] = None,
    ) -> List[SecurityFinding]:
        """Analyzes a single discovered host and returns structured security findings."""
        findings: List[SecurityFinding] = []
        host_target = host.ip_address

        # 1. Run Host-Level Rules
        for rule in self.registry.get_host_rules():
            match = rule.evaluate(host)
            if match:
                finding = self._create_finding_from_match(
                    match=match,
                    host=host,
                    asset_id=asset_id,
                    session_id=session_id,
                    is_host_level=True,
                )
                findings.append(finding)

        # 2. Run Port-Level Rules on Open Ports
        open_ports = [p for p in host.ports if p.state == "open"]
        for port in open_ports:
            for rule in self.registry.get_port_rules():
                match = rule.evaluate(host, port)
                if match:
                    finding = self._create_finding_from_match(
                        match=match,
                        host=host,
                        asset_id=asset_id,
                        session_id=session_id,
                        is_host_level=False,
                    )
                    findings.append(finding)

        return findings

    def _create_finding_from_match(
        self,
        match: RuleMatch,
        host: DiscoveredHost,
        asset_id: Optional[int],
        session_id: Optional[int],
        is_host_level: bool,
    ) -> SecurityFinding:
        """Constructs a fully scored SecurityFinding from a RuleMatch."""
        # Calculate transparent risk score
        risk_result = RiskEngine.calculate_score(
            rule_severity=match.severity,
            confidence=match.confidence,
            target_ip_or_host=host.ip_address,
            confidence_rationale=match.confidence_rationale,
        )

        # Generate defensive remediation guidance
        remediation = RemediationProvider.get_remediation(match.rule_id)
        recommendation_text = remediation.formatted_text()

        # Construct stable deduplication key
        aid_part = str(asset_id) if asset_id is not None else f"ip_{host.ip_address}"
        if is_host_level:
            finding_key = f"{aid_part}:{match.rule_id}:host"
        else:
            finding_key = f"{aid_part}:{match.rule_id}:{match.protocol}:{match.port_number}"

        return SecurityFinding(
            severity=match.severity,  # Rule severity preserved
            title=match.title,
            description=match.description,
            recommendation=recommendation_text,
            asset_id=asset_id,
            session_id=session_id,
            cve_references=match.cve_references,
            rule_id=match.rule_id,
            rule_version=match.rule_version,
            confidence=risk_result.confidence,
            risk_score=risk_result.risk_score,
            risk_tier=risk_result.risk_tier,
            scoring_explanation=risk_result.scoring_explanation,
            evidence=match.evidence,
            status=STATUS_NEW,
            port_number=match.port_number,
            protocol=match.protocol,
            finding_key=finding_key,
            ip_address=host.ip_address,
            hostname=host.hostname,
        )

    def evaluate_finding_resolutions(
        self,
        scan_result: ScanResult,
        session_id: int,
        existing_active_findings: List[SecurityFinding],
        discovered_assets_map: Dict[str, int],  # ip -> asset_id
    ) -> List[Tuple[SecurityFinding, str]]:
        """Evaluates whether any previously active findings can be verified as resolved.

        STRICT SAFETY CRITERIA:
        - Scan must be fully successful (not cancelled, not failed, not timed out).
        - Host must have been observed up during this scan.
        - The relevant port must have been examined and confirmed closed/filtered,
          or the host broad port surface confirmed reduced to <= 10.
        Inconclusive scans (e.g. port not scanned) PRESERVE prior findings.

        Returns list of (finding, resolution_reason) tuples.
        """
        if not scan_result.success or scan_result.was_cancelled:
            # Never resolve findings from an incomplete, failed, or cancelled scan
            return []

        resolved_findings: List[Tuple[SecurityFinding, str]] = []
        hosts_by_ip = {h.ip_address: h for h in scan_result.hosts if h.status == "up"}

        for finding in existing_active_findings:
            if not finding.asset_id:
                continue

            # Find matching host in this scan
            matching_host: Optional[DiscoveredHost] = None
            for host in scan_result.hosts:
                aid = discovered_assets_map.get(host.ip_address)
                if aid == finding.asset_id:
                    matching_host = host
                    break

            if not matching_host or matching_host.status != "up":
                # Host was not examined or was down; preserve finding
                continue

            # Case A: Service-level finding
            if finding.port_number is not None:
                # Check if this port was explicitly examined in this scan
                port_record = next(
                    (p for p in matching_host.ports if p.port_number == finding.port_number and p.protocol == finding.protocol),
                    None,
                )
                if port_record and port_record.state in ("closed", "filtered"):
                    reason = (
                        f"Port {finding.port_number}/{finding.protocol} was examined and verified "
                        f"{port_record.state} in scan session #{session_id}."
                    )
                    resolved_findings.append((finding, reason))

            # Case B: Host-level rule (Broad open ports)
            elif finding.rule_id == "RULE-OBS-BROAD-PORTS":
                # 1. Parse original offending ports from evidence
                m_ports = re.search(r"\[OffendingPorts:\s*([0-9, ]+)\]", finding.evidence or "")
                if m_ports:
                    original_ports = set(int(x.strip()) for x in m_ports.group(1).split(",") if x.strip().isdigit())
                else:
                    original_ports = set(int(p) for p in re.findall(r"(\d+)/(?:tcp|udp)", finding.evidence or ""))

                # Malformed or missing evidence does not cause premature resolution
                if not original_ports:
                    continue

                ports_by_number = {p.port_number: p for p in matching_host.ports}
                examined_port_numbers = set(ports_by_number.keys())

                # Scope verification: Every single original offending port must be explicitly reassessed
                unexamined = original_ports - examined_port_numbers
                if unexamined:
                    # If any original offending port remains unexamined, preserve finding
                    continue

                # Verification: Each original offending port must be verified closed or filtered
                still_open_or_unconfirmed = {
                    p_num for p_num in original_ports
                    if ports_by_number[p_num].state not in ("closed", "filtered")
                }
                if still_open_or_unconfirmed:
                    # Original offending ports are still open or not confirmed closed/filtered
                    continue

                reason = (
                    f"All {len(original_ports)} originally offending open ports were explicitly reassessed "
                    f"and verified closed/filtered in scan session #{session_id}."
                )
                resolved_findings.append((finding, reason))

        return resolved_findings
