"""Data models for NetSentinel AI core entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Port:
    """Network port entity."""
    port_number: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service_name: str = ""
    product: str = ""
    version: str = ""
    risk_note: str = ""
    id: Optional[int] = None
    asset_id: Optional[int] = None
    session_id: Optional[int] = None


@dataclass
class Asset:
    """Discovered network host asset entity."""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    os_name: str = ""
    os_accuracy: int = 0
    risk_level: str = "Low"  # None, Low, Medium, High, Critical
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    id: Optional[int] = None
    ports: List[Port] = field(default_factory=list)
    open_ports_count: int = 0


@dataclass
class ScanSession:
    """Record of a network scan execution."""
    target_input: str
    profile: str = "tcp_connect"  # tcp_connect, service_detect, ping_sweep
    start_time: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    end_time: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed, cancelled
    command_executed: str = ""
    hosts_discovered: int = 0
    ports_found: int = 0
    risk_summary: str = ""
    duration_seconds: float = 0.0
    nmap_version: str = ""
    error_message: str = ""
    configured_ports: str = ""
    process_id: int = 0
    instance_id: str = ""
    id: Optional[int] = None


@dataclass
class DiscoveredPort:
    """Port entity extracted from Nmap XML."""
    port_number: int
    protocol: str = "tcp"
    state: str = "open"  # open, closed, filtered
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""


@dataclass
class DiscoveredHost:
    """Host entity extracted from Nmap XML."""
    ip_address: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac_address: str = ""
    vendor: str = ""
    hostname: str = ""
    status: str = "up"
    os_name: str = ""
    os_accuracy: int = 0
    ports: List[DiscoveredPort] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated output from an Nmap scan execution."""
    success: bool
    hosts: List[DiscoveredHost] = field(default_factory=list)
    start_time: str = ""
    finish_time: str = ""
    elapsed_seconds: float = 0.0
    nmap_version: str = ""
    raw_xml: str = ""
    raw_stdout: str = ""
    raw_stderr: str = ""
    error_message: str = ""
    was_cancelled: bool = False


# Finding lifecycle status constants
STATUS_NEW = "New"
STATUS_OPEN = "Open"
STATUS_ACKNOWLEDGED = "Acknowledged"
STATUS_RESOLVED = "Resolved"
STATUS_FALSE_POSITIVE = "False Positive"

ALL_FINDING_STATUSES = [
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_ACKNOWLEDGED,
    STATUS_RESOLVED,
    STATUS_FALSE_POSITIVE,
]

VALID_STATUS_TRANSITIONS = {
    STATUS_NEW: {STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_FALSE_POSITIVE},
    STATUS_OPEN: {STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_FALSE_POSITIVE},
    STATUS_ACKNOWLEDGED: {STATUS_OPEN, STATUS_RESOLVED, STATUS_FALSE_POSITIVE},
    STATUS_RESOLVED: {STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_FALSE_POSITIVE},
    STATUS_FALSE_POSITIVE: {STATUS_OPEN, STATUS_ACKNOWLEDGED},
}


@dataclass
class SecurityFinding:
    """Identified security risk, vulnerability, or audit item with transparent scoring and lifecycle."""
    severity: str  # Rule severity: Critical, High, Medium, Low, Info
    title: str
    description: str
    recommendation: str
    id: Optional[int] = None
    asset_id: Optional[int] = None
    session_id: Optional[int] = None
    cve_references: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    # Milestone 3 additions
    rule_id: str = ""
    rule_version: str = "1.0"
    confidence: float = 1.0  # 0.1 to 1.0 based on evidence strength
    risk_score: float = 0.0  # 0.0 to 100.0 numerical score
    risk_tier: str = "Low"  # Critical, High, Medium, Low, Info based on score
    scoring_explanation: str = ""  # Human-readable formula breakdown
    evidence: str = ""  # Concrete raw evidence observed
    status: str = STATUS_NEW  # New, Open, Acknowledged, Resolved, False Positive
    port_id: Optional[int] = None
    port_number: Optional[int] = None
    protocol: str = "tcp"
    finding_key: str = ""  # Stable deduplication identity: asset_id:rule_id:protocol:port or asset_id:rule_id:host
    user_notes: str = ""  # Operator rationale for lifecycle updates
    resolution_reason: str = ""  # Explanation of resolution
    ip_address: str = ""  # Joined helper field for UI display
    hostname: str = ""  # Joined helper field for UI display


@dataclass
class AuditLogEntry:
    """Tamper-evident audit entry for scanning and configuration operations."""
    event_type: str  # scan_started, scan_completed, scan_aborted, target_authorized, config_changed
    target: str
    details: str
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    user_confirmed: bool = True


# Milestone 4 Assessment Completeness Statuses
ASSESSMENT_STATUS_COMPLETED = "Completed for configured scope"
ASSESSMENT_STATUS_PARTIAL = "Partial"
ASSESSMENT_STATUS_CANCELLED = "Cancelled"
ASSESSMENT_STATUS_FAILED = "Failed"
ASSESSMENT_STATUS_INCONCLUSIVE = "Inconclusive"

ALL_ASSESSMENT_STATUSES = [
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_PARTIAL,
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_FAILED,
    ASSESSMENT_STATUS_INCONCLUSIVE,
]

# Milestone 4 Historical Comparison Category Constants
DIFF_NEW = "New"
DIFF_REOPENED = "Reopened"
DIFF_RESOLVED = "Resolved"
DIFF_PERSISTENT = "Persistent"
DIFF_NOT_REASSESSED = "Not reassessed / Out of scope"

ALL_DIFF_CATEGORIES = [
    DIFF_NEW,
    DIFF_REOPENED,
    DIFF_RESOLVED,
    DIFF_PERSISTENT,
    DIFF_NOT_REASSESSED,
]


@dataclass
class ScanComparisonResult:
    """Structured result of historical scan differential analysis."""
    baseline_session_id: int
    current_session_id: int
    baseline_target: str = ""
    current_target: str = ""
    new_findings: List[SecurityFinding] = field(default_factory=list)
    reopened_findings: List[SecurityFinding] = field(default_factory=list)
    resolved_findings: List[SecurityFinding] = field(default_factory=list)
    persistent_findings: List[SecurityFinding] = field(default_factory=list)
    not_reassessed_findings: List[SecurityFinding] = field(default_factory=list)
    scope_differences: dict = field(default_factory=dict)
    risk_changes: dict = field(default_factory=dict)
    severity_distribution_changes: dict = field(default_factory=dict)
    assessment_completeness: str = ASSESSMENT_STATUS_COMPLETED
    has_scope_limitations: bool = False
    limitation_notice: str = ""

