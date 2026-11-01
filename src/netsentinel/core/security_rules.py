"""Modular, evidence-based security observation rules for NetSentinel AI.

Evaluates discovered network hosts and ports against deterministic observation criteria.
Every rule requires concrete evidence and clearly distinguishes between confirmed
service banner detections and port-based heuristics.

Titles are strictly observation-based (no speculation or fabricated vulnerabilities).
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from netsentinel.core.models import DiscoveredHost, DiscoveredPort


@dataclass(frozen=True)
class RuleMatch:
    """Represents a matched security observation from a rule."""
    rule_id: str
    rule_name: str
    rule_version: str
    severity: str  # Rule severity: Critical, High, Medium, Low, Info
    confidence: float  # 0.1 to 1.0
    confidence_rationale: str
    title: str
    description: str
    evidence: str
    port_number: Optional[int] = None
    protocol: str = "tcp"
    cve_references: str = ""


class SecurityRule(ABC):
    """Abstract base class for all security observation rules."""

    rule_id: str = "RULE-BASE"
    name: str = "Base Security Rule"
    rule_version: str = "1.0"
    severity: str = "Info"
    is_host_rule: bool = False

    @abstractmethod
    def evaluate(
        self,
        host: DiscoveredHost,
        port: Optional[DiscoveredPort] = None,
    ) -> Optional[RuleMatch]:
        """Evaluates host or port against rule criteria."""
        pass


# -----------------------------------------------------------------------------
# Service Exposure Rules
# -----------------------------------------------------------------------------

class TelnetExposureRule(SecurityRule):
    """Detects exposed Telnet management service."""

    rule_id = "RULE-EXP-TELNET"
    name = "Telnet Service Exposure"
    rule_version = "1.0"
    severity = "High"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_port_23 = port.port_number == 23
        is_telnet_svc = "telnet" in svc

        if not (is_port_23 or is_telnet_svc):
            return None

        if is_telnet_svc or port.product:
            confidence = 1.00
            confidence_rationale = "Service banner confirmed as Telnet"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open and confirmed running Telnet service. "
                f"Service: '{port.service_name}', Product: '{port.product or 'N/A'}', Version: '{port.version or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard Telnet port 23)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open. "
                f"Observed on standard Telnet port 23 (heuristic: service unconfirmed)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="Telnet service observed",
            description=(
                "A Telnet management service was observed. Telnet transmits authentication "
                "credentials and administrative commands in cleartext over the network."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class FtpExposureRule(SecurityRule):
    """Detects exposed standard FTP service."""

    rule_id = "RULE-EXP-FTP"
    name = "FTP Service Exposure"
    rule_version = "1.0"
    severity = "Medium"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_port_21 = port.port_number == 21
        is_ftp_svc = "ftp" in svc and "sftp" not in svc and "tftp" not in svc

        if not (is_port_21 or is_ftp_svc):
            return None

        if is_ftp_svc or port.product:
            confidence = 1.00
            confidence_rationale = "Service banner confirmed as FTP"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running FTP service. "
                f"Product: '{port.product or 'N/A'}', Version: '{port.version or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard FTP port 21)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard FTP port 21 "
                f"(heuristic: service unconfirmed)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="FTP service observed",
            description=(
                "A standard File Transfer Protocol (FTP) service was observed. "
                "Standard FTP transmits session credentials and data payloads in cleartext."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class CleartextHttpRule(SecurityRule):
    """Detects exposed cleartext HTTP web server."""

    rule_id = "RULE-EXP-HTTP-CLEAR"
    name = "Cleartext HTTP Service Exposure"
    rule_version = "1.0"
    severity = "Medium"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_http_port = port.port_number in (80, 8080)
        is_http_svc = svc in ("http", "http-proxy") and "ssl" not in svc and "https" not in svc

        if not (is_http_port or is_http_svc):
            return None

        if is_http_svc or port.product:
            confidence = 0.90
            confidence_rationale = "Service or product confirmed as HTTP web server"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running unencrypted HTTP service. "
                f"Product: '{port.product or 'N/A'}', Version: '{port.version or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard HTTP port 80/8080)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard HTTP port "
                f"(heuristic: unencrypted web listener suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="HTTP service observed",
            description=(
                "An unencrypted HTTP web server was observed. Cleartext web communications "
                "do not provide transport layer security or encryption by default."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class SmbExposureRule(SecurityRule):
    """Detects exposed Server Message Block (SMB) file sharing service."""

    rule_id = "RULE-EXP-SMB"
    name = "SMB Service Exposure"
    rule_version = "1.0"
    severity = "High"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_smb_port = port.port_number in (139, 445)
        is_smb_svc = any(k in svc for k in ("microsoft-ds", "netbios-ssn", "smb"))

        if not (is_smb_port or is_smb_svc):
            return None

        if is_smb_svc or port.product:
            confidence = 1.00
            confidence_rationale = "Service banner confirmed as SMB / NetBIOS"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running SMB file sharing. "
                f"Service: '{port.service_name}', Product: '{port.product or 'Windows SMB'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard SMB port 445/139)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard SMB port "
                f"(heuristic: file sharing service suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="SMB service exposed",
            description=(
                "A Server Message Block (SMB) network service was observed. SMB exposes file shares "
                "and RPC endpoints that should be restricted to trusted internal networks."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class RdpExposureRule(SecurityRule):
    """Detects exposed Remote Desktop Protocol (RDP) service."""

    rule_id = "RULE-EXP-RDP"
    name = "RDP Service Exposure"
    rule_version = "1.0"
    severity = "Medium"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_rdp_port = port.port_number == 3389
        is_rdp_svc = any(k in svc for k in ("ms-wbt-server", "ms-term-service", "rdp"))

        if not (is_rdp_port or is_rdp_svc):
            return None

        if is_rdp_svc or port.product:
            confidence = 1.00
            confidence_rationale = "Service banner confirmed as Microsoft RDP"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running Remote Desktop Protocol. "
                f"Service: '{port.service_name}', Product: '{port.product or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard RDP port 3389)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard RDP port 3389 "
                f"(heuristic: remote desktop service suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="RDP service exposed",
            description=(
                "Remote Desktop Protocol (RDP) listener was observed. Remote desktop access "
                "should be protected by Network Level Authentication, MFA, and restricted to management subnets."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class SshExposureRule(SecurityRule):
    """Detects exposed Secure Shell (SSH) service."""

    rule_id = "RULE-EXP-SSH"
    name = "SSH Service Exposure"
    rule_version = "1.0"
    severity = "Low"
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        is_ssh_port = port.port_number == 22
        is_ssh_svc = "ssh" in svc

        if not (is_ssh_port or is_ssh_svc):
            return None

        if is_ssh_svc or port.product:
            confidence = 1.00
            confidence_rationale = "Service banner confirmed as SSH"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running SSH service. "
                f"Product: '{port.product or 'N/A'}', Version: '{port.version or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = "Port-based heuristic (standard SSH port 22)"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard SSH port 22 "
                f"(heuristic: secure shell service suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="SSH service exposed",
            description=(
                "A Secure Shell (SSH) management service was observed. Ensure access is restricted "
                "to authorized administrative hosts and strong key-based authentication is enforced."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class DatabaseExposureRule(SecurityRule):
    """Detects exposed database service listeners."""

    rule_id = "RULE-EXP-DB"
    name = "Database Service Exposure"
    rule_version = "1.0"
    severity = "High"
    is_host_rule = False

    DB_PORTS = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        27017: "MongoDB",
        6379: "Redis",
    }

    DB_SERVICES = {
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "ms-sql-s": "Microsoft SQL Server",
        "oracle-tns": "Oracle Database",
        "mongodb": "MongoDB",
        "redis": "Redis",
    }

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        matched_db: Optional[str] = None
        is_port_match = port.port_number in self.DB_PORTS

        for svc_key, db_name in self.DB_SERVICES.items():
            if svc_key in svc:
                matched_db = db_name
                break

        if not matched_db and is_port_match:
            matched_db = self.DB_PORTS[port.port_number]

        if not matched_db:
            return None

        if any(svc_key in svc for svc_key in self.DB_SERVICES) or port.product:
            confidence = 1.00
            confidence_rationale = f"Service banner confirmed as {matched_db}"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running {matched_db} database listener. "
                f"Service: '{port.service_name}', Product: '{port.product or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = f"Port-based heuristic (standard {matched_db} port {port.port_number})"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard {matched_db} port "
                f"(heuristic: database listener suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="Database listener observed",
            description=(
                f"A {matched_db} database listener was observed exposed on the network. "
                "Database listeners should not be accessible across general or untrusted network segments."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class AdminInterfaceRule(SecurityRule):
    """Detects exposed dedicated administrative interface (VNC, Webmin, management consoles)."""

    rule_id = "RULE-EXP-ADMIN"
    name = "Administrative Interface Exposure"
    rule_version = "1.0"
    severity = "Medium"
    is_host_rule = False

    ADMIN_PORTS = {
        5900: "VNC Remote Desktop",
        5901: "VNC Remote Desktop",
        10000: "Webmin / Network Management",
    }

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.lower()
        matched_admin: Optional[str] = None
        is_port_match = port.port_number in self.ADMIN_PORTS

        if "vnc" in svc:
            matched_admin = "VNC Remote Desktop"
        elif "webmin" in svc:
            matched_admin = "Webmin Administration Console"

        if not matched_admin and is_port_match:
            matched_admin = self.ADMIN_PORTS[port.port_number]

        if not matched_admin:
            return None

        if "vnc" in svc or "webmin" in svc or port.product:
            confidence = 0.95
            confidence_rationale = f"Service confirmed as {matched_admin}"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open running {matched_admin}. "
                f"Service: '{port.service_name}', Product: '{port.product or 'N/A'}'."
            )
        else:
            confidence = 0.70
            confidence_rationale = f"Port-based heuristic (standard {matched_admin} port {port.port_number})"
            evidence = (
                f"Port {port.port_number}/{port.protocol} is open on standard {matched_admin} port "
                f"(heuristic: remote management console suspected)."
            )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=confidence,
            confidence_rationale=confidence_rationale,
            title="Administrative interface observed",
            description=(
                f"An administrative management interface ({matched_admin}) was observed. "
                "Management consoles should be restricted to dedicated management VLANs."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


# -----------------------------------------------------------------------------
# Host-Level & Observation Rules
# -----------------------------------------------------------------------------

class BroadOpenPortsRule(SecurityRule):
    """Detects hosts exposing an unusually broad number of open ports (> 10 open ports)."""

    rule_id = "RULE-OBS-BROAD-PORTS"
    name = "Broad Open-Port Surface"
    rule_version = "1.0"
    severity = "Medium"
    is_host_rule = True

    THRESHOLD = 10

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        open_ports = [p for p in host.ports if p.state == "open"]
        count = len(open_ports)
        if count <= self.THRESHOLD:
            return None

        port_sample = ", ".join(f"{p.port_number}/{p.protocol}" for p in open_ports[:12])
        if count > 12:
            port_sample += f", and {count - 12} more"

        ports_tag = ",".join(str(p.port_number) for p in open_ports)
        evidence = (
            f"Host {host.ip_address} exposes {count} open ports ({port_sample}), "
            f"exceeding the standard baseline threshold of {self.THRESHOLD} open ports. "
            f"[OffendingPorts: {ports_tag}]"
        )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=0.90,
            confidence_rationale=f"Verified count of {count} open ports on single host",
            title="Broad open-port exposure",
            description=(
                f"Host exposes {count} open network ports. A broad open-port surface indicates "
                "a multi-role server, potential DMZ exposure, or missing default-deny host firewall rules."
            ),
            evidence=evidence,
            port_number=None,
            protocol="tcp",
        )


class UnknownServiceRule(SecurityRule):
    """Detects open ports with unidentified or anomalous services."""

    rule_id = "RULE-OBS-UNKNOWN-SERVICE"
    name = "Unknown Service Identity"
    rule_version = "1.0"
    severity = "Low"
    is_host_rule = False

    COMMON_STANDARD_PORTS = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080}

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        svc = port.service_name.strip().lower()
        prod = port.product.strip()
        is_unknown = (
            svc in ("", "unknown", "?")
            or (port.port_number not in self.COMMON_STANDARD_PORTS and not prod and svc in ("tcpwrapped", "unknown", ""))
        )

        if not is_unknown:
            return None

        evidence = (
            f"Port {port.port_number}/{port.protocol} is open, but service probe returned "
            f"unidentified identity: service='{port.service_name or 'None'}', product='{prod or 'None'}'."
        )

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            rule_version=self.rule_version,
            severity=self.severity,
            confidence=0.75,
            confidence_rationale="Service probe failed to identify standard application banner",
            title="Unknown service identity",
            description=(
                f"An open port ({port.port_number}/{port.protocol}) was identified with an unknown or "
                "unrecognized service banner. Unmanaged listeners may represent non-standard services."
            ),
            evidence=evidence,
            port_number=port.port_number,
            protocol=port.protocol,
        )


class LegacyServiceRule(SecurityRule):
    """Detects confirmed legacy or deprecated software product versions from banner evidence."""

    rule_id = "RULE-OBS-LEGACY-VERSION"
    name = "Legacy Software Version Observed"
    rule_version = "1.0"
    severity = "Medium"  # Default rule severity for legacy versions
    is_host_rule = False

    def evaluate(self, host: DiscoveredHost, port: Optional[DiscoveredPort] = None) -> Optional[RuleMatch]:
        if not port or port.state != "open":
            return None

        prod = port.product.lower()
        ver = port.version.strip()
        extra = port.extra_info.lower()

        # Exact matching criteria:
        # 1. Apache httpd <= 2.2.x (Branch retired in 2017)
        if "apache" in prod and ver:
            match = re.match(r"^([0-9]+)\.([0-9]+)", ver)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                if major < 2 or (major == 2 and minor <= 2):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        rule_version=self.rule_version,
                        severity="High",
                        confidence=1.00,
                        confidence_rationale=f"Exact banner version confirmed ({ver})",
                        title="Legacy version observed",
                        description=(
                            f"Legacy web server branch observed: Apache httpd {ver}. "
                            "The Apache 2.2 and earlier series are end-of-life and no longer receive security maintenance."
                        ),
                        evidence=f"Port {port.port_number}/{port.protocol}: Banner reports product='{port.product}', version='{ver}'.",
                        port_number=port.port_number,
                        protocol=port.protocol,
                    )

        # 2. OpenSSH < 7.4 (Missing modern crypto defaults and retired key exchanges)
        if "openssh" in prod and ver:
            match = re.match(r"^([0-9]+)\.([0-9]+)", ver)
            if match:
                major, minor = int(match.group(1)), int(match.group(2))
                if major < 7 or (major == 7 and minor < 4):
                    return RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        rule_version=self.rule_version,
                        severity="Medium",
                        confidence=1.00,
                        confidence_rationale=f"Exact OpenSSH version confirmed ({ver})",
                        title="Legacy version observed",
                        description=(
                            f"Legacy SSH release observed: OpenSSH {ver}. "
                            "OpenSSH releases prior to 7.4 use deprecated cryptographic algorithms."
                        ),
                        evidence=f"Port {port.port_number}/{port.protocol}: Banner reports product='{port.product}', version='{ver}'.",
                        port_number=port.port_number,
                        protocol=port.protocol,
                    )

        # 3. Explicit SMBv1 protocol in banner or extra info
        if "smbv1" in extra or "smb 1" in extra:
            return RuleMatch(
                rule_id=self.rule_id,
                rule_name=self.name,
                rule_version=self.rule_version,
                severity="Critical",
                confidence=1.00,
                confidence_rationale="Explicit SMBv1 protocol indicator observed in service probe",
                title="Legacy version observed",
                description=(
                    "Legacy SMBv1 protocol was explicitly observed in the service banner. "
                    "SMBv1 lacks modern integrity safeguards and has been deprecated by Microsoft."
                ),
                evidence=f"Port {port.port_number}/{port.protocol}: Service probe reported legacy SMBv1 protocol ({port.extra_info}).",
                port_number=port.port_number,
                protocol=port.protocol,
            )

        # No confirmed match against documented criteria
        return None


# -----------------------------------------------------------------------------
# Rule Registry
# -----------------------------------------------------------------------------

class RuleRegistry:
    """Manages available security observation rules."""

    def __init__(self):
        self._rules: List[SecurityRule] = [
            TelnetExposureRule(),
            FtpExposureRule(),
            CleartextHttpRule(),
            SmbExposureRule(),
            RdpExposureRule(),
            SshExposureRule(),
            DatabaseExposureRule(),
            AdminInterfaceRule(),
            BroadOpenPortsRule(),
            UnknownServiceRule(),
            LegacyServiceRule(),
        ]

    def get_all_rules(self) -> List[SecurityRule]:
        """Returns all registered rules."""
        return list(self._rules)

    def get_port_rules(self) -> List[SecurityRule]:
        """Returns port-level rules."""
        return [r for r in self._rules if not r.is_host_rule]

    def get_host_rules(self) -> List[SecurityRule]:
        """Returns host-level rules."""
        return [r for r in self._rules if r.is_host_rule]
