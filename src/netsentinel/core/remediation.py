"""Defensive remediation guidance provider for NetSentinel AI.

Provides safe, actionable, purely advisory hardening instructions referencing
industry security standards (CIS Benchmarks, NIST SP 800-123, NIST SP 800-53).

CRITICAL SAFETY CONSTRAINT:
NetSentinel AI is strictly an audit and discovery tool. It NEVER executes
system modification commands, firewall rule alterations, or service shutdowns.
All guidance is operator-facing and requires human review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class RemediationGuidance:
    """Structured defensive remediation advice and standard citations."""
    summary: str
    steps: List[str] = field(default_factory=list)
    standards_references: List[str] = field(default_factory=list)
    verification_advice: str = ""

    def formatted_text(self) -> str:
        """Renders guidance into a clean human-readable narrative."""
        lines = [self.summary.strip()]
        if self.steps:
            lines.append("\nRecommended Defensive Actions:")
            for i, step in enumerate(self.steps, 1):
                lines.append(f"  {i}. {step}")
        if self.verification_advice:
            lines.append(f"\nVerification: {self.verification_advice}")
        if self.standards_references:
            lines.append("\nStandards & Hardening References:")
            for ref in self.standards_references:
                lines.append(f"  • {ref}")
        return "\n".join(lines)


class RemediationProvider:
    """Maps security rule IDs and observation types to actionable defensive remediation."""

    _GUIDANCE: Dict[str, RemediationGuidance] = {
        "RULE-EXP-TELNET": RemediationGuidance(
            summary=(
                "Telnet transmits all communications, including authentication credentials, "
                "in unencrypted plaintext. Modern network security standards mandate encrypted "
                "administrative channels."
            ),
            steps=[
                "Confirm whether Telnet is operationally required for legacy equipment.",
                "Migrate all administrative access to SSHv2 (port 22) or an encrypted out-of-band management network.",
                "Disable or uninstall the Telnet server daemon (e.g., 'Stop-Service Telnet' on Windows or disable telnetd in systemd).",
                "If retirement is not immediately possible, restrict host firewall rules to explicit management IP subnets.",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 4.8 - Uninstall or Disable Unnecessary Services",
                "NIST SP 800-123: Guide to General Server Security (Section 4.1 - Insecure Protocols)",
            ],
            verification_advice="Verify that port 23/tcp responds with connection refused or filtered on subsequent scans.",
        ),
        "RULE-EXP-FTP": RemediationGuidance(
            summary=(
                "Standard FTP transmits authentication credentials and file payloads without "
                "encryption over the network, exposing data to network sniffing and spoofing."
            ),
            steps=[
                "Assess if cleartext FTP is required or if it can be replaced with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS).",
                "If file exchange is necessary, enforce explicit TLS (FTPS) with modern ciphers and disable anonymous access.",
                "Restrict FTP listener bindings to internal or dedicated storage VLAN interfaces.",
                "Verify file system permissions on uploaded directory trees.",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 4.8 - Uninstall or Disable Unnecessary Services",
                "NIST SP 800-123: Guide to General Server Security (Section 4.2 - Network Access Controls)",
            ],
            verification_advice="Confirm FTP listener requires TLS or has been migrated to SFTP port 22.",
        ),
        "RULE-EXP-HTTP-CLEAR": RemediationGuidance(
            summary=(
                "An unencrypted HTTP web server was observed. Cleartext web traffic is susceptible "
                "to eavesdropping, session token interception, and man-in-the-middle tampering."
            ),
            steps=[
                "Configure an SSL/TLS digital certificate on the web server or reverse proxy (e.g., Let's Encrypt or enterprise PKI).",
                "Configure an HTTP-to-HTTPS redirect (HTTP 301 Permanent Redirect) from port 80 to port 443.",
                "Enable HTTP Strict Transport Security (HSTS) headers once HTTPS is validated.",
                "Verify that no sensitive login forms, API keys, or private portals are accessible over plain HTTP.",
            ],
            standards_references=[
                "NIST SP 800-52 Rev. 2: Guidelines for the Selection, Configuration, and Use of TLS",
                "OWASP Top 10: Cryptographic Failures (A02:2021)",
            ],
            verification_advice="Query port 80/tcp with curl or a browser to ensure an HTTP 301/308 redirect to https:// is returned.",
        ),
        "RULE-EXP-SMB": RemediationGuidance(
            summary=(
                "Server Message Block (SMB) file sharing ports (139/445) are exposed. Exposed SMB services "
                "are prime targets for network reconnaissance, credential relay attacks, and lateral movement."
            ),
            steps=[
                "Ensure SMB ports (137-139, 445) are never exposed to untrusted or external networks.",
                "Disable legacy SMBv1 across the domain and host systems (e.g., 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol').",
                "Enforce SMB signing and SMB encryption (SMBv3) for all internal file sharing.",
                "Restrict SMB access using Windows Defender Firewall or hardware ACLs to designated management subnets.",
            ],
            standards_references=[
                "CISA Alert TA17-181A: Securing Network Infrastructure - SMB Hardening",
                "CIS Microsoft Windows Server Benchmark (Section 2.3: Network Security)",
            ],
            verification_advice="Confirm port 445/tcp is filtered by host firewall from non-authorized subnets.",
        ),
        "RULE-EXP-RDP": RemediationGuidance(
            summary=(
                "Remote Desktop Protocol (RDP) on port 3389 was observed. Exposed RDP services are "
                "frequently targeted by automated brute-force attacks and protocol vulnerability exploits."
            ),
            steps=[
                "Ensure RDP is never directly accessible from the public internet without an encrypted gateway or VPN.",
                "Enforce Network Level Authentication (NLA) on all RDP-enabled hosts.",
                "Implement multi-factor authentication (MFA) for remote desktop sessions.",
                "Restrict RDP firewall access to authorized administrative workstation IP addresses.",
                "Configure account lockout policies to defend against brute-force attacks.",
            ],
            standards_references=[
                "CIS Microsoft Windows Server Benchmark (Section 18.9: Remote Desktop Services)",
                "NIST SP 800-123: Guide to General Server Security (Section 4.3 - Remote Administration)",
            ],
            verification_advice="Verify NLA is enforced and RDP is inaccessible from unauthorized external IP addresses.",
        ),
        "RULE-EXP-SSH": RemediationGuidance(
            summary=(
                "Secure Shell (SSH) management service was observed. While SSH provides encrypted "
                "communications, public or broad exposure allows password brute-forcing and targeting of software flaws."
            ),
            steps=[
                "Disable password-based authentication in favor of ED25519 or RSA-4096 public key authentication.",
                "Disable root login over SSH ('PermitRootLogin no' in sshd_config).",
                "Configure host-based firewall rules to permit SSH only from management jump hosts or VPN subnets.",
                "Keep OpenSSH updated to the latest vendor-supported release.",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 4.8 - Insecure Management Protocols",
                "OpenSSH Security Hardening Guidelines (NIST SP 800-123)",
            ],
            verification_advice="Verify password authentication is rejected and only authorized keys are accepted.",
        ),
        "RULE-EXP-DB": RemediationGuidance(
            summary=(
                "A database listener was observed exposed on the network. Direct database access from "
                "untrusted network segments presents severe data leakage and credential brute-force risks."
            ),
            steps=[
                "Bind database services strictly to localhost (127.0.0.1) or an isolated internal backend VLAN.",
                "Ensure application servers communicate over private internal interfaces or TLS-encrypted connections.",
                "Audit database authentication credentials and ensure default accounts are disabled or renamed.",
                "Enforce strict firewall rules blocking ingress to database ports from standard user subnets.",
            ],
            standards_references=[
                "CIS Database Security Benchmarks (MySQL, PostgreSQL, MSSQL, Oracle)",
                "NIST SP 800-53 Rev. 5: AC-3 Access Enforcement, SC-7 Boundary Protection",
            ],
            verification_advice="Confirm database port responds only to authorized application tier IP addresses.",
        ),
        "RULE-EXP-ADMIN": RemediationGuidance(
            summary=(
                "A dedicated administrative or management interface was observed (e.g., VNC, Webmin, or admin portal). "
                "Unrestricted access exposes system controls to unauthorized users."
            ),
            steps=[
                "Restrict administrative interfaces to dedicated out-of-band management VLANs or VPNs.",
                "Ensure strong multi-factor authentication is enforced on all administrative consoles.",
                "Review whether management services can be bound to localhost and accessed via SSH tunneling.",
                "Audit administrator session timeouts and TLS encryption settings.",
            ],
            standards_references=[
                "NIST SP 800-53 Rev. 5: AC-6 Least Privilege, SC-7 Boundary Protection",
                "CIS Controls v8: Safeguard 4.2 - Establish and Maintain a Secure Configuration Process",
            ],
            verification_advice="Verify management ports return connection refused from non-management IP ranges.",
        ),
        "RULE-OBS-BROAD-PORTS": RemediationGuidance(
            summary=(
                "Host exposes an unusually broad set of open ports (> 10 open ports observed). "
                "Broad port exposure often signals an unhardened multi-role server, missing host firewall, "
                "or perimeter misconfiguration."
            ),
            steps=[
                "Review all running network services on the target host using netstat or Get-NetTCPConnection.",
                "Decommission or stop services that are not required for the host's primary business role.",
                "Enable and configure the host-based firewall (e.g., Windows Defender Firewall or iptables/nftables) with default-deny inbound rules.",
                "Verify whether the host is placed in an appropriate network segment (DMZ vs internal LAN).",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 4.1 - Establish and Maintain a Secure Configuration Process",
                "NIST SP 800-123: Guide to General Server Security (Section 3.1 - Principle of Least Functionality)",
            ],
            verification_advice="Re-scan the host after applying firewall rules to confirm closed or filtered status on unused ports.",
        ),
        "RULE-OBS-UNKNOWN-SERVICE": RemediationGuidance(
            summary=(
                "An open port was identified with an unrecognized or non-standard service banner. "
                "Unidentified services may represent custom software, unmanaged services, or non-standard listeners."
            ),
            steps=[
                "Identify the process bound to this port on the host (e.g., 'Get-NetTCPConnection -LocalPort <port>' on Windows).",
                "Inspect the binary path, digital signature, and startup method of the hosting executable.",
                "Document legitimate business services or terminate rogue processes.",
                "Implement firewall rules to restrict port access to authorized clients only.",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 2.1 - Establish and Maintain a Software Inventory",
                "CIS Controls v8: Safeguard 4.8 - Insecure Management Protocols",
            ],
            verification_advice="Confirm process identity and ensure unknown or unapproved listeners are removed.",
        ),
        "RULE-OBS-LEGACY-VERSION": RemediationGuidance(
            summary=(
                "A legacy or deprecated software product or protocol version was observed from banner evidence. "
                "Outdated software versions frequently contain known security flaws and lack current vendor support."
            ),
            steps=[
                "Consult the vendor's official lifecycle matrix to verify if the reported version is end-of-life (EOL).",
                "Plan and apply the latest official security patches or upgrade to the current stable release.",
                "If upgrading requires scheduled maintenance, implement compensating controls (network isolation, strict ACLs).",
                "Disable deprecated protocol features or ciphers in the service configuration.",
            ],
            standards_references=[
                "CIS Controls v8: Safeguard 7.1 - Establish and Maintain a Vulnerability Management Process",
                "NIST SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning",
            ],
            verification_advice="Re-run discovery scan to verify the updated service version banner is reported.",
        ),
    }

    _DEFAULT_GUIDANCE = RemediationGuidance(
        summary="Service observed during network discovery. Review configuration against organization security policy.",
        steps=[
            "Verify whether this network service is required for approved operational workflows.",
            "Restrict network access to authorized clients using host-based or network firewall rules.",
            "Keep the underlying software package updated to the latest stable vendor release.",
        ],
        standards_references=["CIS Controls v8: Safeguard 4.1 - Principle of Least Functionality"],
        verification_advice="Confirm port status reflects desired state in subsequent discovery scans.",
    )

    @classmethod
    def get_remediation(cls, rule_id: str, context: Optional[str] = None) -> RemediationGuidance:
        """Returns verified defensive remediation guidance for a rule ID."""
        guidance = cls._GUIDANCE.get(rule_id, cls._DEFAULT_GUIDANCE)
        if context:
            # We can personalize summary or verification without altering static references
            pass
        return guidance
