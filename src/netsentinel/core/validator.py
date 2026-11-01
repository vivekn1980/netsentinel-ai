"""Target validation module for NetSentinel AI.

Enforces strict cybersecurity validation guardrails:
- Validates IPv4, IPv6, CIDR notations, and RFC 1123 hostnames.
- Rejects shell metacharacters and command injection attempts.
- Identifies private vs. public IP targets and surfaces safety warnings.
- Enforces explicit authorization policies.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import List, Optional, Set


@dataclass
class ValidationResult:
    """Outcome of validating a scan target input."""
    is_valid: bool
    target_type: str  # "ipv4", "ipv6", "cidr_v4", "cidr_v6", "hostname", "invalid"
    normalized_target: str
    is_public: bool = False
    is_loopback: bool = False
    is_private: bool = False
    warning: Optional[str] = None
    error: Optional[str] = None
    host_count: int = 1


# Forbidden shell metacharacters and command injection sequences
DANGEROUS_CHARS_REGEX = re.compile(r"[`;&|*?~<>^\$(){}\[\]\"'\\\n\r\t\x00]")

# RFC 1123 Hostname regex (supports labels up to 63 chars, total length up to 253)
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class TargetValidator:
    """Validates user-supplied network scan targets."""

    MAX_SCAN_TARGET_HOSTS = 65536  # Maximum permitted hosts across any scan scope (/16 or IPv6 /112)
    MAX_IPV4_SUBNET_HOSTS = 65536  # Retained for backwards compatibility

    @classmethod
    def resolve_dns_target(cls, hostname: str, timeout: float = 3.0) -> List[str]:
        """Resolves a hostname to unique IP addresses (IPv4 and IPv6) with a timeout guard.

        Returns list of unique IP address strings.
        Raises ValueError on resolution failure, timeout, or if no addresses are returned.

        Inherent DNS Resolution Limitations:
        - Ephemeral DNS & TTL: Returned addresses reflect current DNS state and may change dynamically.
        - Split-horizon & CDN: Internal vs. external resolvers or GeoDNS may yield differing addresses.
        - Multi-homed hosts: Hostnames may map to many addresses, requiring administrator review.
        """
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ValueError(f"DNS resolution failed for '{hostname}': {e}") from e
        except Exception as e:
            raise ValueError(f"DNS resolution error for '{hostname}': {e}") from e
        finally:
            socket.setdefaulttimeout(orig_timeout)

        ips: List[str] = []
        seen = set()
        for _family, _socktype, _proto, _canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)

        if not ips:
            raise ValueError(f"DNS resolution for '{hostname}' returned no IP addresses.")

        if len(ips) > cls.MAX_SCAN_TARGET_HOSTS:
            raise ValueError(
                f"Hostname '{hostname}' resolved to {len(ips):,} IP addresses, "
                f"exceeding maximum permitted scope of {cls.MAX_SCAN_TARGET_HOSTS:,} hosts."
            )

        return ips

    @classmethod
    def validate(cls, raw_target: str, resolve_dns: bool = False) -> ValidationResult:
        """Validates a target string and returns structured validation metadata."""
        if not raw_target or not raw_target.strip():
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target="",
                error="Target cannot be empty. Enter an IP, CIDR, or hostname.",
            )

        target = raw_target.strip()

        # Check for dangerous shell metacharacters or control characters
        if DANGEROUS_CHARS_REGEX.search(target):
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Security Alert: Target contains forbidden characters or command separators.",
            )

        # Check for comma-separated multiple targets
        if "," in target:
            return cls._validate_multi_target(target, resolve_dns=resolve_dns)

        # Check for spaces inside a single target
        if " " in target:
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Target cannot contain spaces. Enter a single IP, CIDR block, or hostname.",
            )

        return cls._validate_single_entry(target, resolve_dns=resolve_dns)

    @classmethod
    def _validate_single_entry(cls, target: str, resolve_dns: bool = False) -> ValidationResult:
        """Validates an individual target entry (IP, CIDR, or hostname)."""
        # 1. Check for CIDR network (contains '/')
        if "/" in target:
            return cls._validate_cidr(target)

        # 2. Check for Single IP (IPv4 or IPv6)
        ip_result = cls._validate_single_ip(target)
        if ip_result is not None:
            return ip_result

        # 3. Check for Hostname / FQDN
        return cls._validate_hostname(target, resolve_dns=resolve_dns)

    @classmethod
    def _validate_multi_target(cls, target: str, resolve_dns: bool = False) -> ValidationResult:
        """Validates comma-separated target entries without silent truncation and deduplicates entries."""
        parts = [p.strip() for p in target.split(",")]
        if not any(parts):
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Target list cannot be empty.",
            )

        validated_entries: List[ValidationResult] = []
        total_hosts = 0
        normalized_parts: List[str] = []
        seen_targets: Set[str] = set()
        duplicate_entries: List[str] = []
        has_public = False
        has_loopback = False
        has_private = False
        warnings: List[str] = []

        for idx, part in enumerate(parts):
            if not part:
                return ValidationResult(
                    is_valid=False,
                    target_type="invalid",
                    normalized_target=target,
                    error=f"Empty target entry at position {idx + 1} in target list.",
                )

            if " " in part:
                return ValidationResult(
                    is_valid=False,
                    target_type="invalid",
                    normalized_target=target,
                    error=f"Target entry '{part}' cannot contain internal spaces.",
                )

            sub_res = cls._validate_single_entry(part, resolve_dns=resolve_dns)
            if not sub_res.is_valid:
                return ValidationResult(
                    is_valid=False,
                    target_type="invalid",
                    normalized_target=target,
                    error=f"Target entry #{idx + 1} ('{part}') is invalid: {sub_res.error}",
                )

            # Deduplicate entries based on normalized target (case-insensitive)
            norm_key = sub_res.normalized_target.lower()
            if norm_key in seen_targets:
                duplicate_entries.append(part)
                continue

            seen_targets.add(norm_key)
            validated_entries.append(sub_res)
            normalized_parts.append(sub_res.normalized_target)
            total_hosts += sub_res.host_count
            if sub_res.is_public:
                has_public = True
            if sub_res.is_loopback:
                has_loopback = True
            if sub_res.is_private:
                has_private = True
            if sub_res.warning:
                warnings.append(f"{part}: {sub_res.warning}")

        if duplicate_entries:
            dup_summary = ", ".join(duplicate_entries[:3])
            if len(duplicate_entries) > 3:
                dup_summary += f" and {len(duplicate_entries) - 3} more"
            warnings.append(f"Notice: Deduplicated {len(duplicate_entries)} duplicate target(s) ({dup_summary}).")

        # Centralized multi-target scope check
        if total_hosts > cls.MAX_SCAN_TARGET_HOSTS:
            return ValidationResult(
                is_valid=False,
                target_type="multi_target",
                normalized_target=",".join(normalized_parts),
                error=(
                    f"Combined target scope exceeds maximum allowed limit of {cls.MAX_SCAN_TARGET_HOSTS:,} hosts "
                    f"({total_hosts:,} hosts specified across {len(normalized_parts)} unique targets)."
                ),
                host_count=total_hosts,
            )

        combined_warning = " | ".join(warnings) if warnings else None
        return ValidationResult(
            is_valid=True,
            target_type="multi_target",
            normalized_target=",".join(normalized_parts),
            is_public=has_public,
            is_loopback=has_loopback,
            is_private=has_private,
            warning=combined_warning,
            host_count=total_hosts,
        )

    @classmethod
    def _validate_single_ip(cls, target: str) -> Optional[ValidationResult]:
        """Tries to validate as single IPv4 or IPv6 address."""
        # Detect malformed IPv4 dotted quad attempts
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
            try:
                ip_obj = ipaddress.ip_address(target)
            except ValueError as e:
                return ValidationResult(
                    is_valid=False,
                    target_type="invalid",
                    normalized_target=target,
                    error=f"Invalid IPv4 address: {e}",
                )
        else:
            try:
                ip_obj = ipaddress.ip_address(target)
            except ValueError:
                return None

        is_v4 = isinstance(ip_obj, ipaddress.IPv4Address)
        target_type = "ipv4" if is_v4 else "ipv6"
        is_loop = ip_obj.is_loopback
        is_priv = ip_obj.is_private

        warning = None
        is_pub = not (is_priv or is_loop or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved)

        if is_pub:
            warning = (
                "Notice: Target is a public IP address. Ensure you possess written "
                "authorization before executing any network discovery or scanning."
            )
        elif is_loop:
            warning = "Target is local loopback (localhost). Safe for self-discovery."

        return ValidationResult(
            is_valid=True,
            target_type=target_type,
            normalized_target=str(ip_obj),
            is_public=is_pub,
            is_loopback=is_loop,
            is_private=is_priv,
            warning=warning,
            host_count=1,
        )

    @classmethod
    def _validate_cidr(cls, target: str) -> ValidationResult:
        """Validates CIDR notation (IPv4 or IPv6)."""
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error=f"Malformed CIDR network address: {e}",
            )

        is_v4 = isinstance(net, ipaddress.IPv4Network)
        target_type = "cidr_v4" if is_v4 else "cidr_v6"
        host_count = net.num_addresses
        is_priv = net.is_private
        is_loop = net.is_loopback
        is_pub = not (is_priv or is_loop or net.is_link_local or net.is_multicast or net.is_reserved)

        # Centralized check: Enforce MAX_SCAN_TARGET_HOSTS equally for IPv4 and IPv6 based on true address count
        if host_count > cls.MAX_SCAN_TARGET_HOSTS:
            if is_v4:
                limit_desc = f"Maximum allowed scope is /16 ({cls.MAX_SCAN_TARGET_HOSTS:,} hosts)."
            else:
                limit_desc = f"Maximum allowed IPv6 scope is /112 ({cls.MAX_SCAN_TARGET_HOSTS:,} hosts)."
            return ValidationResult(
                is_valid=False,
                target_type=target_type,
                normalized_target=str(net),
                error=f"CIDR prefix /{net.prefixlen} is too broad ({host_count:,} hosts). {limit_desc}",
                host_count=host_count,
            )

        warning = None
        if is_pub:
            warning = (
                f"Caution: Public CIDR range ({host_count:,} hosts). Scanning unauthorized public IP blocks "
                f"is strictly prohibited and may violate local cyber laws."
            )
        elif host_count > 1024:
            warning = f"Notice: Large network subnet ({host_count:,} potential hosts). Scan may take considerable time."

        return ValidationResult(
            is_valid=True,
            target_type=target_type,
            normalized_target=str(net),
            is_public=is_pub,
            is_loopback=is_loop,
            is_private=is_priv,
            warning=warning,
            host_count=host_count,
        )

    @classmethod
    def _validate_hostname(cls, target: str, resolve_dns: bool = False) -> ValidationResult:
        """Validates DNS hostname or FQDN, with optional DNS resolution."""
        if len(target) > 253:
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Hostname exceeds maximum RFC 1123 length of 253 characters.",
            )

        if not HOSTNAME_REGEX.match(target):
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Invalid hostname format. Must contain only letters, numbers, hyphens, and dots.",
            )

        labels = target.split(".")
        if labels[-1].isdigit() or target.isdigit():
            return ValidationResult(
                is_valid=False,
                target_type="invalid",
                normalized_target=target,
                error="Invalid hostname format: top-level domain cannot be all-numeric.",
            )

        is_localhost = target.lower() in ("localhost", "localhost.localdomain")
        warning = None
        host_count = 1
        is_pub = not is_localhost
        is_priv = False

        if resolve_dns and not is_localhost:
            try:
                resolved_ips = cls.resolve_dns_target(target)
                host_count = len(resolved_ips)
                has_pub = False
                has_priv = False
                for ip in resolved_ips:
                    ip_obj = ipaddress.ip_address(ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                        has_pub = True
                    else:
                        has_priv = True
                is_pub = has_pub
                is_priv = has_priv
                warning = f"DNS resolved to {host_count} address(es): {', '.join(resolved_ips[:3])}{'...' if host_count > 3 else ''}"
            except ValueError as e:
                return ValidationResult(
                    is_valid=False,
                    target_type="invalid",
                    normalized_target=target.lower(),
                    error=str(e),
                )
        elif not is_localhost:
            warning = "Notice: Hostname resolution will be performed prior to network discovery."

        return ValidationResult(
            is_valid=True,
            target_type="hostname",
            normalized_target=target.lower(),
            is_public=is_pub,
            is_loopback=is_localhost,
            is_private=is_priv,
            warning=warning,
            host_count=host_count,
        )
