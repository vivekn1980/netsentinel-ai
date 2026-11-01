"""Unit tests for TargetValidator security checks and validation logic."""

import pytest
from netsentinel.core.validator import TargetValidator


@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "8.8.8.8",
    "1.1.1.1",
])
def test_valid_ipv4_targets(target: str):
    res = TargetValidator.validate(target)
    assert res.is_valid is True
    assert res.target_type == "ipv4"
    assert res.normalized_target == target
    assert res.host_count == 1


@pytest.mark.parametrize("target", [
    "::1",
    "fe80::1",
    "2001:db8::1",
])
def test_valid_ipv6_targets(target: str):
    res = TargetValidator.validate(target)
    assert res.is_valid is True
    assert res.target_type == "ipv6"
    assert res.host_count == 1


@pytest.mark.parametrize("target, expected_hosts", [
    ("192.168.1.0/24", 256),
    ("10.0.0.0/16", 65536),
    ("192.168.1.128/28", 16),
])
def test_valid_cidr_targets(target: str, expected_hosts: int):
    res = TargetValidator.validate(target)
    assert res.is_valid is True
    assert res.target_type == "cidr_v4"
    assert res.host_count == expected_hosts


def test_broad_cidr_rejection():
    """Ensure subnets broader than /16 (e.g. /8 or /0) are rejected as unsafe."""
    res = TargetValidator.validate("10.0.0.0/8")
    assert res.is_valid is False
    assert "too broad" in res.error.lower()


@pytest.mark.parametrize("target", [
    "localhost",
    "scanme.nmap.org",
    "gateway.corp.local",
    "internal-server-01.dev",
])
def test_valid_hostnames(target: str):
    res = TargetValidator.validate(target)
    assert res.is_valid is True
    assert res.target_type == "hostname"
    assert res.normalized_target == target.lower()


@pytest.mark.parametrize("malicious_target", [
    "127.0.0.1; whoami",
    "192.168.1.1 && calc",
    "192.168.1.1 | dir",
    "192.168.1.1 `id`",
    "$(whoami)",
    "192.168.1.1\nreboot",
    "192.168.1.1\x00",
    "10.0.0.1 > out.txt",
    "10.0.0.1 < in.txt",
    "192.168.1.1' OR '1'='1",
])
def test_rejection_of_command_injections(malicious_target: str):
    res = TargetValidator.validate(malicious_target)
    assert res.is_valid is False
    assert res.target_type == "invalid"
    assert "Security Alert" in res.error or "cannot contain spaces" in res.error


@pytest.mark.parametrize("invalid_target", [
    "",
    "   ",
    "999.999.999.999",
    "192.168.1.300",
    "192.168.1.1/33",
    "invalid..hostname..com",
    "-bad-hostname",
    "bad_hostname_with_underscores_in_host",
])
def test_rejection_of_malformed_targets(invalid_target: str):
    res = TargetValidator.validate(invalid_target)
    assert res.is_valid is False
    assert res.error is not None


def test_public_ip_warning():
    """Verify that public IP addresses trigger an authorization warning."""
    res = TargetValidator.validate("8.8.8.8")
    assert res.is_valid is True
    assert res.is_public is True
    assert res.warning is not None
    assert "public IP" in res.warning


def test_private_ip_flags():
    """Verify private RFC 1918 IPs do not trigger public IP warning."""
    res = TargetValidator.validate("192.168.1.1")
    assert res.is_valid is True
    assert res.is_private is True
    assert res.is_public is False


def test_ipv4_and_ipv6_cidr_boundary_conditions():
    """Verify centralized MAX_SCAN_TARGET_HOSTS limit enforces identical ceilings on IPv4 and IPv6."""
    # IPv4 boundary: /16 (65536) allowed, /15 (131072) rejected
    res_v4_16 = TargetValidator.validate("10.0.0.0/16")
    assert res_v4_16.is_valid is True
    assert res_v4_16.host_count == 65536

    res_v4_15 = TargetValidator.validate("10.0.0.0/15")
    assert res_v4_15.is_valid is False
    assert res_v4_15.host_count == 131072
    assert "too broad" in res_v4_15.error
    assert "Maximum allowed scope is /16" in res_v4_15.error

    # IPv6 boundary: /112 (65536) allowed, /111 (131072) rejected, /64 rejected
    res_v6_112 = TargetValidator.validate("2001:db8::/112")
    assert res_v6_112.is_valid is True
    assert res_v6_112.host_count == 65536

    res_v6_111 = TargetValidator.validate("2001:db8::/111")
    assert res_v6_111.is_valid is False
    assert res_v6_111.host_count == 131072
    assert "too broad" in res_v6_111.error
    assert "Maximum allowed IPv6 scope is /112" in res_v6_111.error

    res_v6_64 = TargetValidator.validate("2001:db8::/64")
    assert res_v6_64.is_valid is False
    assert "too broad" in res_v6_64.error


def test_multi_target_validation():
    """Verify multi-target comma-separated validation, total host summation, and error reporting."""
    # Valid multi-target list
    res = TargetValidator.validate("192.168.1.1, 10.0.0.1, 127.0.0.1")
    assert res.is_valid is True
    assert res.target_type == "multi_target"
    assert res.host_count == 3
    assert res.normalized_target == "192.168.1.1,10.0.0.1,127.0.0.1"

    # Multi-target with one invalid entry displays clear error identifying offending position
    res_bad = TargetValidator.validate("192.168.1.1, invalid..host, 10.0.0.1")
    assert res_bad.is_valid is False
    assert "Target entry #2" in res_bad.error

    # Multi-target exceeding total host limit
    res_over = TargetValidator.validate("192.168.0.0/17, 10.0.0.0/17, 172.16.0.0/17")
    assert res_over.is_valid is False
    assert "Combined target scope exceeds maximum allowed limit" in res_over.error


def test_multi_target_deduplication():
    """Verify that duplicate targets in multi-target inputs are deduplicated and warned."""
    # Deduplicate repeated IPs
    res = TargetValidator.validate("192.168.1.1, 10.0.0.1, 192.168.1.1, 10.0.0.1")
    assert res.is_valid is True
    assert res.host_count == 2
    assert res.normalized_target == "192.168.1.1,10.0.0.1"
    assert "Deduplicated 2 duplicate target(s)" in res.warning

    # Deduplicate case-insensitively for hostnames
    res_host = TargetValidator.validate("scanme.nmap.org, SCANME.NMAP.ORG")
    assert res_host.is_valid is True
    assert res_host.host_count == 1
    assert res_host.normalized_target == "scanme.nmap.org"
    assert "Deduplicated 1 duplicate target(s)" in res_host.warning


def test_multiple_cidr_boundary_enforcement():
    """Verify multiple CIDRs sum host counts and enforce the 65,536 ceiling."""
    # Exactly 65536 hosts across two /17s: Allowed
    res_exact = TargetValidator.validate("10.0.0.0/17, 10.128.0.0/17")
    assert res_exact.is_valid is True
    assert res_exact.host_count == 65536

    # 65536 + 256 = 65792: Exceeds limit and rejected
    res_over = TargetValidator.validate("10.0.0.0/17, 10.128.0.0/17, 192.168.1.0/24")
    assert res_over.is_valid is False
    assert "Combined target scope exceeds maximum allowed limit" in res_over.error
    assert res_over.host_count == 65792


def test_resolve_dns_target_success_and_deduplication(monkeypatch):
    """Verify DNS resolution extracts unique IPv4 and IPv6 addresses preserving order."""
    mock_addrinfo = [
        (2, 1, 6, "", ("93.184.216.34", 0)),
        (2, 1, 6, "", ("93.184.216.34", 0)),  # Duplicate IPv4
        (23, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),  # IPv6
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda host, port, family, socktype: mock_addrinfo)

    ips = TargetValidator.resolve_dns_target("example.com")
    assert ips == ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]


def test_resolve_dns_target_failure_and_scope_limit(monkeypatch):
    """Verify DNS resolution errors and oversized address counts raise clean ValueErrors."""
    import socket

    # Test resolution failure
    def mock_fail(host, port, family, socktype):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr("socket.getaddrinfo", mock_fail)
    with pytest.raises(ValueError, match="DNS resolution failed for 'nonexistent.invalid'"):
        TargetValidator.resolve_dns_target("nonexistent.invalid")

    # Test oversized resolution
    mock_huge = [(2, 1, 6, "", (f"10.0.{i // 256}.{i % 256}", 0)) for i in range(70000)]
    monkeypatch.setattr("socket.getaddrinfo", lambda h, p, f, s: mock_huge)
    with pytest.raises(ValueError, match="exceeding maximum permitted scope"):
        TargetValidator.resolve_dns_target("huge-cdn.local")


def test_validate_hostname_with_dns_resolution(monkeypatch):
    """Verify validate() with resolve_dns=True integrates DNS resolution metadata."""
    mock_addrinfo = [
        (2, 1, 6, "", ("192.168.1.100", 0)),
        (2, 1, 6, "", ("10.0.0.50", 0)),
    ]
    monkeypatch.setattr("socket.getaddrinfo", lambda host, port, family, socktype: mock_addrinfo)

    res = TargetValidator.validate("internal-server.local", resolve_dns=True)
    assert res.is_valid is True
    assert res.host_count == 2
    assert "DNS resolved to 2 address(es)" in res.warning
    assert res.is_private is True

