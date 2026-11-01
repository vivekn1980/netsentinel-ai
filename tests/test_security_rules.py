"""Unit tests for NetSentinel AI security observation rules."""

from __future__ import annotations

import pytest

from netsentinel.core.models import DiscoveredHost, DiscoveredPort
from netsentinel.core.security_rules import (
    AdminInterfaceRule,
    BroadOpenPortsRule,
    CleartextHttpRule,
    DatabaseExposureRule,
    FtpExposureRule,
    LegacyServiceRule,
    RdpExposureRule,
    RuleRegistry,
    SmbExposureRule,
    SshExposureRule,
    TelnetExposureRule,
    UnknownServiceRule,
)


def _make_host(ip: str = "192.168.1.50", hostname: str = "test-host", ports=None) -> DiscoveredHost:
    return DiscoveredHost(
        ip_address=ip,
        hostname=hostname,
        status="up",
        ports=ports or [],
    )


def test_rule_registry_contains_all_rules():
    reg = RuleRegistry()
    rules = reg.get_all_rules()
    rule_ids = {r.rule_id for r in rules}
    expected_ids = {
        "RULE-EXP-TELNET",
        "RULE-EXP-FTP",
        "RULE-EXP-HTTP-CLEAR",
        "RULE-EXP-SMB",
        "RULE-EXP-RDP",
        "RULE-EXP-SSH",
        "RULE-EXP-DB",
        "RULE-EXP-ADMIN",
        "RULE-OBS-BROAD-PORTS",
        "RULE-OBS-UNKNOWN-SERVICE",
        "RULE-OBS-LEGACY-VERSION",
    }
    assert expected_ids.issubset(rule_ids)
    assert len(reg.get_host_rules()) == 1
    assert len(reg.get_port_rules()) == 10


def test_telnet_rule():
    rule = TelnetExposureRule()
    host = _make_host()

    # Match with service banner -> 1.0 confidence
    p_confirmed = DiscoveredPort(port_number=23, protocol="tcp", state="open", service_name="telnet", product="Linux telnetd")
    m1 = rule.evaluate(host, p_confirmed)
    assert m1 is not None
    assert m1.rule_id == "RULE-EXP-TELNET"
    assert m1.title == "Telnet service observed"
    assert m1.severity == "High"
    assert m1.confidence == 1.00
    assert "Linux telnetd" in m1.evidence

    # Match on port 23 heuristic only -> 0.70 confidence
    p_heuristic = DiscoveredPort(port_number=23, protocol="tcp", state="open", service_name="")
    m2 = rule.evaluate(host, p_heuristic)
    assert m2 is not None
    assert m2.confidence == 0.70
    assert "heuristic" in m2.evidence.lower()

    # Closed port -> No match
    p_closed = DiscoveredPort(port_number=23, protocol="tcp", state="closed", service_name="telnet")
    assert rule.evaluate(host, p_closed) is None

    # Unrelated port -> No match
    p_other = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http")
    assert rule.evaluate(host, p_other) is None


def test_ftp_rule():
    rule = FtpExposureRule()
    host = _make_host()

    p_open = DiscoveredPort(port_number=21, protocol="tcp", state="open", service_name="ftp", product="vsftpd", version="3.0.3")
    m = rule.evaluate(host, p_open)
    assert m is not None
    assert m.title == "FTP service observed"
    assert m.severity == "Medium"
    assert m.confidence == 1.00

    p_heuristic = DiscoveredPort(port_number=21, protocol="tcp", state="open")
    m_heur = rule.evaluate(host, p_heuristic)
    assert m_heur is not None
    assert m_heur.confidence == 0.70


def test_http_rule():
    rule = CleartextHttpRule()
    host = _make_host()

    p_http = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="nginx")
    m = rule.evaluate(host, p_http)
    assert m is not None
    assert m.title == "HTTP service observed"
    assert m.severity == "Medium"
    assert m.confidence == 0.90

    # Ensure no speculative vulnerability or missing redirect claims
    combined = (m.description + " " + m.evidence).lower()
    assert "missing redirection" not in combined
    assert "missing https" not in combined
    assert "vulnerable" not in combined
    assert "exploit" not in combined
    assert "password" not in combined

    # HTTPS should not trigger cleartext HTTP rule
    p_https = DiscoveredPort(port_number=443, protocol="tcp", state="open", service_name="https")
    assert rule.evaluate(host, p_https) is None


def test_smb_rule():
    rule = SmbExposureRule()
    host = _make_host()

    p_smb = DiscoveredPort(port_number=445, protocol="tcp", state="open", service_name="microsoft-ds", product="Windows 10 SMB")
    m = rule.evaluate(host, p_smb)
    assert m is not None
    assert m.title == "SMB service exposed"
    assert m.severity == "High"
    assert m.confidence == 1.00


def test_rdp_rule():
    rule = RdpExposureRule()
    host = _make_host()

    p_rdp = DiscoveredPort(port_number=3389, protocol="tcp", state="open", service_name="ms-wbt-server")
    m = rule.evaluate(host, p_rdp)
    assert m is not None
    assert m.title == "RDP service exposed"
    assert m.severity == "Medium"


def test_ssh_rule():
    rule = SshExposureRule()
    host = _make_host()

    p_ssh = DiscoveredPort(port_number=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH", version="9.0")
    m = rule.evaluate(host, p_ssh)
    assert m is not None
    assert m.title == "SSH service exposed"
    assert m.severity == "Low"
    assert m.confidence == 1.00


def test_database_exposure_rule():
    rule = DatabaseExposureRule()
    host = _make_host()

    db_test_cases = [
        (3306, "mysql", "MySQL"),
        (5432, "postgresql", "PostgreSQL"),
        (1433, "ms-sql-s", "Microsoft SQL Server"),
        (1521, "oracle-tns", "Oracle Database"),
        (27017, "mongodb", "MongoDB"),
        (6379, "redis", "Redis"),
    ]

    for port_num, svc, expected_name in db_test_cases:
        p = DiscoveredPort(port_number=port_num, protocol="tcp", state="open", service_name=svc)
        m = rule.evaluate(host, p)
        assert m is not None
        assert m.title == "Database listener observed"
        assert m.severity == "High"
        assert expected_name in m.description


def test_admin_interface_rule():
    rule = AdminInterfaceRule()
    host = _make_host()

    p_vnc = DiscoveredPort(port_number=5900, protocol="tcp", state="open", service_name="vnc")
    m = rule.evaluate(host, p_vnc)
    assert m is not None
    assert m.title == "Administrative interface observed"
    assert "VNC" in m.description

    p_webmin = DiscoveredPort(port_number=10000, protocol="tcp", state="open", service_name="webmin")
    m2 = rule.evaluate(host, p_webmin)
    assert m2 is not None
    assert "Webmin" in m2.description


def test_broad_open_ports_rule():
    rule = BroadOpenPortsRule()

    # Host with 5 open ports -> No match
    ports_5 = [DiscoveredPort(port_number=i, state="open") for i in range(1, 6)]
    host_normal = _make_host(ports=ports_5)
    assert rule.evaluate(host_normal) is None

    # Host with 12 open ports -> Match
    ports_12 = [DiscoveredPort(port_number=i, state="open") for i in range(1, 13)]
    host_broad = _make_host(ports=ports_12)
    m = rule.evaluate(host_broad)
    assert m is not None
    assert m.title == "Broad open-port exposure"
    assert m.severity == "Medium"
    assert m.confidence == 0.90
    assert "12 open ports" in m.evidence


def test_unknown_service_rule():
    rule = UnknownServiceRule()
    host = _make_host()

    # High non-standard port with unknown service
    p_unk = DiscoveredPort(port_number=49152, protocol="tcp", state="open", service_name="unknown")
    m = rule.evaluate(host, p_unk)
    assert m is not None
    assert m.title == "Unknown service identity"
    assert m.severity == "Low"

    # Known standard port 80 with service http should not trigger unknown
    p_known = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="Apache")
    assert rule.evaluate(host, p_known) is None


def test_legacy_version_rule():
    rule = LegacyServiceRule()
    host = _make_host()

    # Legacy Apache 2.2 -> High match
    p_apache_old = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="Apache httpd", version="2.2.34")
    m_apache = rule.evaluate(host, p_apache_old)
    assert m_apache is not None
    assert m_apache.severity == "High"
    assert "2.2.34" in m_apache.evidence

    # Modern Apache 2.4 -> No match
    p_apache_new = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="Apache httpd", version="2.4.58")
    assert rule.evaluate(host, p_apache_new) is None

    # Legacy OpenSSH 6.6 -> Medium match
    p_ssh_old = DiscoveredPort(port_number=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH", version="6.6.1p1")
    m_ssh = rule.evaluate(host, p_ssh_old)
    assert m_ssh is not None
    assert m_ssh.severity == "Medium"

    # Modern OpenSSH 9.3 -> No match
    p_ssh_new = DiscoveredPort(port_number=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH", version="9.3p1")
    assert rule.evaluate(host, p_ssh_new) is None

    # Explicit SMBv1 banner -> Critical match
    p_smb1 = DiscoveredPort(port_number=445, protocol="tcp", state="open", service_name="microsoft-ds", extra_info="SMBv1 enabled")
    m_smb1 = rule.evaluate(host, p_smb1)
    assert m_smb1 is not None
    assert m_smb1.severity == "Critical"

    # Missing or empty version evidence -> No match (omitted)
    p_no_ver = DiscoveredPort(port_number=80, protocol="tcp", state="open", service_name="http", product="Apache httpd", version="")
    assert rule.evaluate(host, p_no_ver) is None

    p_no_info = DiscoveredPort(port_number=22, protocol="tcp", state="open", service_name="ssh", product="", version="")
    assert rule.evaluate(host, p_no_info) is None
