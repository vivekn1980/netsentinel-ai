"""Unit tests for NmapXmlParser entity extraction and error handling."""

import pytest
from netsentinel.core.xml_parser import NmapXmlParser

SAMPLE_VALID_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - 192.168.1.1" startstr="Sat Oct 31 06:00:00 2026" version="7.94">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<host starttime="1700000000" endtime="1700000010">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Netgear"/>
    <hostnames>
        <hostname name="router.home.arpa" type="PTR"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Lighttpd" version="1.4.59" extrainfo="(Unix)" method="probed" conf="10">
                <cpe>cpe:/a:lighttpd:lighttpd:1.4.59</cpe>
            </service>
        </port>
        <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="Lighttpd" version="1.4.59"/>
        </port>
        <port protocol="tcp" portid="23">
            <state state="closed" reason="conn-refused"/>
        </port>
    </ports>
    <os>
        <osmatch name="Embedded Linux (OpenWrt)" accuracy="94"/>
    </os>
</host>
<host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames>
        <hostname name="workstation.corp" type="user"/>
    </hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="9.2p1"/>
        </port>
        <port protocol="tcp" portid="445">
            <state state="filtered"/>
        </port>
    </ports>
</host>
<runstats>
    <finished time="1700000010" timestr="Sat Oct 31 06:00:10 2026" elapsed="10.25" summary="Nmap done at Sat Oct 31 06:00:10 2026; 2 IP addresses (2 hosts up) scanned in 10.25 seconds" exit="success"/>
</runstats>
</nmaprun>
"""

SAMPLE_IPV6_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94" startstr="Sat Oct 31 06:00:00 2026">
<host>
    <status state="up"/>
    <address addr="2001:db8::1" addrtype="ipv6"/>
    <ports>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.25.0"/>
        </port>
    </ports>
</host>
<runstats><finished elapsed="2.5"/></runstats>
</nmaprun>
"""

SAMPLE_HOST_DISCOVERY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun version="7.94">
<host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="gateway" type="PTR"/></hostnames>
</host>
<host>
    <status state="up"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
</host>
<runstats><finished elapsed="0.45"/></runstats>
</nmaprun>
"""


def test_parse_valid_multi_host_xml():
    """Verify parsing of full multi-host scan with services, OS, and MAC addresses."""
    res = NmapXmlParser.parse(SAMPLE_VALID_XML)
    assert res.success is True
    assert res.nmap_version == "7.94"
    assert res.elapsed_seconds == 10.25
    assert len(res.hosts) == 2

    # Check Host 1
    h1 = res.hosts[0]
    assert h1.ip_address == "192.168.1.1"
    assert h1.hostname == "router.home.arpa"
    assert h1.mac_address == "00:11:22:33:44:55"
    assert h1.vendor == "Netgear"
    assert h1.os_name == "Embedded Linux (OpenWrt)"
    assert h1.os_accuracy == 94
    assert len(h1.ports) == 3

    # Check Ports on Host 1
    p80 = next(p for p in h1.ports if p.port_number == 80)
    assert p80.state == "open"
    assert p80.service_name == "http"
    assert p80.product == "Lighttpd"
    assert p80.version == "1.4.59"
    assert "cpe:/a:lighttpd:lighttpd" in p80.cpe

    p23 = next(p for p in h1.ports if p.port_number == 23)
    assert p23.state == "closed"

    # Check Host 2
    h2 = res.hosts[1]
    assert h2.ip_address == "192.168.1.50"
    assert h2.hostname == "workstation.corp"
    assert len(h2.ports) == 2
    p445 = next(p for p in h2.ports if p.port_number == 445)
    assert p445.state == "filtered"


def test_parse_ipv6_xml():
    """Verify parsing of IPv6 target."""
    res = NmapXmlParser.parse(SAMPLE_IPV6_XML)
    assert res.success is True
    assert len(res.hosts) == 1
    assert res.hosts[0].ip_address == "2001:db8::1"
    assert res.hosts[0].ipv6 == "2001:db8::1"
    assert len(res.hosts[0].ports) == 1
    assert res.hosts[0].ports[0].port_number == 80


def test_parse_host_discovery_xml():
    """Verify host discovery ping sweep XML with no ports."""
    res = NmapXmlParser.parse(SAMPLE_HOST_DISCOVERY_XML)
    assert res.success is True
    assert len(res.hosts) == 2
    assert res.hosts[0].ip_address == "10.0.0.1"
    assert res.hosts[0].hostname == "gateway"
    assert len(res.hosts[0].ports) == 0
    assert res.hosts[1].ip_address == "10.0.0.2"


def test_parse_empty_and_malformed_xml():
    """Verify graceful error reporting on invalid XML inputs."""
    # Empty
    res1 = NmapXmlParser.parse("")
    assert res1.success is False
    assert "Empty" in res1.error_message

    # Malformed text
    res2 = NmapXmlParser.parse("This is not XML at all.")
    assert res2.success is False
    assert "Malformed" in res2.error_message


def test_truncated_xml_recovery():
    """Verify recovery parser handles truncated XML from interrupted scans."""
    truncated = (
        '<nmaprun version="7.94" startstr="Sat Oct 31 06:00:00 2026">'
        '<host><status state="up"/><address addr="172.16.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/></port>'
    )
    res = NmapXmlParser.parse(truncated)
    assert res.success is True
    assert len(res.hosts) == 1
    assert res.hosts[0].ip_address == "172.16.0.1"
    assert len(res.hosts[0].ports) == 1
    assert res.hosts[0].ports[0].port_number == 22
