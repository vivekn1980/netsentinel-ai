"""Nmap XML parser for NetSentinel AI.

Extracts structured host, port, service, OS, and scan metadata from Nmap XML output.
Handles malformed, truncated, and edge-case XML gracefully.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List, Optional

from netsentinel.core.models import DiscoveredHost, DiscoveredPort, ScanResult


class NmapXmlParser:
    """Robust parser for Nmap XML output."""

    @classmethod
    def parse(cls, xml_text: str) -> ScanResult:
        """Parses raw Nmap XML text into structured ScanResult entity."""
        if not xml_text or not xml_text.strip():
            return ScanResult(
                success=False,
                error_message="Empty or missing XML scan output.",
            )

        root = cls._parse_element_tree(xml_text)
        if root is None or root.tag != "nmaprun":
            return ScanResult(
                success=False,
                error_message="Malformed, invalid, or non-Nmap XML scan output.",
            )

        # Extract nmaprun metadata
        nmap_version = root.attrib.get("version", "")
        start_str = root.attrib.get("startstr", "")
        elapsed_sec = 0.0

        runstats = root.find("runstats")
        finish_str = ""
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                finish_str = finished.attrib.get("timestr", "")
                try:
                    elapsed_sec = float(finished.attrib.get("elapsed", "0.0"))
                except ValueError:
                    elapsed_sec = 0.0

        discovered_hosts: List[DiscoveredHost] = []

        # Iterate over all <host> entries
        for host_elem in root.findall("host"):
            host = cls._parse_host(host_elem)
            if host is not None:
                discovered_hosts.append(host)

        return ScanResult(
            success=True,
            hosts=discovered_hosts,
            start_time=start_str,
            finish_time=finish_str,
            elapsed_seconds=elapsed_sec,
            nmap_version=nmap_version,
            raw_xml=xml_text,
        )

    @classmethod
    def _parse_element_tree(cls, xml_text: str) -> Optional[ET.Element]:
        """Tries parsing XML, with fallback repair for truncated scans."""
        try:
            return ET.fromstring(xml_text.strip())
        except ET.ParseError:
            pass

        # Attempt recovery if XML was truncated mid-scan (e.g. cancelled scan)
        trimmed = xml_text.strip()
        if "<nmaprun" in trimmed and "</nmaprun>" not in trimmed:
            for closing in [
                "</port></ports></host></nmaprun>",
                "</ports></host></nmaprun>",
                "</host></nmaprun>",
                "</nmaprun>",
            ]:
                try:
                    return ET.fromstring(trimmed + closing)
                except ET.ParseError:
                    continue

        return None

    @classmethod
    def _parse_host(cls, host_elem: ET.Element) -> Optional[DiscoveredHost]:
        """Extracts host details including addresses, hostnames, OS, and ports."""
        status_elem = host_elem.find("status")
        status_state = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"

        # Extract addresses
        ip_address = ""
        ipv4 = None
        ipv6 = None
        mac_address = ""
        vendor = ""

        for addr in host_elem.findall("address"):
            atype = addr.attrib.get("addrtype", "")
            aval = addr.attrib.get("addr", "")
            if atype == "ipv4":
                ipv4 = aval
                if not ip_address:
                    ip_address = aval
            elif atype == "ipv6":
                ipv6 = aval
                if not ip_address:
                    ip_address = aval
            elif atype == "mac":
                mac_address = aval
                vendor = addr.attrib.get("vendor", "")

        # Fallback if no specific ipv4/ipv6 type
        if not ip_address:
            for addr in host_elem.findall("address"):
                ip_address = addr.attrib.get("addr", "")
                if ip_address:
                    break

        if not ip_address:
            # Cannot track an asset without an IP/address identifier
            return None

        # Extract hostnames
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                h_name = hn.attrib.get("name", "")
                if h_name:
                    hostname = h_name
                    break

        # Extract OS matches
        os_name = ""
        os_accuracy = 0
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.attrib.get("name", "")
                try:
                    os_accuracy = int(osmatch.attrib.get("accuracy", "0"))
                except ValueError:
                    os_accuracy = 0

        # Extract ports
        ports_list: List[DiscoveredPort] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port = cls._parse_port(port_elem)
                if port is not None:
                    ports_list.append(port)

        return DiscoveredHost(
            ip_address=ip_address,
            ipv4=ipv4,
            ipv6=ipv6,
            mac_address=mac_address,
            vendor=vendor,
            hostname=hostname,
            status=status_state,
            os_name=os_name,
            os_accuracy=os_accuracy,
            ports=ports_list,
        )

    @classmethod
    def _parse_port(cls, port_elem: ET.Element) -> Optional[DiscoveredPort]:
        """Extracts port number, protocol, state, and service details."""
        try:
            port_num = int(port_elem.attrib.get("portid", "0"))
        except ValueError:
            return None

        protocol = port_elem.attrib.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        port_state = state_elem.attrib.get("state", "open") if state_elem is not None else "open"

        service_name = ""
        product = ""
        version = ""
        extra_info = ""
        cpe = ""

        service_elem = port_elem.find("service")
        if service_elem is not None:
            service_name = service_elem.attrib.get("name", "")
            product = service_elem.attrib.get("product", "")
            version = service_elem.attrib.get("version", "")
            extra_info = service_elem.attrib.get("extrainfo", "")

            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None and cpe_elem.text:
                cpe = cpe_elem.text.strip()

        return DiscoveredPort(
            port_number=port_num,
            protocol=protocol,
            state=port_state,
            service_name=service_name,
            product=product,
            version=version,
            extra_info=extra_info,
            cpe=cpe,
        )
