"""Unit tests for NmapEngine argument construction, execution, and cancellation."""

from pathlib import Path
import subprocess
import pytest
from unittest.mock import MagicMock, patch

from netsentinel.core.nmap_engine import NmapEngine, NmapExecutionResult, DEFAULT_SCAN_PORTS


def test_nmap_engine_arg_construction_tcp_connect(tmp_path: Path):
    """Test argument generation for Profile A: TCP Connect scan."""
    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.touch()

    engine = NmapEngine(nmap_path=fake_nmap)
    assert engine.is_available is True

    cmd = engine.build_args("192.168.1.1", profile="Safe TCP Connect Scan (-sT)")
    assert cmd[0] == str(fake_nmap)
    assert "-sT" in cmd
    assert "-T3" in cmd
    assert "-Pn" in cmd
    assert "-oX" in cmd
    assert "-" in cmd
    assert "--unprivileged" not in cmd
    assert "-p" in cmd
    assert DEFAULT_SCAN_PORTS in cmd
    assert cmd[-1] == "192.168.1.1"


def test_nmap_engine_arg_construction_service_detect(tmp_path: Path):
    """Test argument generation for Profile B: Service Discovery."""
    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.touch()

    engine = NmapEngine(nmap_path=fake_nmap)
    cmd = engine.build_args("10.0.0.1", profile="Service & Version Detection (-sV)", ports="80,443")
    assert "-sT" in cmd
    assert "-sV" in cmd
    assert "--version-light" in cmd
    assert "-Pn" in cmd
    assert "--unprivileged" not in cmd
    assert "-p" in cmd
    assert "80,443" in cmd
    assert cmd[-1] == "10.0.0.1"


def test_nmap_engine_arg_construction_host_discovery(tmp_path: Path):
    """Test argument generation for Profile C: Host Discovery ping sweep."""
    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.touch()

    engine = NmapEngine(nmap_path=fake_nmap)
    cmd = engine.build_args("192.168.1.0/24", profile="Host Discovery Ping Sweep (-sn)")
    assert "-sn" in cmd
    assert "-T3" in cmd
    assert "--unprivileged" not in cmd
    assert "-sT" not in cmd
    assert "-Pn" not in cmd
    assert "-p" not in cmd
    assert cmd[-1] == "192.168.1.0/24"


def test_nmap_xml_parser_parses_arp_host_discovery_zero_ports():
    """Regression test: NmapXmlParser parses ARP host discovery XML with 0 ports into an active host."""
    from netsentinel.core.xml_parser import NmapXmlParser

    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -oX - -sn -T3 192.168.1.16" start="1793509151" version="7.80">
    <host>
        <status state="up" reason="arp-response" reason_ttl="0"/>
        <address addr="192.168.1.16" addrtype="ipv4"/>
        <address addr="BC:D2:2C:1B:24:C0" addrtype="mac"/>
        <hostnames/>
        <times srtt="6000" rttvar="6000" to="100000"/>
    </host>
    <runstats><finished time="1793509151" elapsed="1.31" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
    </nmaprun>"""

    parsed = NmapXmlParser.parse(xml_data)
    assert parsed.success is True
    assert len(parsed.hosts) == 1
    host = parsed.hosts[0]
    assert host.ip_address == "192.168.1.16"
    assert host.status == "up"
    assert host.mac_address == "BC:D2:2C:1B:24:C0"
    assert len(host.ports) == 0


def test_nmap_xml_parser_parses_zero_hosts_cleanly():
    """Regression test: NmapXmlParser handles 0 hosts discovered cleanly without marking scan failed."""
    from netsentinel.core.xml_parser import NmapXmlParser

    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -oX - -sn -T3 192.168.1.99" start="1793509154" version="7.80">
    <runstats><finished time="1793509154" elapsed="3.03" exit="success"/><hosts up="0" down="1" total="1"/></runstats>
    </nmaprun>"""

    parsed = NmapXmlParser.parse(xml_data)
    assert parsed.success is True
    assert len(parsed.hosts) == 0



def test_nmap_engine_unavailable_execution():
    """Test that execution fails safely when Nmap executable is not found."""
    engine = NmapEngine(nmap_path=Path("C:/nonexistent/path/nmap.exe"))
    res = engine.execute_scan("127.0.0.1")
    assert res.success is False
    assert "not available" in res.error_message.lower()


def test_nmap_engine_mock_successful_run(tmp_path: Path):
    """Test successful scan execution with mocked subprocess."""
    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.touch()

    engine = NmapEngine(nmap_path=fake_nmap)

    mock_proc = MagicMock()
    mock_proc.communicate.return_value = ("<nmaprun></nmaprun>", "")
    mock_proc.returncode = 0
    mock_proc.stderr.readline.side_effect = ["Stats: 0:00:02 elapsed; 0 hosts completed\n", ""]

    with patch("subprocess.Popen", return_value=mock_proc):
        logs = []
        res = engine.execute_scan("127.0.0.1", status_callback=lambda l: logs.append(l))
        assert res.success is True
        assert res.xml_output == "<nmaprun></nmaprun>"
        assert len(logs) == 1
        assert "Stats" in logs[0]


def test_nmap_engine_mock_cancellation(tmp_path: Path):
    """Test cancellation terminates the active process and flags cancelled state."""
    fake_nmap = tmp_path / "nmap.exe"
    fake_nmap.touch()

    engine = NmapEngine(nmap_path=fake_nmap)

    mock_proc = MagicMock()
    mock_proc.pid = 12345
    mock_proc.poll.return_value = None

    with patch("subprocess.Popen", return_value=mock_proc):
        engine._active_process = mock_proc
        engine._is_cancelling = False

        with patch("subprocess.run") as mock_run:
            cancelled = engine.cancel()
            assert cancelled is True
            assert engine._is_cancelling is True
            if subprocess.sys.platform == "win32":
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert "taskkill" in args
                assert "12345" in args
