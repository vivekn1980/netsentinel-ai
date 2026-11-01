"""Unit tests for DependencyDetector module and authoritative Nmap engine verification."""

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from netsentinel.core.config import ConfigManager
from netsentinel.core.dependencies import (
    DependencyDetector,
    DependencyItem,
    DiagnosticReport,
    NmapReadinessState,
    NmapVerificationResult,
)


def test_diagnostics_report_generation():
    """Verify that run_diagnostics generates a valid structured DiagnosticReport."""
    report = DependencyDetector.run_diagnostics()
    assert isinstance(report, DiagnosticReport)
    assert len(report.items) >= 4

    # Verify required dependencies
    categories = [i.category for i in report.items]
    assert "required" in categories
    assert "optional" in categories
    assert "advanced" in categories

    # Python runtime must be available
    py_item = next(i for i in report.items if i.name == "Python Runtime")
    assert py_item.available is True
    assert "64-bit" in py_item.version

    # SQLite must be available
    sql_item = next(i for i in report.items if i.name == "SQLite Storage Engine")
    assert sql_item.available is True

    # PySide6 must be available
    pyside_item = next(i for i in report.items if i.name == "PySide6 GUI Framework")
    assert pyside_item.available is True

    # TCP Connect scan availability strictly tracks authoritative engine readiness
    expected_tcp = report.nmap_readiness in (
        NmapReadinessState.READY_STANDARD,
        NmapReadinessState.READY_ELEVATED,
    )
    assert report.can_tcp_connect_scan is expected_tcp


def test_npcap_check_is_safe():
    """Verify that checking Npcap does not raise or mutate system settings."""
    avail, name, loc = DependencyDetector.check_npcap_driver()
    assert isinstance(avail, bool)
    assert isinstance(name, str)
    assert isinstance(loc, str)


def test_missing_executable_returns_missing(tmp_path: Path):
    """Verify non-existent executable returns Missing state."""
    missing_exe = tmp_path / "bin" / "nonexistent_nmap.exe"
    res = DependencyDetector.verify_candidate(missing_exe)
    assert res.state == NmapReadinessState.MISSING
    assert "not found" in res.error_message.lower()


def test_executable_crash_or_nonzero_returns_launch_error(tmp_path: Path):
    """Verify executable that returns non-zero exit code is classified as LaunchError."""
    fake_exe = tmp_path / "nmap.exe"
    fake_exe.touch()

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=1,
        stdout="",
        stderr="VCRUNTIME140.dll missing",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.LAUNCH_ERROR
        assert "exit code 1" in res.error_message
        assert "VCRUNTIME140.dll" in res.error_message


def test_executable_timeout_returns_launch_error(tmp_path: Path):
    """Verify executable that hangs during probe is aborted and classified as LaunchError."""
    fake_exe = tmp_path / "nmap.exe"
    fake_exe.touch()

    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=[str(fake_exe), "-V"], timeout=5),
    ):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.LAUNCH_ERROR
        assert "timed out" in res.error_message.lower()


def test_executable_invalid_version_returns_launch_error(tmp_path: Path):
    """Verify executable that outputs unrecognized version string is classified as LaunchError."""
    fake_exe = tmp_path / "nmap.exe"
    fake_exe.touch()

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=0,
        stdout="Some other utility v2.1.0\nCopyright 2026",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.LAUNCH_ERROR
        assert "did not output a valid Nmap version" in res.error_message


def test_valid_executable_missing_nmap_services_returns_data_files_missing(tmp_path: Path, monkeypatch):
    """Verify executable without nmap-services data file is classified as DataFilesMissing."""
    fake_dir = tmp_path / "nmap_isolated"
    fake_dir.mkdir(parents=True)
    fake_exe = fake_dir / "nmap.exe"
    fake_exe.touch()

    # Clear NMAPDIR and isolate search paths
    monkeypatch.delenv("NMAPDIR", raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "empty_pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "empty_pfx86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty_localapp"))

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.DATA_FILES_MISSING
        assert "nmap-services" in res.missing_data_files
        assert "nmap-services" in res.error_message


def test_valid_executable_with_data_files_standard_user(tmp_path: Path):
    """Verify complete executable and services file with standard user returns ReadyStandard."""
    app_dir = tmp_path / "portable_app"
    app_dir.mkdir(parents=True)
    fake_exe = app_dir / "nmap.exe"
    fake_exe.touch()
    (app_dir / "nmap-services").touch()
    (app_dir / "nmap-service-probes").touch()

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc), \
         patch.object(DependencyDetector, "is_windows_admin", return_value=False), \
         patch.object(DependencyDetector, "check_npcap_driver", return_value=(False, "Not Installed", "")):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.READY_STANDARD
        assert "7.94" in res.version
        assert res.data_dir == app_dir
        assert "nmap-services" in res.present_data_files
        assert "nmap-service-probes" in res.present_data_files


def test_valid_executable_admin_with_npcap_returns_ready_elevated(tmp_path: Path):
    """Verify valid executable with data files, Admin, and Npcap returns ReadyElevated."""
    app_dir = tmp_path / "elevated_app"
    app_dir.mkdir(parents=True)
    fake_exe = app_dir / "nmap.exe"
    fake_exe.touch()
    (app_dir / "nmap-services").touch()

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc), \
         patch.object(DependencyDetector, "is_windows_admin", return_value=True), \
         patch.object(DependencyDetector, "check_npcap_driver", return_value=(True, "Npcap 1.79", "Registry")):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.READY_ELEVATED
        assert res.version.startswith("Nmap version 7.94")


def test_admin_without_npcap_returns_ready_standard_not_elevated(tmp_path: Path):
    """Verify Administrator without Npcap is capped at ReadyStandard and never claims full capabilities."""
    app_dir = tmp_path / "admin_no_npcap"
    app_dir.mkdir(parents=True)
    fake_exe = app_dir / "nmap.exe"
    fake_exe.touch()
    (app_dir / "nmap-services").touch()

    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc), \
         patch.object(DependencyDetector, "is_windows_admin", return_value=True), \
         patch.object(DependencyDetector, "check_npcap_driver", return_value=(False, "Not Installed", "")):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.READY_STANDARD


def test_portable_nmap_detection_in_documented_directory(tmp_path: Path, monkeypatch):
    """Verify portable Nmap in documented bin/nmap/nmap.exe is discovered and verified."""
    app_root = tmp_path / "app_root"
    bin_nmap = app_root / "bin" / "nmap"
    bin_nmap.mkdir(parents=True)
    exe = bin_nmap / "nmap.exe"
    exe.touch()
    (bin_nmap / "nmap-services").touch()

    monkeypatch.setattr(ConfigManager, "get_app_root", lambda: app_root)
    monkeypatch.setattr(ConfigManager, "get_bundle_dir", lambda: app_root)
    monkeypatch.setattr(DependencyDetector, "_get_registry_app_paths", classmethod(lambda cls: []))
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    mock_proc = subprocess.CompletedProcess(
        args=[str(exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.find_and_verify_nmap()
        assert res.state == NmapReadinessState.READY_STANDARD
        assert res.executable_path == exe
        assert res.is_bundled is True


def test_standard_windows_installation_detection(tmp_path: Path, monkeypatch):
    """Verify standard Program Files installation is discovered when portable is absent."""
    pf_dir = tmp_path / "Program Files" / "Nmap"
    pf_dir.mkdir(parents=True)
    exe = pf_dir / "nmap.exe"
    exe.touch()
    (pf_dir / "nmap-services").touch()

    monkeypatch.setattr(ConfigManager, "get_app_root", lambda: tmp_path / "empty_app")
    monkeypatch.setattr(ConfigManager, "get_bundle_dir", lambda: tmp_path / "empty_bundle")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "empty_pfx86"))
    monkeypatch.setattr(DependencyDetector, "_get_registry_app_paths", classmethod(lambda cls: []))
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    mock_proc = subprocess.CompletedProcess(
        args=[str(exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.find_and_verify_nmap()
        assert res.state == NmapReadinessState.READY_STANDARD
        assert res.executable_path == exe
        assert res.is_bundled is False


def test_registry_app_paths_detection(tmp_path: Path, monkeypatch):
    """Verify Nmap discovered via Windows Registry App Paths."""
    reg_dir = tmp_path / "RegistryNmap"
    reg_dir.mkdir(parents=True)
    exe = reg_dir / "nmap.exe"
    exe.touch()
    (reg_dir / "nmap-services").touch()

    monkeypatch.setattr(ConfigManager, "get_app_root", lambda: tmp_path / "empty_app")
    monkeypatch.setattr(ConfigManager, "get_bundle_dir", lambda: tmp_path / "empty_bundle")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "empty_pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "empty_pfx86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty_localapp"))
    monkeypatch.setattr(DependencyDetector, "_get_registry_app_paths", classmethod(lambda cls: [exe]))
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    mock_proc = subprocess.CompletedProcess(
        args=[str(exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.find_and_verify_nmap()
        assert res.state == NmapReadinessState.READY_STANDARD
        assert res.executable_path == exe


def test_system_path_detection(tmp_path: Path, monkeypatch):
    """Verify Nmap discovered via system PATH."""
    path_dir = tmp_path / "SystemPathNmap"
    path_dir.mkdir(parents=True)
    exe = path_dir / "nmap.exe"
    exe.touch()
    (path_dir / "nmap-services").touch()

    monkeypatch.setattr(ConfigManager, "get_app_root", lambda: tmp_path / "empty_app")
    monkeypatch.setattr(ConfigManager, "get_bundle_dir", lambda: tmp_path / "empty_bundle")
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "empty_pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "empty_pfx86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty_localapp"))
    monkeypatch.setattr(DependencyDetector, "_get_registry_app_paths", classmethod(lambda cls: []))
    monkeypatch.setattr(shutil, "which", lambda cmd: str(exe) if "nmap" in cmd else None)

    mock_proc = subprocess.CompletedProcess(
        args=[str(exe), "-V"],
        returncode=0,
        stdout="Nmap version 7.94 ( https://nmap.org )\n",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.find_and_verify_nmap()
        assert res.state == NmapReadinessState.READY_STANDARD
        assert res.executable_path == exe


def test_capability_matrix_sets_can_tcp_false_when_nmap_missing(monkeypatch):
    """Verify capability matrix strictly disables can_tcp_connect_scan when engine is missing."""
    missing_res = NmapVerificationResult(
        state=NmapReadinessState.MISSING,
        error_message="Nmap binary not found.",
    )
    monkeypatch.setattr(DependencyDetector, "find_and_verify_nmap", classmethod(lambda cls: missing_res))

    report = DependencyDetector.run_diagnostics()
    assert report.can_tcp_connect_scan is False
    assert report.can_service_detect is False
    assert report.can_raw_syn_scan is False
    assert report.nmap_readiness == NmapReadinessState.MISSING
    assert "Degraded (Nmap Engine Missing)" in report.summary_status


def test_isolated_empty_path_detection(monkeypatch, tmp_path: Path):
    """Verify clean Missing result in isolated environment with PATH="" and no installations."""
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("NMAPDIR", raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "empty_pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "empty_pfx86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty_localapp"))
    monkeypatch.setattr(ConfigManager, "get_app_root", lambda: tmp_path / "empty_app")
    monkeypatch.setattr(ConfigManager, "get_bundle_dir", lambda: tmp_path / "empty_bundle")
    monkeypatch.setattr(DependencyDetector, "_get_registry_app_paths", classmethod(lambda cls: []))
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    res = DependencyDetector.find_and_verify_nmap()
    assert res.state == NmapReadinessState.MISSING
    assert res.executable_path is None


def test_executable_status_dll_not_found_returns_clear_remediation(tmp_path: Path):
    """Verify executable returning NTSTATUS 0xC0000135 is diagnosed with missing runtime DLL remediation."""
    fake_exe = tmp_path / "nmap.exe"
    fake_exe.touch()

    # 3221225781 is 0xC0000135 (STATUS_DLL_NOT_FOUND)
    mock_proc = subprocess.CompletedProcess(
        args=[str(fake_exe), "-V"],
        returncode=3221225781,
        stdout="",
        stderr="",
    )
    with patch("subprocess.run", return_value=mock_proc):
        res = DependencyDetector.verify_candidate(fake_exe)
        assert res.state == NmapReadinessState.LAUNCH_ERROR
        assert "0xC0000135" in res.error_message
        assert "STATUS_DLL_NOT_FOUND" in res.error_message

    with patch("netsentinel.core.dependencies.DependencyDetector.find_and_verify_nmap", return_value=res):
        report = DependencyDetector.run_diagnostics()
        engine_item = next(i for i in report.items if i.name == "Nmap Discovery Engine")
        assert "winget install Microsoft.VCRedist.2013.x86" in engine_item.remediation

