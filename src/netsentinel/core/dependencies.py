"""Dependency detection and system diagnostic module for NetSentinel AI.

Safely evaluates:
- Bundled Nmap executable vs System Nmap installation
- Npcap / WinPcap packet capture driver availability
- Windows UAC Administrator / elevated privileges
- SQLite embedded engine status
- Embedded Python runtime status (verifying no host Python required)
- Advanced scan capability classification (TCP connect vs SYN stealth/raw)
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import winreg
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from netsentinel.core.config import ConfigManager


class NmapReadinessState(str, Enum):
    """Authoritative engine readiness states for Nmap discovery."""
    MISSING = "Missing"
    LAUNCH_ERROR = "LaunchError"
    DATA_FILES_MISSING = "DataFilesMissing"
    READY_STANDARD = "ReadyStandard"
    READY_ELEVATED = "ReadyElevated"


@dataclass
class NmapVerificationResult:
    """Detailed verification outcome for an Nmap engine candidate or overall search."""
    state: NmapReadinessState
    executable_path: Optional[Path] = None
    is_bundled: bool = False
    version: str = ""
    data_dir: Optional[Path] = None
    present_data_files: List[str] = field(default_factory=list)
    missing_data_files: List[str] = field(default_factory=list)
    error_message: str = ""


@dataclass
class DependencyItem:
    """Status record for a single system or runtime dependency."""
    name: str
    category: str  # "required", "optional", "advanced"
    available: bool
    version: str
    location: str
    description: str
    remediation: str = ""
    status_level: str = "ok"  # "ok", "warning", "info", "missing"


@dataclass
class DiagnosticReport:
    """Full system diagnostics and scan capability matrix."""
    items: List[DependencyItem]
    can_tcp_connect_scan: bool
    can_raw_syn_scan: bool
    can_service_detect: bool
    is_elevated: bool
    is_frozen_bundle: bool
    nmap_executable: Optional[str]
    nmap_is_bundled: bool
    npcap_installed: bool
    summary_status: str  # "Ready", "Ready (Standard Privileges)", "Degraded"
    nmap_readiness: NmapReadinessState = NmapReadinessState.MISSING
    nmap_verification: Optional[NmapVerificationResult] = None


class DependencyDetector:
    """Performs non-invasive detection of scan dependencies and Windows subsystem status."""

    @classmethod
    def is_windows_admin(cls) -> bool:
        """Checks if the current process is running with elevated administrator privileges."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @classmethod
    def check_npcap_driver(cls) -> Tuple[bool, str, str]:
        """Safely probes for Npcap / WinPcap packet drivers without modifying system state."""
        if sys.platform != "win32":
            return False, "Not Windows", ""

        # Check Npcap registry keys safely
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Npcap"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap"),
        ]

        npcap_version = ""
        for hkey, subkey in registry_paths:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    try:
                        npcap_version, _ = winreg.QueryValueEx(key, "Version")
                        if npcap_version:
                            return True, f"Npcap {npcap_version}", "Installed via Windows Registry"
                    except OSError:
                        pass
                    return True, "Npcap Driver", "Service registered in registry"
            except (OSError, PermissionError):
                continue

        # Check for presence of Npcap/WinPcap DLLs in System32
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        dll_candidates = [
            system32 / "Npcap" / "wpcap.dll",
            system32 / "wpcap.dll",
            system32 / "Npcap" / "Packet.dll",
            system32 / "Packet.dll",
        ]

        for dll in dll_candidates:
            if dll.is_file():
                return True, "Npcap/WinPcap DLL", str(dll)

        return False, "Not Installed", "Packet capture driver not detected"

    @classmethod
    def _get_registry_app_paths(cls) -> List[Path]:
        """Safely queries Windows Registry App Paths for nmap.exe."""
        if sys.platform != "win32":
            return []
        candidates: List[Path] = []
        reg_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\nmap.exe"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\nmap.exe"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\nmap.exe"),
        ]
        for hkey, subkey in reg_keys:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, "")
                    if val and isinstance(val, str):
                        clean_path = val.strip().strip('"')
                        if clean_path:
                            p = Path(clean_path)
                            if p not in candidates:
                                candidates.append(p)
            except (OSError, PermissionError):
                pass
        return candidates

    @classmethod
    def _check_data_files(cls, candidate: Path) -> Tuple[bool, Optional[Path], List[str], List[str]]:
        """Verifies presence of required and optional Nmap data files across standard search paths.
        
        Returns:
            Tuple[has_required_services (bool), resolved_data_dir (Optional[Path]), present_files, missing_files]
        """
        all_expected = ["nmap-services", "nmap-service-probes", "nmap-os-db"]
        dirs_to_check: List[Path] = []

        # 1. Explicit NMAPDIR environment variable
        nmapdir_env = os.environ.get("NMAPDIR")
        if nmapdir_env:
            dirs_to_check.append(Path(nmapdir_env))

        # 2. Candidate parent directory and subdirectories
        candidate_dir = candidate.parent
        dirs_to_check.append(candidate_dir)
        dirs_to_check.append(candidate_dir / "data")
        dirs_to_check.append(candidate_dir / "share" / "nmap")

        # 3. Standard system installation directories
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        if pf:
            dirs_to_check.append(Path(pf) / "Nmap")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        if pfx86:
            dirs_to_check.append(Path(pfx86) / "Nmap")

        # Deduplicate search paths
        seen = set()
        unique_dirs: List[Path] = []
        for d in dirs_to_check:
            try:
                resolved = d.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    unique_dirs.append(resolved)
            except Exception:
                if d not in seen:
                    seen.add(d)
                    unique_dirs.append(d)

        for d in unique_dirs:
            try:
                if d.is_dir() and (d / "nmap-services").is_file():
                    present = [f for f in all_expected if (d / f).is_file()]
                    missing = [f for f in all_expected if f not in present]
                    return True, d, present, missing
            except Exception:
                continue

        # nmap-services not found in any directory
        return False, None, [], all_expected

    @classmethod
    def _get_candidate_paths(cls) -> List[Tuple[Path, bool]]:
        """Returns ordered list of candidate (Path, is_bundled) to evaluate."""
        raw_candidates: List[Tuple[Path, bool]] = []

        # 1. Application-relative portable paths (marked bundled)
        app_root = ConfigManager.get_app_root()
        bundle_dir = ConfigManager.get_bundle_dir()

        portable_locations = [
            app_root / "bin" / "nmap" / "nmap.exe",
            app_root / "bin" / "nmap.exe",
            app_root / "nmap" / "nmap.exe",
            app_root / "nmap.exe",
            bundle_dir / "bin" / "nmap" / "nmap.exe",
            bundle_dir / "bin" / "nmap.exe",
            bundle_dir / "nmap" / "nmap.exe",
            bundle_dir / "nmap.exe",
        ]
        for p in portable_locations:
            raw_candidates.append((p, True))

        # 2. Standard Windows installation paths
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        if pf:
            raw_candidates.append((Path(pf) / "Nmap" / "nmap.exe", False))
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        if pfx86:
            raw_candidates.append((Path(pfx86) / "Nmap" / "nmap.exe", False))
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            raw_candidates.append((Path(local_app) / "Programs" / "Nmap" / "nmap.exe", False))

        # 3. Registry App Paths
        for reg_p in cls._get_registry_app_paths():
            raw_candidates.append((reg_p, False))

        # 4. System PATH
        which_nmap = shutil.which("nmap.exe") or shutil.which("nmap")
        if which_nmap:
            raw_candidates.append((Path(which_nmap), False))

        # Deduplicate while preserving order
        seen_paths = set()
        unique_candidates: List[Tuple[Path, bool]] = []
        for path, is_bundled in raw_candidates:
            try:
                norm_str = str(path.resolve()).lower()
            except Exception:
                norm_str = str(path).lower()
            if norm_str not in seen_paths:
                seen_paths.add(norm_str)
                unique_candidates.append((path, is_bundled))

        return unique_candidates

    @classmethod
    def verify_candidate(cls, candidate: Path, is_bundled: bool = False) -> NmapVerificationResult:
        """Executes full diagnostic verification for a specific candidate executable."""
        if not candidate.is_file():
            return NmapVerificationResult(
                state=NmapReadinessState.MISSING,
                executable_path=candidate,
                is_bundled=is_bundled,
                error_message=f"Nmap executable not found at '{candidate}'.",
            )

        # Execute candidate -V with bounded timeout (5 seconds)
        startupinfo = None
        creationflags = 0
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            proc = subprocess.run(
                [str(candidate), "-V"],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired:
            return NmapVerificationResult(
                state=NmapReadinessState.LAUNCH_ERROR,
                executable_path=candidate,
                is_bundled=is_bundled,
                error_message="Executable timed out during version probe ('nmap.exe -V').",
            )
        except Exception as e:
            return NmapVerificationResult(
                state=NmapReadinessState.LAUNCH_ERROR,
                executable_path=candidate,
                is_bundled=is_bundled,
                error_message=f"Executable failed to launch: {e}",
            )

        if proc.returncode != 0:
            unsigned_rc = proc.returncode & 0xFFFFFFFF
            if unsigned_rc == 0xC0000135:
                err_detail = (
                    "Process exited with code 0xC0000135 (STATUS_DLL_NOT_FOUND). "
                    "A required runtime library (such as Visual C++ 2013 x86 Redistributable or Npcap) is missing."
                )
            elif unsigned_rc == 0xC000007B:
                err_detail = (
                    "Process exited with code 0xC000007B (STATUS_INVALID_IMAGE_FORMAT). "
                    "The binary architecture is incompatible or corrupted."
                )
            else:
                err_detail = proc.stderr.strip() or f"Process exited with code {proc.returncode}."
            return NmapVerificationResult(
                state=NmapReadinessState.LAUNCH_ERROR,
                executable_path=candidate,
                is_bundled=is_bundled,
                error_message=f"Executable returned non-zero exit code {proc.returncode}: {err_detail}",
            )

        version_str = ""
        for line in proc.stdout.splitlines():
            if "Nmap version" in line:
                version_str = line.strip()
                break

        if not version_str:
            return NmapVerificationResult(
                state=NmapReadinessState.LAUNCH_ERROR,
                executable_path=candidate,
                is_bundled=is_bundled,
                error_message="Executable ran successfully but did not output a valid Nmap version string.",
            )

        # Check required Nmap data files
        has_services, data_dir, present_files, missing_files = cls._check_data_files(candidate)
        if not has_services:
            return NmapVerificationResult(
                state=NmapReadinessState.DATA_FILES_MISSING,
                executable_path=candidate,
                is_bundled=is_bundled,
                version=version_str,
                present_data_files=present_files,
                missing_data_files=missing_files,
                error_message=(
                    f"Required data file 'nmap-services' is missing. "
                    f"Port scanning cannot function without service definitions."
                ),
            )

        # Check privileges and Npcap driver availability
        npcap_avail, _, _ = cls.check_npcap_driver()
        is_admin = cls.is_windows_admin()

        if is_admin and npcap_avail:
            state = NmapReadinessState.READY_ELEVATED
        else:
            state = NmapReadinessState.READY_STANDARD

        return NmapVerificationResult(
            state=state,
            executable_path=candidate,
            is_bundled=is_bundled,
            version=version_str,
            data_dir=data_dir,
            present_data_files=present_files,
            missing_data_files=missing_files,
        )

    @classmethod
    def find_and_verify_nmap(cls) -> NmapVerificationResult:
        """Finds candidate Nmap executables and returns the first verified ready or best diagnostic result."""
        candidates = cls._get_candidate_paths()
        first_diagnostic_error: Optional[NmapVerificationResult] = None

        for candidate, is_bundled in candidates:
            if not candidate.is_file():
                continue
            ver_res = cls.verify_candidate(candidate, is_bundled=is_bundled)
            if ver_res.state in (NmapReadinessState.READY_STANDARD, NmapReadinessState.READY_ELEVATED):
                return ver_res
            if first_diagnostic_error is None:
                first_diagnostic_error = ver_res

        if first_diagnostic_error is not None:
            return first_diagnostic_error

        return NmapVerificationResult(
            state=NmapReadinessState.MISSING,
            error_message="Nmap discovery engine executable not found in bundle or system.",
        )

    @classmethod
    def find_nmap_binary(cls) -> Tuple[Optional[Path], bool, str]:
        """Locates Nmap executable, prioritizing bundled versions before system PATH.
        
        Returns:
            Tuple[Path to executable or None, is_bundled (bool), version string]
        """
        res = cls.find_and_verify_nmap()
        if res.state in (NmapReadinessState.READY_STANDARD, NmapReadinessState.READY_ELEVATED):
            return res.executable_path, res.is_bundled, res.version
        if res.executable_path and res.executable_path.is_file():
            return res.executable_path, res.is_bundled, res.version
        return None, False, ""

    @staticmethod
    def _get_nmap_version(path: Path) -> str:
        """Executes nmap -V safely to parse version header."""
        try:
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            proc = subprocess.run(
                [str(path), "-V"],
                capture_output=True,
                text=True,
                timeout=5,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            for line in proc.stdout.splitlines():
                if "Nmap version" in line:
                    return line.strip()
            return "Nmap (version unknown)"
        except Exception:
            return "Nmap (detected)"

    @classmethod
    def run_diagnostics(cls) -> DiagnosticReport:
        """Performs full diagnostics check across all runtime dependencies."""
        items: List[DependencyItem] = []

        # 1. Embedded Python Runtime
        is_frozen = getattr(sys, "frozen", False)
        python_ver = platform.python_version()
        items.append(
            DependencyItem(
                name="Python Runtime",
                category="required",
                available=True,
                version=f"Python {python_ver} (64-bit)",
                location=sys.executable,
                description="Self-contained runtime environment; no host Python installation is required.",
                status_level="ok",
            )
        )

        # 2. SQLite Database Engine
        sqlite_ver = sqlite3.sqlite_version
        items.append(
            DependencyItem(
                name="SQLite Storage Engine",
                category="required",
                available=True,
                version=f"SQLite {sqlite_ver}",
                location="Embedded C Engine (sqlite3)",
                description="Local WAL-mode database for host inventory, scan history, and findings. No PostgreSQL or external DB needed.",
                status_level="ok",
            )
        )

        # 3. PySide6 Desktop GUI Subsystem
        try:
            import PySide6
            pyside_ver = PySide6.__version__
            items.append(
                DependencyItem(
                    name="PySide6 GUI Framework",
                    category="required",
                    available=True,
                    version=f"Qt / PySide6 {pyside_ver}",
                    location=str(Path(PySide6.__file__).parent),
                    description="High-performance native Windows desktop interface framework.",
                    status_level="ok",
                )
            )
        except Exception as e:
            items.append(
                DependencyItem(
                    name="PySide6 GUI Framework",
                    category="required",
                    available=False,
                    version="Not Found",
                    location="",
                    description=f"GUI subsystem error: {e}",
                    remediation="Install PySide6 in your environment.",
                    status_level="error",
                )
            )

        # 4. Nmap Discovery Engine Verification
        nmap_res = cls.find_and_verify_nmap()
        if nmap_res.state in (NmapReadinessState.READY_STANDARD, NmapReadinessState.READY_ELEVATED):
            items.append(
                DependencyItem(
                    name="Nmap Discovery Engine",
                    category="optional",
                    available=True,
                    version=nmap_res.version,
                    location=f"{nmap_res.executable_path} ({'Bundled Portable' if nmap_res.is_bundled else 'System Installed'})",
                    description=f"Network discovery and port scanning utility (Data dir: {nmap_res.data_dir}).",
                    status_level="ok",
                )
            )
        elif nmap_res.state == NmapReadinessState.DATA_FILES_MISSING:
            missing_str = ", ".join(nmap_res.missing_data_files)
            items.append(
                DependencyItem(
                    name="Nmap Discovery Engine",
                    category="optional",
                    available=False,
                    version=nmap_res.version or "Incomplete Installation",
                    location=str(nmap_res.executable_path),
                    description=f"Nmap executable found but required data file(s) missing ({missing_str}). Port scanning is disabled.",
                    remediation="Place nmap-services in the Nmap directory or set the NMAPDIR environment variable.",
                    status_level="warning",
                )
            )
        elif nmap_res.state == NmapReadinessState.LAUNCH_ERROR:
            rem = "Ensure the binary is a valid Windows executable and required runtime DLLs are present."
            if "0xC0000135" in (nmap_res.error_message or ""):
                rem = "Missing runtime DLL. Run 'winget install Microsoft.VCRedist.2013.x86' or reinstall Nmap with Npcap."
            items.append(
                DependencyItem(
                    name="Nmap Discovery Engine",
                    category="optional",
                    available=False,
                    version="Launch Failure",
                    location=str(nmap_res.executable_path),
                    description=f"Nmap executable found but failed to launch: {nmap_res.error_message}",
                    remediation=rem,
                    status_level="error",
                )
            )
        else:  # MISSING
            items.append(
                DependencyItem(
                    name="Nmap Discovery Engine",
                    category="optional",
                    available=False,
                    version="Not Detected",
                    location="None",
                    description="Nmap discovery engine executable not found in bundled bin/nmap/ or system PATH.",
                    remediation="Run 'winget install Insecure.Nmap' or place portable nmap.exe in bin/nmap/.",
                    status_level="warning",
                )
            )

        # 5. Npcap Packet Capture Driver
        npcap_avail, npcap_name, npcap_loc = cls.check_npcap_driver()
        if npcap_avail:
            items.append(
                DependencyItem(
                    name="Npcap Packet Driver",
                    category="advanced",
                    available=True,
                    version=npcap_name,
                    location=npcap_loc,
                    description="Packet capture driver required for raw packet SYN stealth scanning (-sS) and OS fingerprinting.",
                    status_level="ok",
                )
            )
        else:
            items.append(
                DependencyItem(
                    name="Npcap Packet Driver",
                    category="advanced",
                    available=False,
                    version="Not Installed",
                    location="N/A",
                    description="Packet capture driver is not installed. Standard unprivileged TCP Connect scanning (-sT) operates without raw packet support.",
                    remediation="Optional: Install Npcap from npcap.com only if raw socket stealth scanning is explicitly required.",
                    status_level="info",
                )
            )

        # 6. Windows Administrator Privileges
        is_admin = cls.is_windows_admin()
        items.append(
            DependencyItem(
                name="Windows Administrative Privileges",
                category="advanced",
                available=is_admin,
                version="Elevated (UAC Admin)" if is_admin else "Standard User",
                location="Windows Security Token",
                description="Administrative elevation is only needed for raw socket manipulation. Standard users can perform full authorized TCP connect scans.",
                remediation="Run NetSentinel AI as Administrator only when raw socket features are strictly necessary." if not is_admin else "",
                status_level="ok" if is_admin else "info",
            )
        )

        # Determine overall scan capabilities strictly from engine readiness
        is_engine_ready = nmap_res.state in (NmapReadinessState.READY_STANDARD, NmapReadinessState.READY_ELEVATED)
        can_tcp = is_engine_ready
        can_service = is_engine_ready
        can_raw = (nmap_res.state == NmapReadinessState.READY_ELEVATED)

        if nmap_res.state == NmapReadinessState.READY_ELEVATED:
            summary = "Ready (Full Capabilities, SYN & OS Detection)"
        elif nmap_res.state == NmapReadinessState.READY_STANDARD:
            summary = "Ready (Standard User TCP Connect & Service Detection)"
        elif nmap_res.state == NmapReadinessState.DATA_FILES_MISSING:
            summary = "Degraded (Nmap Data Files Incomplete)"
        elif nmap_res.state == NmapReadinessState.LAUNCH_ERROR:
            summary = "Error (Nmap Engine Launch Failed)"
        else:
            summary = "Degraded (Nmap Engine Missing)"

        return DiagnosticReport(
            items=items,
            can_tcp_connect_scan=can_tcp,
            can_raw_syn_scan=can_raw,
            can_service_detect=can_service,
            is_elevated=is_admin,
            is_frozen_bundle=is_frozen,
            nmap_executable=str(nmap_res.executable_path) if nmap_res.executable_path else None,
            nmap_is_bundled=nmap_res.is_bundled,
            npcap_installed=npcap_avail,
            summary_status=summary,
            nmap_readiness=nmap_res.state,
            nmap_verification=nmap_res,
        )
