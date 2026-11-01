"""Nmap scan engine for NetSentinel AI.

Handles locating Nmap, safe argument construction, unprivileged execution,
real-time stderr progress capture, and Windows process cancellation.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from netsentinel.core.dependencies import (
    DependencyDetector,
    NmapReadinessState,
    NmapVerificationResult,
)


@dataclass
class NmapExecutionResult:
    """Outcome of an Nmap process execution."""
    success: bool
    command: List[str]
    xml_output: str = ""
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    returncode: int = 0
    error_message: str = ""
    was_cancelled: bool = False
    nmap_version: str = ""


# Default safe common ports for TCP connect scan (covers most standard business/infra services)
DEFAULT_SCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443"


class NmapEngine:
    """Safe Nmap subprocess orchestrator for authorized network discovery."""

    def __init__(self, nmap_path: Optional[Path] = None):
        if nmap_path is not None:
            self._nmap_path: Optional[Path] = Path(nmap_path)
            self._is_bundled = False
            self._version = DependencyDetector._get_nmap_version(self._nmap_path)
            if not self._nmap_path.is_file():
                self._readiness_state = NmapReadinessState.MISSING
                self._verification_result = NmapVerificationResult(
                    state=NmapReadinessState.MISSING,
                    executable_path=self._nmap_path,
                    error_message=f"Nmap executable not found at '{self._nmap_path}'.",
                )
            else:
                self._verification_result = DependencyDetector.verify_candidate(self._nmap_path)
                self._readiness_state = self._verification_result.state
        else:
            res = DependencyDetector.find_and_verify_nmap()
            self._verification_result = res
            self._readiness_state = res.state
            self._nmap_path = res.executable_path
            self._is_bundled = res.is_bundled
            self._version = res.version

        self._active_process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._is_cancelling = False

    @property
    def readiness_state(self) -> NmapReadinessState:
        """Authoritative engine readiness state."""
        return self._readiness_state

    @property
    def verification_result(self) -> Optional[NmapVerificationResult]:
        """Diagnostic verification details for the engine."""
        return self._verification_result

    @property
    def is_available(self) -> bool:
        """Returns True if a valid Nmap executable is located."""
        return self._nmap_path is not None and self._nmap_path.is_file()

    @property
    def is_ready(self) -> bool:
        """Returns True if Nmap is verified ready for scanning (standard or elevated)."""
        return self._readiness_state in (
            NmapReadinessState.READY_STANDARD,
            NmapReadinessState.READY_ELEVATED,
        )

    @property
    def nmap_path(self) -> Optional[Path]:
        return self._nmap_path

    @property
    def is_bundled(self) -> bool:
        return self._is_bundled

    @property
    def version(self) -> str:
        return self._version

    def build_args(
        self,
        target: str,
        profile: str = "tcp_connect",
        ports: Optional[str] = None,
    ) -> List[str]:
        """Constructs safe argument list for Nmap execution without shell interpolation."""
        if not self._nmap_path:
            raise FileNotFoundError("Nmap executable not found on system or bundle.")

        args: List[str] = [str(self._nmap_path)]

        # Normalize profile name
        p_lower = profile.lower()

        # Always output XML to stdout for structured parsing
        args.extend(["-oX", "-"])

        # Periodic status updates on stderr every 2 seconds
        args.extend(["--stats-every", "2s"])


        if "service" in p_lower or "version" in p_lower:
            # Profile B: Service & Version Discovery (skip ping probes with -Pn for unprivileged reliability)
            args.extend(["-sT", "-sV", "--version-light", "-T3", "-Pn"])
            if ports:
                args.extend(["-p", ports])
            else:
                args.extend(["-p", DEFAULT_SCAN_PORTS])
        elif "host" in p_lower or "ping" in p_lower or "-sn" in p_lower:
            # Profile C: Host Discovery Only (No port scanning)
            args.extend(["-sn", "-T3"])
        else:
            # Profile A: Standard Safe TCP Connect Scan (Default, skip ping probes with -Pn)
            args.extend(["-sT", "-T3", "-Pn"])
            if ports:
                args.extend(["-p", ports])
            else:
                args.extend(["-p", DEFAULT_SCAN_PORTS])

        # Target must be the last argument
        args.append(target.strip())
        return args

    def execute_scan(
        self,
        target: str,
        profile: str = "tcp_connect",
        ports: Optional[str] = None,
        timeout_seconds: int = 300,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> NmapExecutionResult:
        """Executes Nmap scan synchronously in the current thread (call from QThread worker)."""
        if not self.is_available:
            return NmapExecutionResult(
                success=False,
                command=[],
                error_message="Nmap binary is not available. Please verify installation or bundle in bin/nmap/.",
                nmap_version=self._version,
            )

        cmd = self.build_args(target, profile, ports)
        start_time = time.time()
        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        self._is_cancelling = False

        creation_flags = 0
        if sys.platform == "win32":
            # CREATE_NEW_PROCESS_GROUP allows targeted process tree termination
            creation_flags |= subprocess.CREATE_NEW_PROCESS_GROUP
            creation_flags |= subprocess.CREATE_NO_WINDOW

        try:
            with self._lock:
                self._active_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=creation_flags,
                )

            proc = self._active_process

            # Background thread to capture and stream stderr in real-time
            def read_stderr():
                try:
                    for line in iter(proc.stderr.readline, ""):
                        if not line or not isinstance(line, str):
                            break
                        clean_line = line.strip()
                        stderr_chunks.append(line)
                        if clean_line and status_callback:
                            status_callback(clean_line)
                except Exception:
                    pass

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            # Read stdout (XML stream)
            stdout_data, _ = proc.communicate(timeout=timeout_seconds)
            stderr_thread.join(timeout=2.0)

            duration = time.time() - start_time
            retcode = proc.returncode

            with self._lock:
                was_cancelled = self._is_cancelling
                self._active_process = None

            if was_cancelled:
                return NmapExecutionResult(
                    success=False,
                    command=cmd,
                    xml_output=stdout_data,
                    stdout=stdout_data,
                    stderr="".join(stderr_chunks),
                    duration_seconds=duration,
                    returncode=retcode,
                    error_message="Scan was cancelled by user.",
                    was_cancelled=True,
                    nmap_version=self._version,
                )

            if retcode != 0:
                err_msg = "".join(stderr_chunks).strip() or f"Nmap exited with error code {retcode}."
                return NmapExecutionResult(
                    success=False,
                    command=cmd,
                    xml_output=stdout_data,
                    stdout=stdout_data,
                    stderr="".join(stderr_chunks),
                    duration_seconds=duration,
                    returncode=retcode,
                    error_message=err_msg,
                    was_cancelled=False,
                    nmap_version=self._version,
                )

            return NmapExecutionResult(
                success=True,
                command=cmd,
                xml_output=stdout_data,
                stdout=stdout_data,
                stderr="".join(stderr_chunks),
                duration_seconds=duration,
                returncode=0,
                was_cancelled=False,
                nmap_version=self._version,
            )

        except subprocess.TimeoutExpired:
            self.cancel()
            duration = time.time() - start_time
            return NmapExecutionResult(
                success=False,
                command=cmd,
                duration_seconds=duration,
                error_message=f"Scan timed out after {timeout_seconds} seconds.",
                was_cancelled=False,
                nmap_version=self._version,
            )
        except Exception as e:
            with self._lock:
                self._active_process = None
            duration = time.time() - start_time
            return NmapExecutionResult(
                success=False,
                command=cmd,
                duration_seconds=duration,
                error_message=f"Process execution error: {e}",
                was_cancelled=False,
                nmap_version=self._version,
            )

    def cancel(self) -> bool:
        """Safely terminates the active Nmap process started by NetSentinel AI."""
        with self._lock:
            proc = self._active_process
            if not proc or proc.poll() is not None:
                return False
            self._is_cancelling = True

        try:
            if sys.platform == "win32":
                # Terminate the process and its immediate subprocesses cleanly using taskkill by PID
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                try:
                    proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, Exception):
                    try:
                        proc.kill()
                        proc.wait(timeout=1)
                    except Exception:
                        pass
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, Exception):
                    try:
                        proc.kill()
                        proc.wait(timeout=1)
                    except Exception:
                        pass
            return True
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=1)
            except Exception:
                pass
            return False
