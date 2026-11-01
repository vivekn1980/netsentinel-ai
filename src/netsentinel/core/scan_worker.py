"""Background scan worker thread for NetSentinel AI.

Orchestrates the asynchronous discovery scan lifecycle without freezing the PySide6 UI:
IDLE -> VALIDATING -> AUTHORIZED -> RUNNING -> PARSING -> SAVING -> COMPLETED
(or CANCELLED / FAILED / TIMEOUT)
"""

from __future__ import annotations

import logging
import platform
import socket
import time
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal

from netsentinel.core.database import DatabaseManager
from netsentinel.core.dependencies import NmapReadinessState
from netsentinel.core.models import (
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_RESOLVED,
    ScanResult,
    ScanSession,
)
from netsentinel.core.nmap_engine import NmapEngine, NmapExecutionResult
from netsentinel.core.security_analyzer import SecurityAnalyzer
from netsentinel.core.validator import TargetValidator
from netsentinel.core.xml_parser import NmapXmlParser

logger = logging.getLogger(__name__)


class ScanWorker(QThread):
    """QThread worker executing discovery scans asynchronously."""

    # Lifecycle & UI signals
    state_changed = Signal(str)           # "VALIDATING", "RUNNING", "PARSING", "SAVING", "COMPLETED", "CANCELLED", "FAILED"
    status_message = Signal(str)          # Detailed narrative message
    log_line = Signal(str)                # Streamed raw scanner message
    scan_finished = Signal(int, bool, str, object)  # session_id, success, message, ScanResult

    def __init__(
        self,
        target: str,
        profile: str,
        db_mgr: DatabaseManager,
        ports: Optional[str] = None,
        timeout_seconds: int = 300,
        engine: Optional[NmapEngine] = None,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.target = target.strip()
        self.profile = profile
        self.ports = ports
        self.timeout_seconds = timeout_seconds
        self.db_mgr = db_mgr
        self.engine = engine or NmapEngine()
        self._is_cancelled = False
        self._finished_emitted = False
        self.session_id: Optional[int] = None

    def _safe_emit_finished(
        self,
        session_id: int,
        success: bool,
        message: str,
        result: Optional[ScanResult] = None,
    ) -> None:
        """Guarantees scan_finished is emitted exactly once per worker run."""
        if not self._finished_emitted:
            self._finished_emitted = True
            self.scan_finished.emit(session_id, success, message, result)

    def run(self) -> None:
        """Executes the scan lifecycle sequentially in background thread with crash protection."""
        try:
            self._execute_scan_lifecycle()
        except Exception as exc:
            logger.exception("Unexpected crash in scan worker lifecycle: %s", exc)
            self._handle_unexpected_crash(exc)
        finally:
            if hasattr(self.db_mgr, "end_scan_operation"):
                self.db_mgr.end_scan_operation()

    def _handle_unexpected_crash(self, exc: Exception) -> None:
        """Recovers from unexpected worker exceptions, terminates subprocesses, and updates DB."""
        err_msg = f"Unexpected scan worker error: {exc}"
        self.log_line.emit(f"[!] Critical worker error: {err_msg}")
        self.status_message.emit(err_msg)
        self.state_changed.emit("FAILED")

        # Safely terminate child engine subprocess if running
        try:
            self.engine.cancel()
        except Exception:
            pass

        # Update database session if one was created
        if self.session_id and self.db_mgr:
            try:
                now_iso = datetime.now().isoformat(timespec="seconds")
                session = self.db_mgr.get_scan_session(self.session_id)
                if session and session.status == "running":
                    session.status = "failed"
                    session.end_time = now_iso
                    session.error_message = err_msg
                    self.db_mgr.update_scan_session(session)
            except Exception as db_err:
                self.log_line.emit(f"[!] Failed to update crashed session in DB: {db_err}")

        # Emit scan_finished exactly once
        self._safe_emit_finished(self.session_id or 0, False, err_msg, None)

    def _execute_scan_lifecycle(self) -> None:
        # 1. VALIDATING
        self.state_changed.emit("VALIDATING")
        self.status_message.emit(f"Validating target '{self.target}' and security parameters...")

        val = TargetValidator.validate(self.target, resolve_dns=True)
        if not val.is_valid:
            err = val.error or "Invalid target specification."
            self.state_changed.emit("FAILED")
            self.status_message.emit(f"Target Validation Error: {err}")
            self._safe_emit_finished(0, False, err, None)
            return

        normalized_target = val.normalized_target

        # Check authoritative engine readiness before initializing database session
        raw_readiness = getattr(self.engine, "readiness_state", None)
        if isinstance(raw_readiness, NmapReadinessState):
            readiness = raw_readiness
        elif isinstance(raw_readiness, str) and raw_readiness in [s.value for s in NmapReadinessState]:
            readiness = NmapReadinessState(raw_readiness)
        else:
            # Fallback if engine is a mock without explicit readiness enum
            if getattr(self.engine, "is_available", False):
                readiness = NmapReadinessState.READY_STANDARD
            else:
                readiness = NmapReadinessState.MISSING

        if readiness not in (NmapReadinessState.READY_STANDARD, NmapReadinessState.READY_ELEVATED):
            ver_res = getattr(self.engine, "verification_result", None)
            if readiness == NmapReadinessState.MISSING:
                err = (
                    "Nmap discovery engine executable not found. "
                    "Run 'winget install Insecure.Nmap' or place portable nmap.exe in bin/nmap/."
                )
            elif readiness == NmapReadinessState.LAUNCH_ERROR:
                err_detail = ver_res.error_message if ver_res and ver_res.error_message else "Execution probe failed."
                err = f"Nmap executable found but failed to launch: {err_detail}"
            elif readiness == NmapReadinessState.DATA_FILES_MISSING:
                err_detail = ver_res.error_message if ver_res and ver_res.error_message else "Required data files missing."
                err = f"Nmap installation incomplete: {err_detail}"
            else:
                err = f"Nmap discovery engine is not ready ({readiness.value if hasattr(readiness, 'value') else readiness})."

            self.state_changed.emit("FAILED")
            self.status_message.emit(err)
            self._safe_emit_finished(0, False, err, None)
            return

        # Acquire scan slot to guard against concurrent database clearing
        if hasattr(self.db_mgr, "start_scan_operation"):
            if not self.db_mgr.start_scan_operation():
                err = "Cannot start scan: Database reset is currently in progress."
                self.state_changed.emit("FAILED")
                self.status_message.emit(err)
                self._safe_emit_finished(0, False, err, None)
                return

        # 2. AUTHORIZED & INITIALIZE DATABASE SESSION
        self.state_changed.emit("AUTHORIZED")
        self.status_message.emit("Scan authorized. Initializing local database session...")

        cmd_preview = " ".join(self.engine.build_args(normalized_target, self.profile, self.ports))
        session = ScanSession(
            target_input=normalized_target,
            profile=self.profile,
            status="running",
            command_executed=cmd_preview,
            nmap_version=self.engine.version,
            configured_ports=self.ports or "",
        )
        self.session_id = self.db_mgr.create_scan_session(session)

        # 3. RUNNING
        self.state_changed.emit("RUNNING")
        self.status_message.emit(f"Executing {self.profile} discovery on {normalized_target}...")
        self.log_line.emit(f"[*] Starting scan session #{self.session_id}: {cmd_preview}")

        # Execute scan via engine
        exec_res: NmapExecutionResult = self.engine.execute_scan(
            target=normalized_target,
            profile=self.profile,
            ports=self.ports,
            timeout_seconds=self.timeout_seconds,
            status_callback=self._on_stderr_line,
        )

        # Check for cancellation
        if exec_res.was_cancelled or self._is_cancelled:
            self.state_changed.emit("CANCELLED")
            self.status_message.emit("Scan was cancelled by user.")
            self.log_line.emit("[!] Scan cancelled. Terminating scanner process.")

            # Attempt to parse whatever partial XML was collected
            partial_scan = NmapXmlParser.parse(exec_res.xml_output)
            partial_scan.success = False
            partial_scan.was_cancelled = True
            partial_scan.error_message = "Scan cancelled by user."
            partial_scan.elapsed_seconds = exec_res.duration_seconds
            partial_scan.nmap_version = exec_res.nmap_version

            self.db_mgr.save_scan_results(self.session_id, partial_scan, cmd_preview)
            self._safe_emit_finished(self.session_id, False, "Scan cancelled by user.", partial_scan)
            return

        # Check for execution failure or non-zero exit
        if not exec_res.success:
            self.state_changed.emit("FAILED")
            self.status_message.emit(f"Scan failed: {exec_res.error_message}")
            self.log_line.emit(f"[!] Scanner error: {exec_res.error_message}")

            failed_scan = ScanResult(
                success=False,
                error_message=exec_res.error_message,
                elapsed_seconds=exec_res.duration_seconds,
                nmap_version=exec_res.nmap_version,
                raw_stderr=exec_res.stderr,
            )
            self.db_mgr.save_scan_results(self.session_id, failed_scan, cmd_preview)
            self._safe_emit_finished(self.session_id, False, exec_res.error_message, failed_scan)
            return

        # 4. PARSING
        self.state_changed.emit("PARSING")
        self.status_message.emit("Parsing Nmap XML discovery stream...")

        parsed_scan: ScanResult = NmapXmlParser.parse(exec_res.xml_output)
        parsed_scan.elapsed_seconds = exec_res.duration_seconds
        parsed_scan.nmap_version = exec_res.nmap_version
        parsed_scan.raw_stdout = exec_res.stdout
        parsed_scan.raw_stderr = exec_res.stderr

        # Enrich host details (hostname & OS) with local system and heuristic fallback
        self._enrich_host_details(parsed_scan)

        if not parsed_scan.success:
            self.state_changed.emit("FAILED")
            err = f"XML Parsing Error: {parsed_scan.error_message}"
            self.status_message.emit(err)
            self.log_line.emit(f"[!] {err}")
            self.db_mgr.save_scan_results(self.session_id, parsed_scan, cmd_preview)
            self._safe_emit_finished(self.session_id, False, err, parsed_scan)
            return

        # 5. SAVING & SECURITY ANALYSIS
        self.state_changed.emit("SAVING")
        total_hosts = len(parsed_scan.hosts)
        self.status_message.emit(f"Persisting {total_hosts} discovered host(s) and running security risk analysis...")

        try:
            self.db_mgr.save_scan_results(self.session_id, parsed_scan, cmd_preview)

            # Perform Security Analysis on discovered hosts
            analyzer = SecurityAnalyzer()
            all_findings = []
            assets_map = {}

            for host in parsed_scan.hosts:
                db_asset = self.db_mgr.get_asset_by_ip(host.ip_address)
                if db_asset and db_asset.id:
                    assets_map[host.ip_address] = db_asset.id
                    host_findings = analyzer.analyze_host(host, asset_id=db_asset.id, session_id=self.session_id)
                    all_findings.extend(host_findings)

            # Persist findings with stable deduplication and user status preservation
            for finding in all_findings:
                self.db_mgr.upsert_security_finding(finding)

            # Check for verified resolution of prior findings on examined hosts
            if parsed_scan.success and not parsed_scan.was_cancelled:
                active_findings = (
                    self.db_mgr.list_security_findings(status=STATUS_NEW)
                    + self.db_mgr.list_security_findings(status=STATUS_OPEN)
                )
                seen_ids = set()
                unique_active = []
                for af in active_findings:
                    if af.id not in seen_ids and af.asset_id in assets_map.values():
                        seen_ids.add(af.id)
                        unique_active.append(af)

                resolutions = analyzer.evaluate_finding_resolutions(
                    scan_result=parsed_scan,
                    session_id=self.session_id,
                    existing_active_findings=unique_active,
                    discovered_assets_map=assets_map,
                )
                for res_finding, reason in resolutions:
                    if res_finding.id:
                        self.db_mgr.update_finding_status(
                            finding_id=res_finding.id,
                            new_status=STATUS_RESOLVED,
                            notes=reason,
                            user_confirmed=False,
                        )
                        self.log_line.emit(f"[*] Verified resolved: {res_finding.title} on {res_finding.ip_address} ({reason})")

            # Update scan session risk summary
            sev_counts = {}
            for f in all_findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            risk_summary_parts = []
            for s in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev_counts.get(s):
                    risk_summary_parts.append(f"{sev_counts[s]} {s}")
            risk_summary_str = ", ".join(risk_summary_parts) if risk_summary_parts else "No high risks identified"

            current_session = self.db_mgr.get_scan_session(self.session_id)
            if current_session:
                current_session.risk_summary = risk_summary_str
                self.db_mgr.update_scan_session(current_session)

            if all_findings:
                self.log_line.emit(f"[+] Security analysis complete: {len(all_findings)} observation(s) recorded ({risk_summary_str}).")
            else:
                self.log_line.emit("[+] Security analysis complete: no immediate risk observations detected.")

        except Exception as e:
            self.state_changed.emit("FAILED")
            err = f"Database Persistence & Analysis Error: {e}"
            self.status_message.emit(err)
            self.log_line.emit(f"[!] {err}")
            # Ensure DB session record reflects failure rather than remaining 'running'
            try:
                if self.session_id and hasattr(self.db_mgr, "get_scan_session"):
                    sess = self.db_mgr.get_scan_session(self.session_id)
                    if sess:
                        sess.status = "failed"
                        sess.error_message = err
                        sess.end_time = datetime.now().isoformat(timespec="seconds")
                        self.db_mgr.update_scan_session(sess)
            except Exception as db_err:
                logger.warning("Failed to update scan session status after analysis error: %s", db_err)
            self._safe_emit_finished(self.session_id, False, err, parsed_scan)
            return

        # 6. COMPLETED
        self.state_changed.emit("COMPLETED")
        summary_msg = (
            f"Discovery complete: {total_hosts} host(s) discovered in {parsed_scan.elapsed_seconds:.2f}s."
        )
        self.status_message.emit(summary_msg)
        self.log_line.emit(f"[+] {summary_msg}")
        self._safe_emit_finished(self.session_id, True, summary_msg, parsed_scan)

    def _on_stderr_line(self, line: str) -> None:
        """Callback from engine reading real-time stderr stream."""
        self.log_line.emit(line)

    def cancel_scan(self) -> None:
        """Request immediate cancellation of active scan."""
        self._is_cancelled = True
        self.engine.cancel()

    @staticmethod
    def _enrich_host_details(scan_result: ScanResult) -> None:
        """Enriches discovered hosts with local OS and hostname resolution fallback."""
        local_hostname = socket.gethostname()
        try:
            local_ips = set(socket.gethostbyname_ex(local_hostname)[2])
        except Exception:
            local_ips = set()
        local_ips.update({"127.0.0.1", "::1"})

        os_str = f"{platform.system()} {platform.release()}".strip()

        for host in scan_result.hosts:
            is_local = host.ip_address in local_ips

            # Hostname enrichment
            if is_local or not host.hostname or host.hostname in ("kubernetes.docker.internal", "localhost"):
                if is_local:
                    host.hostname = local_hostname
                else:
                    try:
                        name, _, _ = socket.gethostbyaddr(host.ip_address)
                        if name and not name.endswith(".in-addr.arpa"):
                            host.hostname = name.split(".")[0]
                    except Exception:
                        pass

            # Operating system enrichment
            if not host.os_name:
                if is_local:
                    host.os_name = os_str
                    host.os_accuracy = 100
                elif any(p.port_number in (135, 445) and p.state == "open" for p in host.ports):
                    host.os_name = "Microsoft Windows"
                    host.os_accuracy = 85

    # Retain backwards compatibility for tests
    _enrich_hostnames = _enrich_host_details
