"""Local SQLite database management module for NetSentinel AI.

Provides WAL-mode thread-safe storage, foreign key enforcement, schema migrations,
integrity verification, and CRUD operations for scans, assets, ports, findings, and audit logs.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import sqlite3
import sys
import threading
from typing import Any, Dict, Generator, List, Optional, Tuple
import uuid

from netsentinel.core.models import (
    Asset,
    AuditLogEntry,
    DiscoveredHost,
    DiscoveredPort,
    Port,
    ScanResult,
    ScanSession,
    SecurityFinding,
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_ACKNOWLEDGED,
    STATUS_RESOLVED,
    STATUS_FALSE_POSITIVE,
    ALL_FINDING_STATUSES,
    VALID_STATUS_TRANSITIONS,
)

logger = logging.getLogger(__name__)


def get_process_metadata(pid: int) -> Tuple[bool, Optional[str], Optional[int]]:
    """Inspects a process by PID and returns (is_active, executable_name_lower, creation_filetime_100ns).
    
    Uses Win32 OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    and GetProcessTimes. Never throws exceptions.
    """
    if not pid or pid <= 0:
        return False, None, None

    if sys.platform == "win32":
        try:
            import ctypes
            import ctypes.wintypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259

            class FILETIME(ctypes.Structure):
                _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD), ("dwHighDateTime", ctypes.wintypes.DWORD)]

            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False, None, None

            try:
                exit_code = ctypes.wintypes.DWORD()
                if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    if exit_code.value != STILL_ACTIVE:
                        return False, None, None

                # Query process image path
                buf = ctypes.create_unicode_buffer(1024)
                size = ctypes.wintypes.DWORD(1024)
                exe_name = None
                if ctypes.windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    exe_name = Path(buf.value).name.lower()

                # Query process creation timestamp
                ct, et, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
                creation_time = None
                if ctypes.windll.kernel32.GetProcessTimes(handle, ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)):
                    creation_time = (ct.dwHighDateTime << 32) + ct.dwLowDateTime

                return True, exe_name, creation_time
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception as e:
            logger.debug("Failed querying Win32 process metadata for PID %d: %s", pid, e)
            return False, None, None
    else:
        try:
            os.kill(pid, 0)
            comm_file = Path(f"/proc/{pid}/comm")
            exe_name = comm_file.read_text().strip().lower() if comm_file.exists() else None
            return True, exe_name, None
        except (OSError, ProcessLookupError):
            return False, None, None


def is_pid_running(pid: int) -> bool:
    """Checks whether a process with the given PID is currently active."""
    active, _, _ = get_process_metadata(pid)
    return active


def is_netsentinel_process(pid: int) -> bool:
    """Verifies that an active PID belongs to NetSentinel AI or the Python execution environment."""
    active, exe_name, _ = get_process_metadata(pid)
    if exe_name is not None:
        allowed = ("netsentinelai.exe", "python.exe", "pythonw.exe", "pytest.exe")
        return exe_name in allowed
    # If process image name couldn't be queried directly (e.g. mock or permission boundary), delegate to is_pid_running
    return is_pid_running(pid)


@dataclass
class DataResetResult:
    """Encapsulates the outcome of a complete database reset and storage compaction."""
    records_cleared: bool = False
    compaction_succeeded: bool = False
    error: Optional[str] = None
    compaction_error: Optional[str] = None

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_input TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'tcp_connect',
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    command_executed TEXT DEFAULT '',
    hosts_discovered INTEGER DEFAULT 0,
    ports_found INTEGER DEFAULT 0,
    risk_summary TEXT DEFAULT '',
    duration_seconds REAL DEFAULT 0.0,
    nmap_version TEXT DEFAULT '',
    error_message TEXT DEFAULT '',
    configured_ports TEXT DEFAULT '',
    process_id INTEGER DEFAULT 0,
    instance_id TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_start_time ON scan_sessions(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT DEFAULT '',
    mac_address TEXT DEFAULT '',
    os_name TEXT DEFAULT '',
    os_accuracy INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'Low',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_risk_level ON assets(risk_level);

CREATE TABLE IF NOT EXISTS scan_session_assets (
    session_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    PRIMARY KEY(session_id, asset_id),
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_session_assets_session ON scan_session_assets(session_id);
CREATE INDEX IF NOT EXISTS idx_scan_session_assets_asset ON scan_session_assets(asset_id);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    session_id INTEGER,
    port_number INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT DEFAULT '',
    product TEXT DEFAULT '',
    version TEXT DEFAULT '',
    risk_note TEXT DEFAULT '',
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL,
    UNIQUE(asset_id, port_number, protocol)
);

CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON ports(asset_id);
CREATE INDEX IF NOT EXISTS idx_ports_session_id ON ports(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_number ON ports(port_number);

CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER,
    session_id INTEGER,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    cve_references TEXT DEFAULT '',
    timestamp TEXT NOT NULL,
    rule_id TEXT DEFAULT '',
    rule_version TEXT DEFAULT '1.0',
    confidence REAL DEFAULT 1.0,
    risk_score REAL DEFAULT 0.0,
    risk_tier TEXT DEFAULT 'Low',
    scoring_explanation TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    status TEXT DEFAULT 'New',
    port_id INTEGER,
    port_number INTEGER,
    protocol TEXT DEFAULT 'tcp',
    finding_key TEXT DEFAULT '',
    user_notes TEXT DEFAULT '',
    resolution_reason TEXT DEFAULT '',
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL,
    FOREIGN KEY(port_id) REFERENCES ports(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON security_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_id ON security_findings(session_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    user_confirmed INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
"""


class DatabaseManager:
    """Manages SQLite database lifecycle, migrations, and transactional queries."""

    def __init__(self, db_path: Path, instance_id: Optional[str] = None):
        self.db_path = Path(db_path)
        self._op_lock = threading.Lock()
        self._is_clearing: bool = False
        self._active_scans: int = 0
        self.instance_id: str = instance_id or uuid.uuid4().hex
        self.initialize()

    @contextlib.contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing an active SQLite connection with WAL and foreign keys."""
        conn = sqlite3.connect(str(self.db_path), timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Initializes database schema and indexes, runs migrations, and recovers interrupted sessions."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            self._run_migrations(conn)
        self.recover_interrupted_sessions()

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Performs non-destructive schema migrations for existing databases."""
        # 1. scan_sessions migrations
        cursor = conn.execute("PRAGMA table_info(scan_sessions);")
        scan_cols = {row["name"] for row in cursor.fetchall()}
        if "duration_seconds" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN duration_seconds REAL DEFAULT 0.0;")
        if "nmap_version" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN nmap_version TEXT DEFAULT '';")
        if "error_message" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN error_message TEXT DEFAULT '';")
        if "configured_ports" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN configured_ports TEXT DEFAULT '';")
        if "process_id" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN process_id INTEGER DEFAULT 0;")
        if "instance_id" not in scan_cols:
            conn.execute("ALTER TABLE scan_sessions ADD COLUMN instance_id TEXT DEFAULT '';")

        # 2. security_findings migrations
        cursor = conn.execute("PRAGMA table_info(security_findings);")
        finding_cols = {row["name"] for row in cursor.fetchall()}

        col_defs = {
            "rule_id": "TEXT DEFAULT ''",
            "rule_version": "TEXT DEFAULT '1.0'",
            "confidence": "REAL DEFAULT 1.0",
            "risk_score": "REAL DEFAULT 0.0",
            "risk_tier": "TEXT DEFAULT 'Low'",
            "scoring_explanation": "TEXT DEFAULT ''",
            "evidence": "TEXT DEFAULT ''",
            "status": "TEXT DEFAULT 'New'",
            "port_id": "INTEGER",
            "port_number": "INTEGER",
            "protocol": "TEXT DEFAULT 'tcp'",
            "finding_key": "TEXT DEFAULT ''",
            "user_notes": "TEXT DEFAULT ''",
            "resolution_reason": "TEXT DEFAULT ''",
        }

        for col, col_def in col_defs.items():
            if col not in finding_cols:
                conn.execute(f"ALTER TABLE security_findings ADD COLUMN {col} {col_def};")

        # Ensure Milestone 3 indexes exist
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON security_findings(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON security_findings(rule_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_key ON security_findings(finding_key);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON security_findings(risk_score DESC);")

        # 3. scan_session_assets junction table migration & backfill
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_session_assets (
                session_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                PRIMARY KEY(session_id, asset_id),
                FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_session_assets_session ON scan_session_assets(session_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_session_assets_asset ON scan_session_assets(asset_id);")

        # A. Backfill from historical ports
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_session_assets (session_id, asset_id)
            SELECT DISTINCT session_id, asset_id FROM ports WHERE session_id IS NOT NULL;
            """
        )
        # B. Backfill from historical security findings
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_session_assets (session_id, asset_id)
            SELECT DISTINCT session_id, asset_id FROM security_findings WHERE session_id IS NOT NULL AND asset_id IS NOT NULL;
            """
        )
        # C. Backfill single-target discovery scans where target_input matched asset IP
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_session_assets (session_id, asset_id)
            SELECT s.id, a.id
            FROM scan_sessions s
            JOIN assets a ON s.target_input = a.ip_address
            WHERE s.hosts_discovered > 0;
            """
        )
        # D. Backfill single-target discovery scans where target_input matched asset hostname
        conn.execute(
            """
            INSERT OR IGNORE INTO scan_session_assets (session_id, asset_id)
            SELECT s.id, a.id
            FROM scan_sessions s
            JOIN assets a ON LOWER(s.target_input) = LOWER(a.hostname)
            WHERE s.hosts_discovered > 0 AND a.hostname IS NOT NULL AND a.hostname != '';
            """
        )

    def recover_interrupted_sessions(
        self,
        current_instance_id: Optional[str] = None,
        current_pid: Optional[int] = None,
    ) -> int:
        """Transactionally recovers abandoned running sessions from terminated or crashed instances.

        Enforces strict process & instance ownership verification:
        - Reclaims sessions abandoned by the current instance on restart.
        - Reclaims sessions whose owning PID has terminated.
        - Reclaims sessions whose PID has been reused by an unrelated non-NetSentinel system process.
        - Reclaims sessions whose PID has been reused by a newer NetSentinel process created after session started.
        - Strictly preserves active scans owned by a live concurrent NetSentinel instance.
        - Prevents silent session state corruption and records transactional audit logs.
        """
        cur_pid = current_pid if current_pid is not None else os.getpid()
        cur_inst = current_instance_id if current_instance_id is not None else self.instance_id
        recovered_count = 0
        now_iso = datetime.now().isoformat(timespec="seconds")

        try:
            with self.get_connection() as conn:
                cursor = conn.execute(
                    "SELECT id, process_id, instance_id, start_time, target_input "
                    "FROM scan_sessions WHERE status = 'running';"
                )
                running_sessions = cursor.fetchall()
                for row in running_sessions:
                    sid = row["id"]
                    keys = row.keys()
                    owning_pid = row["process_id"] or 0
                    owning_inst = row["instance_id"] if "instance_id" in keys else ""
                    start_time_str = row["start_time"] or ""

                    should_recover = False
                    reason = ""

                    # 1. Leftover from the current running instance (prior to restart)
                    if owning_inst and owning_inst == cur_inst:
                        should_recover = True
                        reason = f"Session interrupted: Owning application instance ({owning_inst}) restarted."
                    # 2. Owning PID is invalid, dead, or not running
                    elif owning_pid <= 0 or not is_pid_running(owning_pid):
                        should_recover = True
                        reason = f"Session interrupted: Owning process (PID {owning_pid}) terminated unexpectedly."
                    # 3. Owning PID is running, but current process has the exact same PID on restart
                    elif owning_pid == cur_pid:
                        should_recover = True
                        reason = f"Session interrupted: Process (PID {owning_pid}) restarted with new instance ({cur_inst})."
                    # 4. Owning PID is running, but NOT a NetSentinel process (PID reuse by another system program)
                    elif not is_netsentinel_process(owning_pid):
                        should_recover = True
                        reason = f"Session interrupted: Owning process terminated (PID {owning_pid} reused by non-NetSentinel process)."
                    else:
                        # 5. Owning PID is running and IS a NetSentinel/Python process.
                        # Check creation time to see if it's a PID reuse by a newer NetSentinel instance.
                        _, _, creation_time_100ns = get_process_metadata(owning_pid)
                        if creation_time_100ns and start_time_str:
                            try:
                                session_start_dt = datetime.fromisoformat(start_time_str)
                                proc_creation_posix = (creation_time_100ns / 10_000_000.0) - 11644473600.0
                                proc_creation_dt = datetime.fromtimestamp(proc_creation_posix)
                                if proc_creation_dt > session_start_dt + timedelta(seconds=2):
                                    should_recover = True
                                    reason = f"Session interrupted: PID {owning_pid} reused by newer application instance."
                            except Exception:
                                pass

                    if should_recover:
                        conn.execute(
                            """
                            UPDATE scan_sessions SET
                                status = 'inconclusive',
                                end_time = CASE WHEN end_time IS NULL OR end_time = '' THEN ? ELSE end_time END,
                                error_message = ?
                            WHERE id = ?;
                            """,
                            (now_iso, reason, sid),
                        )
                        conn.execute(
                            """
                            INSERT INTO audit_log (timestamp, event_type, target, details, user_confirmed)
                            SELECT ?, 'session_interrupted_recovery', target_input, ?, 1
                            FROM scan_sessions WHERE id = ?;
                            """,
                            (now_iso, f"Recovered abandoned scan session #{sid}: {reason}", sid),
                        )
                        recovered_count += 1
                        logger.info("Recovered abandoned scan session #%d: %s", sid, reason)
                    else:
                        logger.info(
                            "Preserved active concurrent scan session #%d owned by live instance %s (PID %d).",
                            sid,
                            owning_inst or "unknown",
                            owning_pid,
                        )
        except Exception as e:
            logger.exception("Error during interrupted session recovery: %s", e)

        return recovered_count

    def check_integrity(self) -> bool:
        """Executes SQLite PRAGMA quick_check to verify database health."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("PRAGMA quick_check;")
                row = cursor.fetchone()
                return bool(row and row[0] == "ok")
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Concurrency Guards & Complete Data Management
    # -------------------------------------------------------------------------

    def start_scan_operation(self) -> bool:
        """Acquires a scan slot. Fails if clearing is actively in progress."""
        with self._op_lock:
            if self._is_clearing:
                return False
            self._active_scans += 1
            return True

    def end_scan_operation(self) -> None:
        """Releases a scan slot."""
        with self._op_lock:
            self._active_scans = max(0, self._active_scans - 1)

    @property
    def is_scan_active(self) -> bool:
        """Returns True if any background discovery scans are currently active."""
        with self._op_lock:
            return self._active_scans > 0

    @property
    def is_clearing(self) -> bool:
        """Returns True if a database purge and compaction operation is underway."""
        with self._op_lock:
            return self._is_clearing

    def acquire_clear_lock(self) -> bool:
        """Acquires exclusive clearing lock if no scans are active."""
        with self._op_lock:
            if self._active_scans > 0 or self._is_clearing:
                return False
            self._is_clearing = True
            return True

    def release_clear_lock(self) -> None:
        """Releases the exclusive clearing lock."""
        with self._op_lock:
            self._is_clearing = False

    def clear_all_data(self, skip_vacuum: bool = False) -> DataResetResult:
        """Atomically clears all scan sessions, discovered assets, ports, security findings, and audit logs.
        
        Enforces foreign keys, deletes in strict dependency order, resets SQLite sequence counters,
        and performs a separate WAL checkpoint and VACUUM compaction.
        """
        # Ensure clearing lock is acquired
        with self._op_lock:
            if self._active_scans > 0:
                return DataResetResult(
                    records_cleared=False,
                    error="Cannot clear database while a discovery scan is actively running.",
                )
            was_already_clearing = self._is_clearing
            if not was_already_clearing:
                self._is_clearing = True

        try:
            # 1. Atomic Deletion Transaction with Foreign Keys Enabled
            with self.get_connection() as conn:
                conn.execute("PRAGMA foreign_keys = ON;")
                # Strict dependency order deletion:
                # 1. security_findings (references ports, assets, sessions)
                conn.execute("DELETE FROM security_findings;")
                # 2. ports (references assets, sessions)
                conn.execute("DELETE FROM ports;")
                # 3. scan_session_assets (references assets, sessions)
                conn.execute("DELETE FROM scan_session_assets;")
                # 4. assets (referenced by ports, security_findings, scan_session_assets)
                conn.execute("DELETE FROM assets;")
                # 5. scan_sessions (referenced by ports, security_findings, scan_session_assets)
                conn.execute("DELETE FROM scan_sessions;")
                # 6. audit_log (independent)
                conn.execute("DELETE FROM audit_log;")

                # Reset sequence counters for all cleared tables if sqlite_sequence exists
                try:
                    conn.execute(
                        "DELETE FROM sqlite_sequence WHERE name IN "
                        "('security_findings', 'ports', 'scan_session_assets', 'assets', 'scan_sessions', 'audit_log');"
                    )
                except sqlite3.OperationalError:
                    pass
        except Exception as e:
            return DataResetResult(records_cleared=False, error=str(e))
        finally:
            if not was_already_clearing:
                with self._op_lock:
                    self._is_clearing = False

        # 2. Separate Post-Commit Maintenance: WAL Checkpoint and VACUUM Compaction
        # CRITICAL: This is executed outside the deletion transaction.
        compaction_succeeded = True
        compaction_error = None
        try:
            maint_conn = sqlite3.connect(str(self.db_path), timeout=20.0)
            try:
                maint_conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                if not skip_vacuum:
                    maint_conn.execute("VACUUM;")
            finally:
                maint_conn.close()
        except Exception as ce:
            compaction_succeeded = False
            compaction_error = str(ce)

        return DataResetResult(
            records_cleared=True,
            compaction_succeeded=compaction_succeeded,
            compaction_error=compaction_error,
        )

    # -------------------------------------------------------------------------
    # Scan Sessions CRUD & Persistence
    # -------------------------------------------------------------------------

    def create_scan_session(self, session: ScanSession) -> int:
        """Inserts a new scan session record and returns its ID."""
        with self._op_lock:
            if self._is_clearing:
                raise RuntimeError("Cannot initialize database session while database clearing is in progress.")
        if not session.process_id:
            session.process_id = os.getpid()
        if not session.instance_id:
            session.instance_id = self.instance_id
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_sessions (
                    target_input, profile, start_time, end_time, status,
                    command_executed, hosts_discovered, ports_found, risk_summary,
                    duration_seconds, nmap_version, error_message, configured_ports,
                    process_id, instance_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.target_input,
                    session.profile,
                    session.start_time,
                    session.end_time,
                    session.status,
                    session.command_executed,
                    session.hosts_discovered,
                    session.ports_found,
                    session.risk_summary,
                    session.duration_seconds,
                    session.nmap_version,
                    session.error_message,
                    session.configured_ports,
                    session.process_id,
                    session.instance_id,
                ),
            )
            session_id = int(cursor.lastrowid)
            session.id = session_id
            return session_id

    def update_scan_session(self, session: ScanSession) -> None:
        """Updates an existing scan session record."""
        if session.id is None:
            raise ValueError("Cannot update scan session without valid ID.")
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE scan_sessions SET
                    end_time = ?,
                    status = ?,
                    command_executed = ?,
                    hosts_discovered = ?,
                    ports_found = ?,
                    risk_summary = ?,
                    duration_seconds = ?,
                    nmap_version = ?,
                    error_message = ?,
                    configured_ports = ?,
                    process_id = CASE WHEN ? > 0 THEN ? ELSE process_id END,
                    instance_id = CASE WHEN ? != '' THEN ? ELSE instance_id END
                WHERE id = ?
                """,
                (
                    session.end_time,
                    session.status,
                    session.command_executed,
                    session.hosts_discovered,
                    session.ports_found,
                    session.risk_summary,
                    session.duration_seconds,
                    session.nmap_version,
                    session.error_message,
                    session.configured_ports,
                    session.process_id,
                    session.process_id,
                    session.instance_id,
                    session.instance_id,
                    session.id,
                ),
            )

    def get_scan_session(self, session_id: int) -> Optional[ScanSession]:
        """Retrieves a single scan session by ID."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,))
            row = cursor.fetchone()
            if not row:
                return None
            keys = row.keys()
            return ScanSession(
                id=row["id"],
                target_input=row["target_input"],
                profile=row["profile"],
                start_time=row["start_time"],
                end_time=row["end_time"],
                status=row["status"],
                command_executed=row["command_executed"],
                hosts_discovered=row["hosts_discovered"],
                ports_found=row["ports_found"],
                risk_summary=row["risk_summary"],
                duration_seconds=row["duration_seconds"] if "duration_seconds" in keys else 0.0,
                nmap_version=row["nmap_version"] if "nmap_version" in keys else "",
                error_message=row["error_message"] if "error_message" in keys else "",
                configured_ports=row["configured_ports"] if "configured_ports" in keys else "",
                process_id=row["process_id"] if "process_id" in keys else 0,
                instance_id=row["instance_id"] if "instance_id" in keys else "",
            )

    def list_scan_sessions(self, limit: int = 100) -> List[ScanSession]:
        """Lists recent scan sessions ordered by start time descending."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            sessions = []
            for row in cursor.fetchall():
                keys = row.keys()
                sessions.append(
                    ScanSession(
                        id=row["id"],
                        target_input=row["target_input"],
                        profile=row["profile"],
                        start_time=row["start_time"],
                        end_time=row["end_time"],
                        status=row["status"],
                        command_executed=row["command_executed"],
                        hosts_discovered=row["hosts_discovered"],
                        ports_found=row["ports_found"],
                        risk_summary=row["risk_summary"],
                        duration_seconds=row["duration_seconds"] if "duration_seconds" in keys else 0.0,
                        nmap_version=row["nmap_version"] if "nmap_version" in keys else "",
                        error_message=row["error_message"] if "error_message" in keys else "",
                        configured_ports=row["configured_ports"] if "configured_ports" in keys else "",
                        process_id=row["process_id"] if "process_id" in keys else 0,
                        instance_id=row["instance_id"] if "instance_id" in keys else "",
                    )
                )
            return sessions

    def save_scan_results(
        self,
        session_id: int,
        result: ScanResult,
        command_str: str = "",
    ) -> None:
        """Persists scan results, updates session, and deduplicates assets & ports in a transaction."""
        now_iso = datetime.now().isoformat(timespec="seconds")
        end_time = result.finish_time or now_iso

        status = "completed" if result.success else ("cancelled" if result.was_cancelled else "failed")

        # Calculate total open ports across all hosts
        total_open_ports = 0
        for host in result.hosts:
            total_open_ports += len([p for p in host.ports if p.state == "open"])

        with self.get_connection() as conn:
            # 1. Update Scan Session record
            conn.execute(
                """
                UPDATE scan_sessions SET
                    end_time = ?,
                    status = ?,
                    command_executed = CASE WHEN ? != '' THEN ? ELSE command_executed END,
                    hosts_discovered = ?,
                    ports_found = ?,
                    duration_seconds = ?,
                    nmap_version = ?,
                    error_message = ?
                WHERE id = ?
                """,
                (
                    end_time,
                    status,
                    command_str,
                    command_str,
                    len(result.hosts),
                    total_open_ports,
                    result.elapsed_seconds,
                    result.nmap_version,
                    result.error_message,
                    session_id,
                ),
            )

            # 2. Upsert Discovered Hosts into assets
            for host in result.hosts:
                cursor = conn.execute(
                    """
                    INSERT INTO assets (
                        ip_address, hostname, mac_address, os_name, os_accuracy,
                        risk_level, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, 'Low', ?, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE assets.hostname END,
                        mac_address = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address ELSE assets.mac_address END,
                        os_name = CASE WHEN excluded.os_name != '' THEN excluded.os_name ELSE assets.os_name END,
                        os_accuracy = CASE WHEN excluded.os_accuracy > assets.os_accuracy THEN excluded.os_accuracy ELSE assets.os_accuracy END,
                        last_seen = excluded.last_seen
                    RETURNING id;
                    """,
                    (
                        host.ip_address,
                        host.hostname,
                        host.mac_address,
                        host.os_name,
                        host.os_accuracy,
                        now_iso,
                        now_iso,
                    ),
                )
                row = cursor.fetchone()
                if row is not None:
                    asset_id = int(row["id"]) if isinstance(row, sqlite3.Row) else int(row[0])
                else:
                    c2 = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (host.ip_address,))
                    asset_id = int(c2.fetchone()["id"])

                # Link asset to scan session in junction table
                conn.execute(
                    """
                    INSERT OR IGNORE INTO scan_session_assets (session_id, asset_id)
                    VALUES (?, ?);
                    """,
                    (session_id, asset_id),
                )

                # 3. Upsert Discovered Ports
                for port in host.ports:
                    conn.execute(
                        """
                        INSERT INTO ports (
                            asset_id, session_id, port_number, protocol, state,
                            service_name, product, version, risk_note
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(asset_id, port_number, protocol) DO UPDATE SET
                            session_id = excluded.session_id,
                            state = excluded.state,
                            service_name = CASE WHEN excluded.service_name != '' THEN excluded.service_name ELSE ports.service_name END,
                            product = CASE WHEN excluded.product != '' THEN excluded.product ELSE ports.product END,
                            version = CASE WHEN excluded.version != '' THEN excluded.version ELSE ports.version END,
                            risk_note = excluded.risk_note
                        """,
                        (
                            asset_id,
                            session_id,
                            port.port_number,
                            port.protocol,
                            port.state,
                            port.service_name,
                            port.product,
                            port.version,
                            getattr(port, "extra_info", getattr(port, "risk_note", "")),
                        ),
                    )

            # 4. Record Audit Log
            event_type = f"scan_{status}"
            details = (
                f"Scan #{session_id} finished ({status}): {len(result.hosts)} hosts discovered, "
                f"{total_open_ports} open ports identified in {result.elapsed_seconds:.2f}s."
            )
            conn.execute(
                """
                INSERT INTO audit_log (timestamp, event_type, target, details, user_confirmed)
                SELECT ?, ?, target_input, ?, 1 FROM scan_sessions WHERE id = ?
                """,
                (now_iso, event_type, details, session_id),
            )

    def get_session_details(self, session_id: int) -> Dict[str, Any]:
        """Retrieves a scan session and all assets & ports linked to it."""
        session = self.get_scan_session(session_id)
        if not session:
            return {}

        with self.get_connection() as conn:
            # Query ports linked to this session
            ports_cursor = conn.execute(
                """
                SELECT p.*, a.ip_address, a.hostname
                FROM ports p
                JOIN assets a ON p.asset_id = a.id
                WHERE p.session_id = ?
                ORDER BY a.ip_address, p.port_number
                """,
                (session_id,),
            )
            ports = [dict(row) for row in ports_cursor.fetchall()]

            # Query assets active during this session via junction table
            assets_cursor = conn.execute(
                """
                SELECT a.*
                FROM assets a
                JOIN scan_session_assets ssa ON ssa.asset_id = a.id
                WHERE ssa.session_id = ?
                ORDER BY a.ip_address
                """,
                (session_id,),
            )
            assets = [dict(row) for row in assets_cursor.fetchall()]

            # Fallback for historical sessions without junction records
            if not assets:
                assets_cursor = conn.execute(
                    """
                    SELECT DISTINCT a.*
                    FROM assets a
                    JOIN ports p ON p.asset_id = a.id
                    WHERE p.session_id = ?
                    ORDER BY a.ip_address
                    """,
                    (session_id,),
                )
                assets = [dict(row) for row in assets_cursor.fetchall()]

            return {
                "session": session,
                "assets": assets,
                "ports": ports,
            }

    # -------------------------------------------------------------------------
    # Assets CRUD
    # -------------------------------------------------------------------------

    def upsert_asset(self, asset: Asset) -> int:
        """Inserts a new asset or updates last_seen/os/hostname if already present."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO assets (
                    ip_address, hostname, mac_address, os_name, os_accuracy,
                    risk_level, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE assets.hostname END,
                    mac_address = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address ELSE assets.mac_address END,
                    os_name = CASE WHEN excluded.os_name != '' THEN excluded.os_name ELSE assets.os_name END,
                    os_accuracy = CASE WHEN excluded.os_accuracy > assets.os_accuracy THEN excluded.os_accuracy ELSE assets.os_accuracy END,
                    risk_level = excluded.risk_level,
                    last_seen = excluded.last_seen
                RETURNING id;
                """,
                (
                    asset.ip_address,
                    asset.hostname,
                    asset.mac_address,
                    asset.os_name,
                    asset.os_accuracy,
                    asset.risk_level,
                    asset.first_seen,
                    asset.last_seen,
                ),
            )
            row = cursor.fetchone()
            if row is not None:
                asset_id = int(row["id"]) if isinstance(row, sqlite3.Row) else int(row[0])
            else:
                c2 = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (asset.ip_address,))
                asset_id = int(c2.fetchone()["id"])
            asset.id = asset_id
            return asset_id

    def get_asset(self, asset_id: int) -> Optional[Asset]:
        """Retrieves an asset by primary key with open ports count."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT a.*, COUNT(p.id) as open_ports_count
                FROM assets a
                LEFT JOIN ports p ON a.id = p.asset_id AND p.state = 'open'
                WHERE a.id = ?
                GROUP BY a.id
                """,
                (asset_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Asset(
                id=row["id"],
                ip_address=row["ip_address"],
                hostname=row["hostname"],
                mac_address=row["mac_address"],
                os_name=row["os_name"],
                os_accuracy=row["os_accuracy"],
                risk_level=row["risk_level"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                open_ports_count=row["open_ports_count"],
            )

    def get_asset_by_ip(self, ip_address: str) -> Optional[Asset]:
        """Retrieves an asset by IP address."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT id FROM assets WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            if not row:
                return None
            return self.get_asset(row["id"])

    def list_assets(self, limit: int = 200) -> List[Asset]:
        """Lists assets with their open port counts."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT a.*, COUNT(p.id) as open_ports_count
                FROM assets a
                LEFT JOIN ports p ON a.id = p.asset_id AND p.state = 'open'
                GROUP BY a.id
                ORDER BY a.last_seen DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [
                Asset(
                    id=row["id"],
                    ip_address=row["ip_address"],
                    hostname=row["hostname"],
                    mac_address=row["mac_address"],
                    os_name=row["os_name"],
                    os_accuracy=row["os_accuracy"],
                    risk_level=row["risk_level"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    open_ports_count=row["open_ports_count"],
                )
                for row in cursor.fetchall()
            ]

    # -------------------------------------------------------------------------
    # Ports CRUD
    # -------------------------------------------------------------------------

    def add_port(self, port: Port) -> int:
        """Inserts or updates a discovered network port for an asset."""
        if port.asset_id is None:
            raise ValueError("Cannot insert port without asset_id.")
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO ports (
                    asset_id, session_id, port_number, protocol, state,
                    service_name, product, version, risk_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, port_number, protocol) DO UPDATE SET
                    session_id = excluded.session_id,
                    state = excluded.state,
                    service_name = excluded.service_name,
                    product = excluded.product,
                    version = excluded.version,
                    risk_note = excluded.risk_note
                RETURNING id;
                """,
                (
                    port.asset_id,
                    port.session_id,
                    port.port_number,
                    port.protocol,
                    port.state,
                    port.service_name,
                    port.product,
                    port.version,
                    port.risk_note,
                ),
            )
            row = cursor.fetchone()
            if row is not None:
                port_id = int(row["id"]) if isinstance(row, sqlite3.Row) else int(row[0])
            else:
                c2 = conn.execute(
                    "SELECT id FROM ports WHERE asset_id = ? AND port_number = ? AND protocol = ?",
                    (port.asset_id, port.port_number, port.protocol),
                )
                port_id = int(c2.fetchone()["id"])
            port.id = port_id
            return port_id

    def get_ports_for_asset(self, asset_id: int) -> List[Port]:
        """Returns all ports for a specific asset."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM ports WHERE asset_id = ? ORDER BY port_number ASC",
                (asset_id,),
            )
            return [
                Port(
                    id=row["id"],
                    asset_id=row["asset_id"],
                    session_id=row["session_id"],
                    port_number=row["port_number"],
                    protocol=row["protocol"],
                    state=row["state"],
                    service_name=row["service_name"],
                    product=row["product"],
                    version=row["version"],
                    risk_note=row["risk_note"],
                )
                for row in cursor.fetchall()
            ]

    # -------------------------------------------------------------------------
    # Security Findings CRUD & Lifecycle Management
    # -------------------------------------------------------------------------

    def add_security_finding(self, finding: SecurityFinding) -> int:
        """Inserts a security finding record with transparent scoring and evidence."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO security_findings (
                    asset_id, session_id, severity, title, description,
                    recommendation, cve_references, timestamp, rule_id,
                    rule_version, confidence, risk_score, risk_tier,
                    scoring_explanation, evidence, status, port_id,
                    port_number, protocol, finding_key, user_notes, resolution_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.asset_id,
                    finding.session_id,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.recommendation,
                    finding.cve_references,
                    finding.timestamp,
                    finding.rule_id,
                    finding.rule_version,
                    finding.confidence,
                    finding.risk_score,
                    finding.risk_tier,
                    finding.scoring_explanation,
                    finding.evidence,
                    finding.status,
                    finding.port_id,
                    finding.port_number,
                    finding.protocol,
                    finding.finding_key,
                    finding.user_notes,
                    finding.resolution_reason,
                ),
            )
            finding_id = int(cursor.lastrowid)
            finding.id = finding_id
            return finding_id

    def upsert_security_finding(self, finding: SecurityFinding) -> int:
        """Upserts a security finding using stable finding identity.

        STABILITY & LIFECYCLE PRESERVATION:
        - Deduplication key: finding_key (or asset_id + rule_id + protocol + port_number).
        - If finding exists with user-assigned status ('Acknowledged' or 'False Positive'),
          that status is STRICTLY PRESERVED across repeat scans.
        - If finding was 'Resolved' but is re-observed, it is reopened to 'Open'.
        - If finding was 'New' and observed again in a later scan, it transitions to 'Open'.
        - Updated scan session, timestamp, evidence, and risk score are persisted.
        """
        with self.get_connection() as conn:
            # 1. Check for existing finding by key or composite identity
            row = None
            if finding.finding_key:
                cursor = conn.execute(
                    "SELECT * FROM security_findings WHERE finding_key = ?",
                    (finding.finding_key,),
                )
                row = cursor.fetchone()

            if not row and finding.asset_id is not None:
                cursor = conn.execute(
                    """
                    SELECT * FROM security_findings
                    WHERE asset_id = ? AND rule_id = ? AND protocol = ?
                      AND ((port_number IS NULL AND ? IS NULL) OR (port_number = ?))
                    """,
                    (finding.asset_id, finding.rule_id, finding.protocol, finding.port_number, finding.port_number),
                )
                row = cursor.fetchone()

            if not row:
                # Insert as a new finding
                return self.add_security_finding(finding)

            # 2. Existing finding found: calculate preserved or transitioned status
            existing_id = int(row["id"])
            current_status = row["status"]
            current_user_notes = row["user_notes"] or ""

            if current_status in (STATUS_ACKNOWLEDGED, STATUS_FALSE_POSITIVE):
                # Strictly preserve operator's risk acceptance decision
                target_status = current_status
            elif current_status == STATUS_RESOLVED:
                # Reopen previously resolved finding since condition has reappeared
                target_status = STATUS_OPEN
                reopen_note = f"[{finding.timestamp}] Reopened: condition re-detected in scan #{finding.session_id}."
                current_user_notes = f"{current_user_notes}\n{reopen_note}".strip()
                conn.execute(
                    """
                    INSERT INTO audit_log (timestamp, event_type, target, details, user_confirmed)
                    VALUES (?, 'finding_reopened', ?, ?, 0)
                    """,
                    (
                        finding.timestamp,
                        f"finding:{existing_id}",
                        f"Finding #{existing_id} automatically reopened to '{STATUS_OPEN}': condition re-detected in scan #{finding.session_id}.",
                    ),
                )
            elif current_status == STATUS_NEW and finding.session_id != row["session_id"]:
                # Confirmed across multiple scans -> Open
                target_status = STATUS_OPEN
            else:
                target_status = current_status

            conn.execute(
                """
                UPDATE security_findings SET
                    session_id = ?,
                    severity = ?,
                    title = ?,
                    description = ?,
                    recommendation = ?,
                    cve_references = ?,
                    timestamp = ?,
                    rule_id = ?,
                    rule_version = ?,
                    confidence = ?,
                    risk_score = ?,
                    risk_tier = ?,
                    scoring_explanation = ?,
                    evidence = ?,
                    status = ?,
                    port_id = ?,
                    port_number = ?,
                    protocol = ?,
                    finding_key = ?,
                    user_notes = ?
                WHERE id = ?
                """,
                (
                    finding.session_id,
                    finding.severity,
                    finding.title,
                    finding.description,
                    finding.recommendation,
                    finding.cve_references,
                    finding.timestamp,
                    finding.rule_id,
                    finding.rule_version,
                    finding.confidence,
                    finding.risk_score,
                    finding.risk_tier,
                    finding.scoring_explanation,
                    finding.evidence,
                    target_status,
                    finding.port_id,
                    finding.port_number,
                    finding.protocol,
                    finding.finding_key,
                    current_user_notes,
                    existing_id,
                ),
            )
            finding.id = existing_id
            finding.status = target_status
            return existing_id

    def update_finding_status(
        self,
        finding_id: int,
        new_status: str,
        notes: str = "",
        user_confirmed: bool = True,
    ) -> bool:
        """Transitions a finding's lifecycle status and writes an immutable audit log entry."""
        if new_status not in ALL_FINDING_STATUSES:
            raise ValueError(f"Invalid finding status '{new_status}'. Allowed: {ALL_FINDING_STATUSES}")

        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM security_findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return False

            old_status = row["status"]
            if old_status != new_status:
                allowed_next = VALID_STATUS_TRANSITIONS.get(old_status, set())
                if new_status not in allowed_next:
                    raise ValueError(
                        f"Illegal status transition from '{old_status}' to '{new_status}'. "
                        f"Allowed transitions: {allowed_next}"
                    )

            now_iso = datetime.now().isoformat(timespec="seconds")
            existing_notes = row["user_notes"] or ""
            notes_append = f"[{now_iso}] Status changed from '{old_status}' to '{new_status}'. Note: {notes}"
            combined_notes = f"{existing_notes}\n{notes_append}".strip()

            resolution_reason = notes if new_status == STATUS_RESOLVED else (row["resolution_reason"] or "")

            conn.execute(
                """
                UPDATE security_findings SET
                    status = ?,
                    user_notes = ?,
                    resolution_reason = ?
                WHERE id = ?
                """,
                (new_status, combined_notes, resolution_reason, finding_id),
            )

            # Record audit log entry
            conn.execute(
                """
                INSERT INTO audit_log (timestamp, event_type, target, details, user_confirmed)
                VALUES (?, 'finding_status_changed', ?, ?, ?)
                """,
                (
                    now_iso,
                    f"finding:{finding_id}",
                    f"Finding #{finding_id} status changed from '{old_status}' to '{new_status}'. Reason: {notes or 'No reason provided'}",
                    1 if user_confirmed else 0,
                ),
            )
            return True

    def get_security_finding(self, finding_id: int) -> Optional[SecurityFinding]:
        """Retrieves a single security finding with joined host details."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT f.*, a.ip_address, a.hostname
                FROM security_findings f
                LEFT JOIN assets a ON f.asset_id = a.id
                WHERE f.id = ?
                """,
                (finding_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def list_security_findings(
        self,
        severity: Optional[str] = None,
        risk_tier: Optional[str] = None,
        status: Optional[str] = None,
        asset_id: Optional[int] = None,
        session_id: Optional[int] = None,
        rule_id: Optional[str] = None,
        search_term: Optional[str] = None,
        limit: int = 200,
    ) -> List[SecurityFinding]:
        """Lists security findings with multi-criteria filtering and sorting."""
        query = """
            SELECT f.*, a.ip_address, a.hostname
            FROM security_findings f
            LEFT JOIN assets a ON f.asset_id = a.id
            WHERE 1=1
        """
        params: List[Any] = []

        if severity and severity != "All Severities":
            query += " AND f.severity = ?"
            params.append(severity)

        if risk_tier and risk_tier != "All Risk Tiers":
            query += " AND f.risk_tier = ?"
            params.append(risk_tier)

        if status and status != "All Statuses":
            query += " AND f.status = ?"
            params.append(status)

        if asset_id is not None:
            query += " AND f.asset_id = ?"
            params.append(asset_id)

        if session_id is not None:
            query += " AND f.session_id = ?"
            params.append(session_id)

        if rule_id:
            query += " AND f.rule_id = ?"
            params.append(rule_id)

        if search_term and search_term.strip():
            st = f"%{search_term.strip()}%"
            query += " AND (a.ip_address LIKE ? OR a.hostname LIKE ? OR f.title LIKE ? OR f.rule_id LIKE ?)"
            params.extend([st, st, st, st])

        query += """
            ORDER BY
                CASE f.severity
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                f.risk_score DESC,
                f.id DESC
            LIMIT ?
        """
        params.append(limit)

        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_finding(row) for row in cursor.fetchall()]

    def _row_to_finding(self, row: sqlite3.Row) -> SecurityFinding:
        """Helper to convert a sqlite3.Row to a SecurityFinding dataclass."""
        keys = row.keys()
        return SecurityFinding(
            id=row["id"],
            asset_id=row["asset_id"],
            session_id=row["session_id"],
            severity=row["severity"],
            title=row["title"],
            description=row["description"],
            recommendation=row["recommendation"],
            cve_references=row["cve_references"],
            timestamp=row["timestamp"],
            rule_id=row["rule_id"] if "rule_id" in keys and row["rule_id"] is not None else "",
            rule_version=row["rule_version"] if "rule_version" in keys and row["rule_version"] is not None else "1.0",
            confidence=row["confidence"] if "confidence" in keys and row["confidence"] is not None else 1.0,
            risk_score=row["risk_score"] if "risk_score" in keys and row["risk_score"] is not None else 0.0,
            risk_tier=row["risk_tier"] if "risk_tier" in keys and row["risk_tier"] is not None else "Low",
            scoring_explanation=row["scoring_explanation"] if "scoring_explanation" in keys and row["scoring_explanation"] is not None else "",
            evidence=row["evidence"] if "evidence" in keys and row["evidence"] is not None else "",
            status=row["status"] if "status" in keys and row["status"] is not None else STATUS_NEW,
            port_id=row["port_id"] if "port_id" in keys else None,
            port_number=row["port_number"] if "port_number" in keys else None,
            protocol=row["protocol"] if "protocol" in keys and row["protocol"] is not None else "tcp",
            finding_key=row["finding_key"] if "finding_key" in keys and row["finding_key"] is not None else "",
            user_notes=row["user_notes"] if "user_notes" in keys and row["user_notes"] is not None else "",
            resolution_reason=row["resolution_reason"] if "resolution_reason" in keys and row["resolution_reason"] is not None else "",
            ip_address=row["ip_address"] if "ip_address" in keys and row["ip_address"] is not None else "",
            hostname=row["hostname"] if "hostname" in keys and row["hostname"] is not None else "",
        )

    # -------------------------------------------------------------------------
    # Audit Log CRUD
    # -------------------------------------------------------------------------

    def add_audit_log(self, entry: AuditLogEntry) -> int:
        """Inserts an immutable audit log record."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (timestamp, event_type, target, details, user_confirmed)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entry.timestamp,
                    entry.event_type,
                    entry.target,
                    entry.details,
                    1 if entry.user_confirmed else 0,
                ),
            )
            entry_id = int(cursor.lastrowid)
            entry.id = entry_id
            return entry_id

    def list_audit_logs(self, limit: int = 100) -> List[AuditLogEntry]:
        """Lists recent audit log entries."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return [
                AuditLogEntry(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    target=row["target"],
                    details=row["details"],
                    user_confirmed=bool(row["user_confirmed"]),
                )
                for row in cursor.fetchall()
            ]

    # -------------------------------------------------------------------------
    # Dashboard Aggregation Metrics (True DB values, no fakes)
    # -------------------------------------------------------------------------

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Returns verified real counts from the database."""
        with self.get_connection() as conn:
            total_assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            open_ports = conn.execute("SELECT COUNT(*) FROM ports WHERE state = 'open'").fetchone()[0]
            total_scans = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
            completed_scans = conn.execute("SELECT COUNT(*) FROM scan_sessions WHERE status = 'completed'").fetchone()[0]

            # Findings by Rule Severity
            critical_findings = conn.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'Critical'").fetchone()[0]
            high_findings = conn.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'High'").fetchone()[0]
            medium_findings = conn.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'Medium'").fetchone()[0]
            low_findings = conn.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'Low'").fetchone()[0]
            info_findings = conn.execute("SELECT COUNT(*) FROM security_findings WHERE severity = 'Info'").fetchone()[0]

            # Findings by Risk Tier
            tier_critical = conn.execute("SELECT COUNT(*) FROM security_findings WHERE risk_tier = 'Critical'").fetchone()[0]
            tier_high = conn.execute("SELECT COUNT(*) FROM security_findings WHERE risk_tier = 'High'").fetchone()[0]
            tier_medium = conn.execute("SELECT COUNT(*) FROM security_findings WHERE risk_tier = 'Medium'").fetchone()[0]
            tier_low = conn.execute("SELECT COUNT(*) FROM security_findings WHERE risk_tier = 'Low'").fetchone()[0]
            tier_info = conn.execute("SELECT COUNT(*) FROM security_findings WHERE risk_tier = 'Info'").fetchone()[0]

            # Findings by Status
            active_findings = conn.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE status IN ('{STATUS_NEW}', '{STATUS_OPEN}')"
            ).fetchone()[0]
            acknowledged_findings = conn.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE status = '{STATUS_ACKNOWLEDGED}'"
            ).fetchone()[0]
            resolved_findings = conn.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE status = '{STATUS_RESOLVED}'"
            ).fetchone()[0]
            false_positive_findings = conn.execute(
                f"SELECT COUNT(*) FROM security_findings WHERE status = '{STATUS_FALSE_POSITIVE}'"
            ).fetchone()[0]

            total_findings = conn.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0]

            return {
                "total_assets": total_assets,
                "open_ports": open_ports,
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
                "low_findings": low_findings,
                "info_findings": info_findings,
                "tier_critical": tier_critical,
                "tier_high": tier_high,
                "tier_medium": tier_medium,
                "tier_low": tier_low,
                "tier_info": tier_info,
                "active_findings": active_findings,
                "acknowledged_findings": acknowledged_findings,
                "resolved_findings": resolved_findings,
                "false_positive_findings": false_positive_findings,
                "total_findings": total_findings,
            }
