"""Dashboard view for NetSentinel AI.

Displays system status, storage mode, real database metrics, authorized target scan launcher,
and live scan activity monitor with safe cancellation.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.config import ConfigManager
from netsentinel.core.database import DatabaseManager
from netsentinel.core.dependencies import (
    DependencyDetector,
    DiagnosticReport,
    NmapReadinessState,
)
from netsentinel.core.validator import TargetValidator, ValidationResult


class DashboardView(QWidget):
    """Main dashboard panel with system status, database KPIs, target launcher, and live scan console."""

    scan_requested = Signal(str, str)  # target, profile
    cancel_requested = Signal()        # user clicked cancel scan

    def __init__(
        self,
        config_mgr: ConfigManager,
        db_mgr: DatabaseManager,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.config_mgr = config_mgr
        self.db_mgr = db_mgr
        self.current_validation: Optional[ValidationResult] = None
        self._elapsed_seconds = 0

        # Timer for live elapsed time updates
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._update_timer_tick)

        self._init_ui()
        self.refresh_metrics()

    def _init_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        outer_layout.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)

        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(28, 28, 28, 28)
        main_layout.setSpacing(20)

        # Header Title
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        title = QLabel("Network Discovery & Security Dashboard")
        title.setProperty("class", "viewTitle")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")

        subtitle = QLabel("Authorized network reconnaissance, inventory tracking, and risk auditing")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        main_layout.addLayout(header_layout)

        # Environment Banner Card
        env_card = QFrame()
        env_card.setProperty("class", "contentCard")
        env_card_layout = QHBoxLayout(env_card)
        env_card_layout.setContentsMargins(16, 12, 16, 12)

        self.storage_badge = QLabel(self.config_mgr.storage_mode_label)
        self.storage_badge.setStyleSheet(
            "background-color: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
        )
        env_card_layout.addWidget(self.storage_badge)

        self.diag_badge = QLabel("Analyzing Dependencies...")
        self.diag_badge.setStyleSheet(
            "background-color: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
        )
        env_card_layout.addWidget(self.diag_badge)

        self.engine_badge = QLabel("Engine: Nmap Connect / Native TCP")
        self.engine_badge.setStyleSheet(
            "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
        )
        env_card_layout.addWidget(self.engine_badge)

        env_card_layout.addStretch()
        main_layout.addWidget(env_card)

        # Metrics KPI Grid (True Database counts)
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(16)

        self.metric_assets = self._create_kpi_card("Assets Discovered", "0", "#2563EB")
        self.metric_ports = self._create_kpi_card("Open Ports Found", "0", "#0284C7")
        self.metric_scans = self._create_kpi_card("Completed Scans", "0", "#059669")
        self.metric_findings = self._create_kpi_card("Security Findings", "0", "#D97706")

        kpi_grid.addWidget(self.metric_assets["frame"], 0, 0)
        kpi_grid.addWidget(self.metric_ports["frame"], 0, 1)
        kpi_grid.addWidget(self.metric_scans["frame"], 0, 2)
        kpi_grid.addWidget(self.metric_findings["frame"], 0, 3)
        main_layout.addLayout(kpi_grid)

        # Scan Launcher Card
        launcher_card = QFrame()
        launcher_card.setProperty("class", "contentCard")
        launcher_layout = QVBoxLayout(launcher_card)
        launcher_layout.setContentsMargins(20, 20, 20, 20)
        launcher_layout.setSpacing(14)

        launcher_title = QLabel("Authorized Scan Console")
        launcher_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #0F172A;")
        launcher_layout.addWidget(launcher_title)

        # Target input + profile row
        inputs_row = QHBoxLayout()
        inputs_row.setSpacing(12)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter Target (e.g. 192.168.1.1, 10.0.0.0/24, or hostname)")
        self.target_input.textChanged.connect(self._on_target_changed)
        inputs_row.addWidget(self.target_input, stretch=3)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems([
            "Safe TCP Connect Scan (-sT)",
            "Service & Version Detection (-sV)",
            "Host Discovery Ping Sweep (-sn)",
        ])
        inputs_row.addWidget(self.profile_combo, stretch=2)

        self.scan_btn = QPushButton("Start Discovery Scan")
        self.scan_btn.setProperty("class", "primaryButton")
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._on_start_scan_clicked)
        inputs_row.addWidget(self.scan_btn, stretch=1)

        launcher_layout.addLayout(inputs_row)

        # Validation Feedback Banner
        self.validation_feedback = QLabel("Enter a valid network IP, CIDR subnet, or hostname to begin.")
        self.validation_feedback.setStyleSheet(
            "color: #64748B; font-size: 12px; padding: 4px 0px;"
        )
        launcher_layout.addWidget(self.validation_feedback)

        # Authorization Confirmation Checkbox
        auth_layout = QHBoxLayout()
        auth_layout.setSpacing(8)
        self.auth_checkbox = QCheckBox(
            "I certify that I am explicitly authorized to perform security auditing on this target network."
        )
        self.auth_checkbox.setStyleSheet("font-weight: 600; color: #1E293B;")
        self.auth_checkbox.toggled.connect(self._evaluate_launch_readiness)
        auth_layout.addWidget(self.auth_checkbox)
        auth_layout.addStretch()
        launcher_layout.addLayout(auth_layout)

        main_layout.addWidget(launcher_card)

        # Live Scan Activity Monitor Card (Milestone 2)
        self.monitor_card = QFrame()
        self.monitor_card.setProperty("class", "contentCard")
        monitor_layout = QVBoxLayout(self.monitor_card)
        monitor_layout.setContentsMargins(20, 20, 20, 20)
        monitor_layout.setSpacing(12)

        monitor_header = QHBoxLayout()
        monitor_title = QLabel("Live Scan Monitor & Output Feed")
        monitor_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #0F172A;")
        monitor_header.addWidget(monitor_title)

        monitor_header.addStretch()

        self.state_badge = QLabel("IDLE")
        self.state_badge.setStyleSheet(
            "background-color: #F1F5F9; color: #64748B; border: 1px solid #CBD5E1; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;"
        )
        monitor_header.addWidget(self.state_badge)

        self.timer_label = QLabel("⏱️ 00:00")
        self.timer_label.setStyleSheet("font-size: 12px; font-weight: 600; color: #475569;")
        monitor_header.addWidget(self.timer_label)

        self.cancel_btn = QPushButton("Cancel Scan")
        self.cancel_btn.setStyleSheet(
            "background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; "
            "border-radius: 6px; padding: 6px 14px; font-weight: 600; font-size: 12px;"
        )
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_clicked)
        monitor_header.addWidget(self.cancel_btn)

        monitor_layout.addLayout(monitor_header)

        self.status_narrative = QLabel("No active scan in progress.")
        self.status_narrative.setStyleSheet("font-size: 13px; color: #475569;")
        monitor_layout.addWidget(self.status_narrative)

        # Log text area (Monospace output feed)
        self.log_viewer = QPlainTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setMaximumHeight(140)
        self.log_viewer.setStyleSheet(
            "background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px; "
            "font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #1E293B;"
        )
        monitor_layout.addWidget(self.log_viewer)

        main_layout.addWidget(self.monitor_card)
        main_layout.addStretch()

    def _create_kpi_card(self, title: str, initial_value: str, accent_color: str) -> dict:
        frame = QFrame()
        frame.setProperty("class", "contentCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 12px; font-weight: 600; color: #64748B; text-transform: uppercase;")

        lbl_value = QLabel(initial_value)
        lbl_value.setStyleSheet(f"font-size: 28px; font-weight: 700; color: {accent_color};")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_value)
        return {"frame": frame, "value_label": lbl_value}

    def _on_target_changed(self, text: str) -> None:
        """Validates target in real-time as user types."""
        if not text.strip():
            self.current_validation = None
            self.validation_feedback.setText("Enter a valid network IP, CIDR subnet, or hostname to begin.")
            self.validation_feedback.setStyleSheet("color: #64748B; font-size: 12px;")
            self._evaluate_launch_readiness()
            return

        result = TargetValidator.validate(text)
        self.current_validation = result

        if not result.is_valid:
            self.validation_feedback.setText(f"❌ {result.error}")
            self.validation_feedback.setStyleSheet("color: #DC2626; font-size: 12px; font-weight: 600;")
        else:
            msg = f"✓ Valid {result.target_type.upper()} ({result.host_count:,} target host{'s' if result.host_count > 1 else ''})"
            color = "#059669"
            if result.warning:
                msg += f" — ⚠️ {result.warning}"
                color = "#D97706"
            self.validation_feedback.setText(msg)
            self.validation_feedback.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: 500;")

        self._evaluate_launch_readiness()

    def _evaluate_launch_readiness(self) -> None:
        """Enables scan button only when input is valid and user confirmed authorization."""
        can_run = (
            self.current_validation is not None
            and self.current_validation.is_valid
            and self.auth_checkbox.isChecked()
        )
        self.scan_btn.setEnabled(can_run)

    def _on_start_scan_clicked(self) -> None:
        if self.current_validation and self.current_validation.is_valid and self.auth_checkbox.isChecked():
            profile = self.profile_combo.currentText()
            target = self.current_validation.normalized_target
            self.scan_requested.emit(target, profile)

    def _on_cancel_clicked(self) -> None:
        self.cancel_requested.emit()
        self.cancel_btn.setEnabled(False)
        self.status_narrative.setText("Cancellation requested... terminating scanner process.")

    # -------------------------------------------------------------------------
    # Scan Lifecycle Slots (Connected to Worker / MainWindow)
    # -------------------------------------------------------------------------

    def on_scan_started(self, target: str, profile: str) -> None:
        """Locks controls, resets timer, and updates UI when scan begins."""
        self.scan_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.target_input.setEnabled(False)
        self.profile_combo.setEnabled(False)
        self.auth_checkbox.setEnabled(False)

        self.log_viewer.clear()
        self._elapsed_seconds = 0
        self.timer_label.setText("⏱️ 00:00")
        self.timer.start()

        self.update_state_badge("RUNNING")
        self.status_narrative.setText(f"Initiating {profile} for {target}...")

    def update_state_badge(self, state: str) -> None:
        """Updates color and text of state badge."""
        self.state_badge.setText(state.upper())
        s = state.upper()
        if s == "RUNNING":
            self.state_badge.setStyleSheet("background-color: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")
        elif s in ("PARSING", "SAVING"):
            self.state_badge.setStyleSheet("background-color: #FDF4FF; color: #A855F7; border: 1px solid #F0ABFC; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")
        elif s == "COMPLETED":
            self.state_badge.setStyleSheet("background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")
        elif s == "CANCELLED":
            self.state_badge.setStyleSheet("background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")
        elif s == "FAILED":
            self.state_badge.setStyleSheet("background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")
        else:
            self.state_badge.setStyleSheet("background-color: #F1F5F9; color: #64748B; border: 1px solid #CBD5E1; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;")

    def set_status_message(self, message: str) -> None:
        self.status_narrative.setText(message)

    def append_log_line(self, line: str) -> None:
        self.log_viewer.appendPlainText(line)
        # Scroll to bottom
        sb = self.log_viewer.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_scan_finished(self, success: bool, message: str) -> None:
        """Unlocks controls, stops timer, and updates metrics when scan finishes."""
        self.timer.stop()
        self.cancel_btn.setEnabled(False)
        self.target_input.setEnabled(True)
        self.profile_combo.setEnabled(True)
        self.auth_checkbox.setEnabled(True)

        self._evaluate_launch_readiness()
        self.refresh_metrics()

    def _update_timer_tick(self) -> None:
        self._elapsed_seconds += 1
        mins = self._elapsed_seconds // 60
        secs = self._elapsed_seconds % 60
        self.timer_label.setText(f"⏱️ {mins:02d}:{secs:02d}")

    def update_diagnostics_summary(self, report: DiagnosticReport) -> None:
        """Updates diagnostic badges on dashboard."""
        if report.can_raw_syn_scan:
            self.diag_badge.setText("Privileges: Elevated (Full Capabilities)")
            self.diag_badge.setStyleSheet(
                "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        else:
            self.diag_badge.setText("Privileges: Standard User (TCP Connect Only)")
            self.diag_badge.setStyleSheet(
                "background-color: #F8FAFC; color: #475569; border: 1px solid #CBD5E1; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )

        readiness = report.nmap_readiness
        if readiness == NmapReadinessState.READY_ELEVATED:
            self.engine_badge.setText("Nmap Engine: Ready (Full Capabilities)")
            self.engine_badge.setStyleSheet(
                "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        elif readiness == NmapReadinessState.READY_STANDARD:
            self.engine_badge.setText("Nmap Engine: Ready (TCP Connect)")
            self.engine_badge.setStyleSheet(
                "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        elif readiness == NmapReadinessState.DATA_FILES_MISSING:
            self.engine_badge.setText("Nmap Engine: Incomplete")
            self.engine_badge.setStyleSheet(
                "background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        elif readiness == NmapReadinessState.LAUNCH_ERROR:
            self.engine_badge.setText("Nmap Engine: Launch Error")
            self.engine_badge.setStyleSheet(
                "background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        else:  # MISSING
            self.engine_badge.setText("Nmap Engine: Missing")
            self.engine_badge.setStyleSheet(
                "background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )

    def refresh_metrics(self) -> None:
        """Queries SQLite database to populate real KPI values without fabrication."""
        try:
            metrics = self.db_mgr.get_dashboard_metrics()
            self.metric_assets["value_label"].setText(f"{metrics['total_assets']:,}")
            self.metric_ports["value_label"].setText(f"{metrics['open_ports']:,}")
            self.metric_scans["value_label"].setText(f"{metrics['completed_scans']:,}")
            self.metric_findings["value_label"].setText(f"{metrics['total_findings']:,}")
        except Exception:
            self.metric_assets["value_label"].setText("0")
            self.metric_ports["value_label"].setText("0")
            self.metric_scans["value_label"].setText("0")
            self.metric_findings["value_label"].setText("0")
