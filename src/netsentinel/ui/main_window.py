"""Main Application Window for NetSentinel AI."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.config import APP_NAME, APP_VERSION, ConfigManager
from netsentinel.core.database import DatabaseManager
from netsentinel.core.dependencies import DependencyDetector, DiagnosticReport
from netsentinel.core.models import AuditLogEntry, ScanSession
from netsentinel.core.scan_worker import ScanWorker
from netsentinel.ui.theme import LIGHT_THEME_QSS
from netsentinel.ui.views.dashboard_view import DashboardView
from netsentinel.ui.views.dependencies_view import DependenciesView
from netsentinel.ui.views.findings_view import FindingsView
from netsentinel.ui.views.history_view import HistoryView
from netsentinel.ui.views.inventory_view import InventoryView
from netsentinel.ui.views.settings_view import SettingsView


class MainWindow(QMainWindow):
    """NetSentinel AI primary desktop window shell."""

    def __init__(
        self,
        config_mgr: ConfigManager,
        db_mgr: DatabaseManager,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.config_mgr = config_mgr
        self.db_mgr = db_mgr
        self.nav_buttons: list[QPushButton] = []
        self.active_worker: Optional[ScanWorker] = None

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Network Discovery & AI Security Auditing")
        self.resize(1180, 780)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(LIGHT_THEME_QSS)

        self._init_ui()
        self._wire_signals()

        # Initial diagnostic sync
        self.dependencies_view.run_diagnostics()

    def _init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Top Header Bar
        header = QFrame()
        header.setObjectName("topHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(14)

        # Brand / Title
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(1)
        title_lbl = QLabel(f"🛡️  {APP_NAME}")
        title_lbl.setObjectName("appTitle")
        subtitle_lbl = QLabel("Autonomous Discovery & Defensive Security Auditing")
        subtitle_lbl.setObjectName("appSubtitle")
        brand_layout.addWidget(title_lbl)
        brand_layout.addWidget(subtitle_lbl)
        header_layout.addLayout(brand_layout)

        header_layout.addStretch()

        # Top Status Badges
        self.top_storage_badge = QLabel(self.config_mgr.storage_mode_label)
        self.top_storage_badge.setStyleSheet(
            "background-color: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
        )
        header_layout.addWidget(self.top_storage_badge)

        self.top_priv_badge = QLabel("Privileges: Checking...")
        self.top_priv_badge.setStyleSheet(
            "background-color: #F8FAFC; color: #475569; border: 1px solid #E2E8F0; "
            "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
        )
        header_layout.addWidget(self.top_priv_badge)

        root_layout.addWidget(header)

        # 2. Main Content Split (Sidebar + Stacked Views)
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Navigation Rail
        sidebar = QFrame()
        sidebar.setObjectName("sidebarFrame")
        sidebar.setFixedWidth(230)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(6)

        nav_header = QLabel("NAVIGATION")
        nav_header.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8; padding-left: 8px; margin-bottom: 4px;")
        sidebar_layout.addWidget(nav_header)

        self.btn_dash = self._create_nav_button("📊  Dashboard", 0)
        self.btn_inv = self._create_nav_button("🖥️  Asset Inventory", 1)
        self.btn_hist = self._create_nav_button("📜  Scan History", 2)
        self.btn_findings = self._create_nav_button("🛡️  Security Findings", 3)
        self.btn_diag = self._create_nav_button("⚙️  Dependency Diagnostics", 4)
        self.btn_settings = self._create_nav_button("🔧  Settings", 5)

        for btn in [self.btn_dash, self.btn_inv, self.btn_hist, self.btn_findings, self.btn_diag, self.btn_settings]:
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()

        # Version Info footer in sidebar
        side_footer = QLabel(f"v{APP_VERSION} (Win64 Portable)")
        side_footer.setStyleSheet("font-size: 11px; color: #94A3B8; text-align: center; padding: 8px;")
        side_footer.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(side_footer)

        body_layout.addWidget(sidebar)

        # Stacked Views Container
        self.stack = QStackedWidget()
        self.dashboard_view = DashboardView(self.config_mgr, self.db_mgr)
        self.inventory_view = InventoryView(self.db_mgr)
        self.history_view = HistoryView(self.db_mgr)
        self.findings_view = FindingsView(self.db_mgr)
        self.dependencies_view = DependenciesView()
        self.settings_view = SettingsView(self.config_mgr)

        self.stack.addWidget(self.dashboard_view)      # index 0
        self.stack.addWidget(self.inventory_view)      # index 1
        self.stack.addWidget(self.history_view)        # index 2
        self.stack.addWidget(self.findings_view)       # index 3
        self.stack.addWidget(self.dependencies_view)   # index 4
        self.stack.addWidget(self.settings_view)       # index 5

        body_layout.addWidget(self.stack)
        root_layout.addWidget(body)

        # 3. Status Bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready. Database initialized with WAL mode.")

        # Bottom Right: Developer Credit
        self.credit_label = QLabel("Developed by: Vivek Nigam")
        self.credit_label.setObjectName("creditLabel")
        self.credit_label.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 500; padding-right: 12px;")
        self.statusBar.addPermanentWidget(self.credit_label)

        # Activate initial view
        self._switch_view(0)

    def _create_nav_button(self, label: str, view_index: int) -> QPushButton:
        btn = QPushButton(label)
        btn.setObjectName("navButton")
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda: self._switch_view(view_index))
        self.nav_buttons.append(btn)
        return btn

    def _switch_view(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            is_active = (i == index)
            btn.setProperty("active", "true" if is_active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

        # Refresh the active view's data
        if index == 0:
            self.dashboard_view.refresh_metrics()
        elif index == 1:
            self.inventory_view.refresh()
        elif index == 2:
            self.history_view.refresh()
        elif index == 3:
            self.findings_view.refresh()

    def _wire_signals(self) -> None:
        self.dependencies_view.diagnostics_updated.connect(self._on_diagnostics_updated)
        self.dashboard_view.scan_requested.connect(self._handle_scan_request)
        self.dashboard_view.cancel_requested.connect(self._handle_cancel_request)
        self.settings_view.clear_requested.connect(self._handle_clear_all_data)
        self.history_view.clear_requested.connect(self._handle_clear_all_data)

    def _on_diagnostics_updated(self, report: DiagnosticReport) -> None:
        # Update dashboard badges
        self.dashboard_view.update_diagnostics_summary(report)

        # Update header badge
        if report.is_elevated:
            self.top_priv_badge.setText("Privileges: Elevated Admin")
            self.top_priv_badge.setStyleSheet(
                "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )
        else:
            self.top_priv_badge.setText("Privileges: Standard User")
            self.top_priv_badge.setStyleSheet(
                "background-color: #F8FAFC; color: #64748B; border: 1px solid #CBD5E1; "
                "border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;"
            )

    def _handle_scan_request(self, target: str, profile: str) -> None:
        """Starts asynchronous background scan worker."""
        if hasattr(self.db_mgr, "is_clearing") and self.db_mgr.is_clearing:
            QMessageBox.warning(self, "Database Busy", "Cannot start a discovery scan while database reset is in progress.")
            return

        if self.active_worker and self.active_worker.isRunning():
            QMessageBox.warning(self, "Scan Active", "A discovery scan is already actively running.")
            return

        # Prepare Dashboard UI
        self.dashboard_view.on_scan_started(target, profile)
        self.statusBar.showMessage(f"Active discovery scan initiated for target '{target}'...")

        # Initialize background worker
        self.active_worker = ScanWorker(
            target=target,
            profile=profile,
            db_mgr=self.db_mgr,
            parent=self,
        )

        # Wire worker signals
        self.active_worker.state_changed.connect(self.dashboard_view.update_state_badge)
        self.active_worker.status_message.connect(self._on_worker_status_message)
        self.active_worker.log_line.connect(self.dashboard_view.append_log_line)
        self.active_worker.scan_finished.connect(self._on_scan_finished)

        # Start thread
        self.active_worker.start()

    def _handle_cancel_request(self) -> None:
        """Propagates cancellation request to active background worker."""
        if self.active_worker and self.active_worker.isRunning():
            self.statusBar.showMessage("Cancelling active scan process...")
            self.active_worker.cancel_scan()

    def _on_worker_status_message(self, message: str) -> None:
        self.dashboard_view.set_status_message(message)
        self.statusBar.showMessage(message)

    def _on_scan_finished(self, session_id: int, success: bool, message: str, scan_result: object) -> None:
        """Handles scan completion, auto-refreshes inventory, history and metrics."""
        self.dashboard_view.on_scan_finished(success, message)
        self.dashboard_view.refresh_metrics()
        self.inventory_view.refresh()
        self.history_view.refresh()
        self.findings_view.refresh()

        if success:
            self.statusBar.showMessage(f"✓ Scan #{session_id} completed successfully.", 8000)
        else:
            if not session_id or session_id <= 0:
                self.statusBar.showMessage(f"⚠️ Scan failed to start: {message}", 8000)
            else:
                self.statusBar.showMessage(f"⚠️ Scan #{session_id} ended: {message}", 8000)

        # Clean up worker thread
        if self.active_worker:
            self.active_worker.quit()
            self.active_worker.wait(1000)
            self.active_worker = None

    def _handle_clear_all_data(self) -> None:
        """Centralized handler for complete scan and database reset."""
        # 1. Check active scan status
        if (self.active_worker and self.active_worker.isRunning()) or (
            hasattr(self.db_mgr, "is_scan_active") and self.db_mgr.is_scan_active
        ):
            QMessageBox.warning(
                self,
                "Scan Active",
                "Cannot clear database while a network discovery scan is actively running.\n\n"
                "Please cancel or wait for the active scan to complete before resetting data.",
            )
            return

        # 2. Explicit confirmation dialog listing all data categories being deleted
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Confirm Complete Data Reset")
        msg_box.setStyleSheet(
            "QMessageBox { background-color: #FFFFFF; color: #0F172A; } "
            "QLabel { color: #0F172A; background-color: transparent; font-size: 13px; }"
        )
        msg_box.setText("Are you sure you want to permanently erase all NetSentinel AI scan data?")
        msg_box.setInformativeText(
            "This operation will permanently delete all records across:\n\n"
            "  • All historical scan sessions and execution logs\n"
            "  • All discovered network assets and host inventories\n"
            "  • All identified network ports and services\n"
            "  • All security findings, risk scores, and resolutions\n"
            "  • All compliance audit log entries\n\n"
            "This action cannot be undone."
        )
        cancel_btn = msg_box.addButton("Cancel", QMessageBox.RejectRole)
        cancel_btn.setStyleSheet(
            "QPushButton { background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; "
            "border-radius: 6px; padding: 7px 18px; font-weight: 600; font-size: 12px; min-width: 80px; } "
            "QPushButton:hover { background-color: #E2E8F0; border-color: #94A3B8; } "
            "QPushButton:focus { border: 2px solid #2563EB; outline: none; }"
        )
        confirm_btn = msg_box.addButton("Permanently Erase All Data", QMessageBox.DestructiveRole)
        confirm_btn.setStyleSheet(
            "QPushButton { background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; "
            "border-radius: 6px; padding: 7px 18px; font-weight: 600; font-size: 12px; min-width: 160px; } "
            "QPushButton:hover { background-color: #FEE2E2; border-color: #F87171; } "
            "QPushButton:focus { border: 2px solid #DC2626; outline: none; }"
        )
        # Cancel must be the default action (destructive confirmation must not be default)
        msg_box.setDefaultButton(cancel_btn)
        msg_box.setEscapeButton(cancel_btn)
        cancel_btn.setFocus()

        msg_box.exec()
        if msg_box.clickedButton() != confirm_btn:
            return

        # 3. Double-check scan status and acquire database-operation guard
        if (self.active_worker and self.active_worker.isRunning()) or not self.db_mgr.acquire_clear_lock():
            QMessageBox.warning(
                self,
                "Operation Blocked",
                "A scan session was initiated or the database is currently busy. Reset aborted.",
            )
            return

        # Disable UI controls while clearing
        self.settings_view.clear_data_btn.setEnabled(False)
        self.history_view.clear_btn.setEnabled(False)
        self.statusBar.showMessage("Erasing database records and compacting storage...")

        try:
            # 4. Perform deletion transaction & compaction
            res = self.db_mgr.clear_all_data()
            if not res.records_cleared:
                QMessageBox.critical(
                    self,
                    "Database Error",
                    f"Failed to clear database records:\n{res.error or 'Unknown error'}",
                )
                self.statusBar.showMessage("Database reset failed.")
                return

            # 5. Refresh all views after successful commit
            self.dashboard_view.refresh_metrics()
            self.inventory_view.refresh()
            self.history_view.refresh()
            self.findings_view.refresh()

            if res.compaction_succeeded:
                self.statusBar.showMessage("All scan history and database records have been completely cleared.")
                QMessageBox.information(
                    self,
                    "Data Reset Complete",
                    "All scan sessions, discovered assets, open ports, security findings, "
                    "and audit logs have been successfully cleared.",
                )
            else:
                self.statusBar.showMessage("Data cleared, but database compaction failed.")
                QMessageBox.warning(
                    self,
                    "Data Reset Complete (Compaction Warning)",
                    f"All database records were successfully deleted, but SQLite storage compaction (VACUUM) failed:\n"
                    f"{res.compaction_error}\n\n"
                    f"The database is clean, but disk space may not be fully reclaimed until restart.",
                )
        finally:
            self.db_mgr.release_clear_lock()
            self.settings_view.clear_data_btn.setEnabled(True)
            self.history_view.clear_btn.setEnabled(True)

    def closeEvent(self, event) -> None:
        """Ensures any active scanner background process is safely terminated on window close."""
        if self.active_worker and self.active_worker.isRunning():
            self.active_worker.cancel_scan()
            self.active_worker.quit()
            self.active_worker.wait(2000)
        event.accept()
