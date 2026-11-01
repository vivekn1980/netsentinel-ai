"""Scan history view for NetSentinel AI.

Renders prior discovery executions, profiles, start/end timestamps,
execution durations, and statuses with comprehensive scan inspection dialogs.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.database import DatabaseManager
from netsentinel.ui.dialogs.export_dialog import ExportDialog
from netsentinel.ui.dialogs.scan_compare_dialog import ScanCompareDialog



class ScanDetailDialog(QDialog):
    """Modal dialog displaying comprehensive historical scan inspection details."""

    def __init__(self, details: dict, db_mgr: Optional[DatabaseManager] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.details = details
        self.db_mgr = db_mgr
        session = details.get("session")
        target = session.target_input if session else "Unknown"
        self.setWindowTitle(f"Scan Session Inspection — #{session.id if session else ''} ({target})")
        self.resize(800, 560)
        self.setStyleSheet("background-color: #FFFFFF; font-family: 'Segoe UI', sans-serif;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        if not session:
            layout.addWidget(QLabel("No session details available."))
            return

        # Top Session Summary Card
        card = QFrame()
        card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;")
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(16, 14, 16, 14)
        card_l.setSpacing(6)

        title_row = QHBoxLayout()
        title = QLabel(f"Scan #{session.id}: {session.target_input}")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #0F172A;")
        title_row.addWidget(title)

        title_row.addStretch()

        status_lbl = QLabel(session.status.upper())
        st = session.status.lower()
        if st == "completed":
            status_lbl.setStyleSheet("background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        elif st == "cancelled":
            status_lbl.setStyleSheet("background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        else:
            status_lbl.setStyleSheet("background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        title_row.addWidget(status_lbl)
        card_l.addLayout(title_row)

        sub_info = (
            f"Profile: {session.profile}  •  Duration: {session.duration_seconds:.2f}s  •  "
            f"Discovered: {session.hosts_discovered} host(s), {session.ports_found} open port(s)"
        )
        card_l.addWidget(QLabel(sub_info))

        time_info = f"Started: {session.start_time.replace('T', ' ')}  |  Finished: {(session.end_time or 'In Progress').replace('T', ' ')}"
        time_lbl = QLabel(time_info)
        time_lbl.setStyleSheet("font-size: 11px; color: #64748B;")
        card_l.addWidget(time_lbl)

        if session.command_executed:
            cmd_lbl = QLabel(f"Executed: {session.command_executed}")
            cmd_lbl.setStyleSheet("font-size: 11px; color: #475569; font-family: monospace;")
            cmd_lbl.setWordWrap(True)
            card_l.addWidget(cmd_lbl)

        if session.error_message:
            err_lbl = QLabel(f"Scanner Diagnostics: {session.error_message}")
            err_lbl.setStyleSheet("font-size: 11px; color: #DC2626; font-style: italic;")
            err_lbl.setWordWrap(True)
            card_l.addWidget(err_lbl)

        layout.addWidget(card)

        # Tabbed Container for Discovered Hosts & Network Services
        self.tabs = QTabWidget()

        # 1. Discovered Hosts Tab
        assets = details.get("assets", [])
        hosts_widget = QWidget()
        hosts_layout = QVBoxLayout(hosts_widget)
        hosts_layout.setContentsMargins(8, 8, 8, 8)
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(5)
        self.hosts_table.setHorizontalHeaderLabels(["Host IP", "Hostname", "MAC Address", "Vendor / OS", "Status"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hosts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.hosts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.hosts_table.verticalHeader().setVisible(False)
        self.hosts_table.setAlternatingRowColors(True)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hosts_table.setRowCount(len(assets))

        for row, a in enumerate(assets):
            ip_str = a.get("ip_address", "—") or "—"
            host_str = a.get("hostname", "—") or "—"
            mac_str = a.get("mac_address", "—") or "—"

            v = a.get("vendor") or ""
            o = a.get("os_name") or ""
            detail_str = f"{v} ({o})" if (v and o) else (v or o or "—")
            status_str = "Active / Up"

            ip_item = QTableWidgetItem(ip_str)
            ip_item.setData(Qt.UserRole, a.get("id"))
            host_item = QTableWidgetItem(host_str)
            mac_item = QTableWidgetItem(mac_str)
            detail_item = QTableWidgetItem(detail_str)
            status_item = QTableWidgetItem(status_str)
            status_item.setTextAlignment(Qt.AlignCenter)

            self.hosts_table.setItem(row, 0, ip_item)
            self.hosts_table.setItem(row, 1, host_item)
            self.hosts_table.setItem(row, 2, mac_item)
            self.hosts_table.setItem(row, 3, detail_item)
            self.hosts_table.setItem(row, 4, status_item)

        self.hosts_table.itemDoubleClicked.connect(self._on_host_double_clicked)
        hosts_layout.addWidget(self.hosts_table)
        self.tabs.addTab(hosts_widget, f"🖥️  Discovered Hosts ({len(assets)})")

        # 2. Discovered Network Services Tab
        ports = details.get("ports", [])
        ports_widget = QWidget()
        ports_layout = QVBoxLayout(ports_widget)
        ports_layout.setContentsMargins(8, 8, 8, 8)
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(5)
        self.ports_table.setHorizontalHeaderLabels(["Host IP", "Hostname", "Port", "State", "Service / Product"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.ports_table.verticalHeader().setVisible(False)
        self.ports_table.setAlternatingRowColors(True)
        self.ports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ports_table.setRowCount(len(ports))

        for row, p in enumerate(ports):
            ip_item = QTableWidgetItem(p.get("ip_address", "—"))
            host_item = QTableWidgetItem(p.get("hostname", "—") or "—")
            p_item = QTableWidgetItem(f"{p.get('port_number')}/{p.get('protocol', 'tcp')}")
            p_item.setTextAlignment(Qt.AlignCenter)
            state_item = QTableWidgetItem(p.get("state", "open"))
            state_item.setTextAlignment(Qt.AlignCenter)

            svc = p.get("service_name", "") or ""
            prod = p.get("product", "") or ""
            ver = p.get("version", "") or ""
            detail_str = f"{svc} ({prod} {ver})".strip() if prod else svc
            svc_item = QTableWidgetItem(detail_str or "—")

            self.ports_table.setItem(row, 0, ip_item)
            self.ports_table.setItem(row, 1, host_item)
            self.ports_table.setItem(row, 2, p_item)
            self.ports_table.setItem(row, 3, state_item)
            self.ports_table.setItem(row, 4, svc_item)

        ports_layout.addWidget(self.ports_table)
        self.tabs.addTab(ports_widget, f"🔌  Discovered Services ({len(ports)})")

        # Select tab based on scan type:
        # Default to Discovered Hosts tab (index 0) if host discovery or ports == 0;
        # If open ports were found and assets are 0, select ports tab.
        if len(ports) > 0 and len(assets) == 0:
            self.tabs.setCurrentIndex(1)
        else:
            self.tabs.setCurrentIndex(0)

        layout.addWidget(self.tabs)

        btn_row = QHBoxLayout()
        if self.db_mgr and session and session.id:
            btn_export = QPushButton("Export Session Report...")
            btn_export.setStyleSheet(
                "background-color: #0284C7; color: white; padding: 6px 16px; border-radius: 6px; font-weight: 600;"
            )
            btn_export.clicked.connect(self._on_export_session)
            btn_row.addWidget(btn_export)

        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(
            "background-color: #F1F5F9; color: #475569; padding: 6px 18px; border: 1px solid #CBD5E1; border-radius: 6px; font-weight: 600;"
        )
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    def _on_host_double_clicked(self, item: QTableWidgetItem) -> None:
        if not self.db_mgr:
            return
        row = item.row()
        ip_item = self.hosts_table.item(row, 0)
        if not ip_item:
            return
        asset_id = ip_item.data(Qt.UserRole)
        if asset_id:
            asset = self.db_mgr.get_asset(asset_id)
            if asset:
                from netsentinel.ui.views.inventory_view import AssetDetailDialog
                ports = self.db_mgr.get_ports_for_asset(asset_id)
                dlg = AssetDetailDialog(asset, ports, parent=self)
                dlg.exec()

    def _on_export_session(self) -> None:
        session = self.details.get("session")
        if not session or not session.id or not self.db_mgr:
            return
        dlg = ExportDialog(
            db_mgr=self.db_mgr,
            session_id=session.id,
            target_name=session.target_input,
            parent=self,
        )
        dlg.exec()



class HistoryView(QWidget):
    """Historical scan audit log view with inspection capabilities."""

    clear_requested = Signal()

    def __init__(self, db_mgr: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db_mgr = db_mgr
        self._init_ui()
        self.refresh()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        # Header Title
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Scan History & Audit Trail")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("Chronological log of discovery runs (Double-click any scan row to inspect discovered hosts)")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)

        header_row.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setProperty("class", "secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_btn)

        self.compare_btn = QPushButton("Compare Scans...")
        self.compare_btn.setStyleSheet("padding: 7px 16px; background-color: #0F172A; color: #FFFFFF; font-weight: 600; border-radius: 6px; border: none; font-size: 13px;")
        self.compare_btn.clicked.connect(self._on_compare_clicked)
        header_row.addWidget(self.compare_btn)

        self.clear_btn = QPushButton("Clear All History...")
        self.clear_btn.setStyleSheet(
            "QPushButton { background-color: #FEE2E2; color: #DC2626; border: 1px solid #FCA5A5; "
            "padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 13px; } "
            "QPushButton:hover { background-color: #DC2626; color: #FFFFFF; border-color: #DC2626; }"
        )
        self.clear_btn.clicked.connect(self._on_clear_clicked)
        header_row.addWidget(self.clear_btn)
        layout.addLayout(header_row)

        # Stacked Container for Table vs. Empty State
        self.stack = QStackedWidget()

        # 1. Empty State Frame
        self.empty_frame = QFrame()
        self.empty_frame.setProperty("class", "contentCard")
        empty_layout = QVBoxLayout(self.empty_frame)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.setSpacing(12)
        empty_layout.setContentsMargins(40, 60, 40, 60)

        empty_icon = QLabel("📜")
        empty_icon.setStyleSheet("font-size: 42px;")
        empty_icon.setAlignment(Qt.AlignCenter)

        empty_title = QLabel("No Scan History Recorded")
        empty_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #1E293B;")
        empty_title.setAlignment(Qt.AlignCenter)

        empty_desc = QLabel(
            "Every scan initiated from the Dashboard is recorded in your local SQLite audit log. "
            "Start a scan to begin building your compliance history."
        )
        empty_desc.setStyleSheet("font-size: 13px; color: #64748B; max-width: 480px;")
        empty_desc.setWordWrap(True)
        empty_desc.setAlignment(Qt.AlignCenter)

        empty_layout.addWidget(empty_icon)
        empty_layout.addWidget(empty_title)
        empty_layout.addWidget(empty_desc)
        self.stack.addWidget(self.empty_frame)

        # 2. Table Container Frame
        self.table_frame = QFrame()
        self.table_frame.setProperty("class", "contentCard")
        table_layout = QVBoxLayout(self.table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Scan ID", "Target Input", "Profile", "Start Time", "Duration", "Discovered", "Status"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)

        table_layout.addWidget(self.table)
        self.stack.addWidget(self.table_frame)

        layout.addWidget(self.stack)

    def _on_clear_clicked(self) -> None:
        self.clear_requested.emit()

    def refresh(self) -> None:
        """Queries SQLite database for recent scan sessions."""
        sessions = self.db_mgr.list_scan_sessions(limit=100)
        if not sessions:
            self.stack.setCurrentIndex(0)
            return

        self.stack.setCurrentIndex(1)
        self.table.setRowCount(len(sessions))
        for row, session in enumerate(sessions):
            id_item = QTableWidgetItem(f"#{session.id}")
            id_item.setData(Qt.UserRole, session.id)
            id_item.setTextAlignment(Qt.AlignCenter)

            target_item = QTableWidgetItem(session.target_input)
            profile_item = QTableWidgetItem(session.profile)
            start_item = QTableWidgetItem(session.start_time.replace("T", " "))

            dur_str = f"{session.duration_seconds:.1f}s" if session.duration_seconds > 0 else "—"
            dur_item = QTableWidgetItem(dur_str)
            dur_item.setTextAlignment(Qt.AlignCenter)

            disc_str = f"{session.hosts_discovered} host(s), {session.ports_found} port(s)"
            disc_item = QTableWidgetItem(disc_str)

            status_item = QTableWidgetItem(session.status.capitalize())
            status_item.setTextAlignment(Qt.AlignCenter)

            self.table.setItem(row, 0, id_item)
            self.table.setItem(row, 1, target_item)
            self.table.setItem(row, 2, profile_item)
            self.table.setItem(row, 3, start_item)
            self.table.setItem(row, 4, dur_item)
            self.table.setItem(row, 5, disc_item)
            self.table.setItem(row, 6, status_item)

    def _on_item_double_clicked(self, item: QTableWidgetItem) -> None:
        """Opens modal inspection dialog for the double-clicked historical scan."""
        row = item.row()
        id_item = self.table.item(row, 0)
        if not id_item:
            return

        session_id = id_item.data(Qt.UserRole)
        if not session_id:
            return

        details = self.db_mgr.get_session_details(session_id)
        if details:
            dlg = ScanDetailDialog(details, db_mgr=self.db_mgr, parent=self)
            dlg.exec()

    def _on_compare_clicked(self) -> None:
        """Opens the historical scan comparison dialog."""
        dlg = ScanCompareDialog(db_mgr=self.db_mgr, parent=self)
        dlg.exec()

