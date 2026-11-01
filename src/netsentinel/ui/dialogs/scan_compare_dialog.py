"""Historical scan comparison dialog for NetSentinel AI.

Provides side-by-side comparison between any two scan sessions, displaying
new findings, reopened findings, verified resolved findings, persistent findings,
and out-of-scope unexamined findings with limitation warnings.
"""

from __future__ import annotations

import html
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
)
from netsentinel.core.reporting.report_generator import ReportGenerator
from netsentinel.ui.dialogs.export_dialog import ExportDialog


class ScanCompareDialog(QDialog):
    """Interactive modal dialog for comparing two historical scan sessions."""

    def __init__(
        self,
        db_mgr: DatabaseManager,
        preselect_session_id: Optional[int] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.db_mgr = db_mgr
        self.generator = ReportGenerator(db_mgr)
        self.preselect_session_id = preselect_session_id
        self.current_comparison: Optional[ScanComparisonResult] = None
        self.sessions: List[ScanSession] = []

        self.setWindowTitle("Historical Scan Comparison — Differential Analysis")
        self.resize(880, 640)
        self.setStyleSheet("background-color: #FFFFFF; font-family: 'Segoe UI', sans-serif;")

        self._init_ui()
        self._load_sessions()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        # Title & Subtitle
        title_box = QVBoxLayout()
        title = QLabel("Historical Scan Comparison & Differential Analysis")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #0F172A;")
        sub = QLabel("Compare two scan sessions using stable identity to isolate new, reopened, resolved, and persistent risks.")
        sub.setStyleSheet("font-size: 12px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        layout.addLayout(title_box)

        # Session Selectors Bar
        select_card = QFrame()
        select_card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;")
        select_l = QHBoxLayout(select_card)
        select_l.setContentsMargins(16, 12, 16, 12)
        select_l.setSpacing(16)

        # Baseline Combobox
        b_box = QVBoxLayout()
        b_lbl = QLabel("1. Baseline Prior Scan:")
        b_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569;")
        self.combo_baseline = QComboBox()
        self.combo_baseline.setStyleSheet("padding: 4px 8px; border: 1px solid #CBD5E1; border-radius: 4px; font-size: 12px; min-width: 240px;")
        b_box.addWidget(b_lbl)
        b_box.addWidget(self.combo_baseline)
        select_l.addLayout(b_box)

        # Current Combobox
        c_box = QVBoxLayout()
        c_lbl = QLabel("2. Current Comparison Scan:")
        c_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569;")
        self.combo_current = QComboBox()
        self.combo_current.setStyleSheet("padding: 4px 8px; border: 1px solid #CBD5E1; border-radius: 4px; font-size: 12px; min-width: 240px;")
        c_box.addWidget(c_lbl)
        c_box.addWidget(self.combo_current)
        select_l.addLayout(c_box)

        # Compare Button
        self.btn_compare = QPushButton("Run Comparison")
        self.btn_compare.setStyleSheet("padding: 8px 18px; background-color: #0284C7; color: #FFFFFF; font-weight: 700; border-radius: 6px; border: none; margin-top: 14px;")
        self.btn_compare.clicked.connect(self._run_comparison)
        select_l.addWidget(self.btn_compare)

        layout.addWidget(select_card)

        # Scope Limitation Alert Banner (Hidden by default)
        self.alert_frame = QFrame()
        self.alert_frame.setStyleSheet("background-color: #FFFBEB; border: 1px solid #FCD34D; border-radius: 6px; padding: 10px 14px;")
        alert_l = QVBoxLayout(self.alert_frame)
        alert_l.setContentsMargins(0, 0, 0, 0)
        self.alert_title = QLabel("COMPARISON SCOPE LIMITATION")
        self.alert_title.setStyleSheet("font-size: 11px; font-weight: 800; color: #B45309; letter-spacing: 0.05em;")
        self.alert_msg = QLabel("")
        self.alert_msg.setStyleSheet("font-size: 12px; color: #92400E;")
        self.alert_msg.setWordWrap(True)
        alert_l.addWidget(self.alert_title)
        alert_l.addWidget(self.alert_msg)
        self.alert_frame.setVisible(False)
        layout.addWidget(self.alert_frame)

        # KPI Metrics Cards Row
        self.kpi_row = QHBoxLayout()
        self.kpi_row.setSpacing(10)
        self.card_new = self._create_kpi_card("New Risks", "+0", "#EF4444")
        self.card_reop = self._create_kpi_card("Reopened", "0", "#F59E0B")
        self.card_res = self._create_kpi_card("Verified Resolved", "-0", "#10B981")
        self.card_pers = self._create_kpi_card("Persistent", "0", "#3B82F6")
        self.card_out = self._create_kpi_card("Not Reassessed", "0", "#94A3B8")

        self.kpi_row.addWidget(self.card_new["frame"])
        self.kpi_row.addWidget(self.card_reop["frame"])
        self.kpi_row.addWidget(self.card_res["frame"])
        self.kpi_row.addWidget(self.card_pers["frame"])
        self.kpi_row.addWidget(self.card_out["frame"])
        layout.addLayout(self.kpi_row)

        # Findings Detail Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #E2E8F0; background: #FFFFFF; border-radius: 6px; }
            QTabBar::tab { background: #F1F5F9; color: #475569; padding: 6px 14px; font-weight: 600; font-size: 12px; }
            QTabBar::tab:selected { background: #FFFFFF; color: #0F172A; border-bottom: 2px solid #0284C7; }
        """)

        self.table_new = self._create_findings_table()
        self.table_reop = self._create_findings_table()
        self.table_res = self._create_findings_table()
        self.table_pers = self._create_findings_table()
        self.table_out = self._create_findings_table()

        self.tabs.addTab(self.table_new, "New Findings (0)")
        self.tabs.addTab(self.table_reop, "Reopened (0)")
        self.tabs.addTab(self.table_res, "Verified Resolved (0)")
        self.tabs.addTab(self.table_pers, "Persistent (0)")
        self.tabs.addTab(self.table_out, "Not Reassessed (0)")

        layout.addWidget(self.tabs)

        # Bottom Action Buttons Row
        bot_row = QHBoxLayout()
        self.btn_export_diff = QPushButton("Export Comparison Report...")
        self.btn_export_diff.setStyleSheet("padding: 8px 16px; background-color: #0F172A; color: #FFFFFF; font-weight: 600; border-radius: 6px; border: none;")
        self.btn_export_diff.clicked.connect(self._export_comparison_report)
        self.btn_export_diff.setEnabled(False)
        bot_row.addWidget(self.btn_export_diff)

        bot_row.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setStyleSheet("padding: 8px 18px; background-color: #F1F5F9; color: #475569; font-weight: 600; border: 1px solid #CBD5E1; border-radius: 6px;")
        btn_close.clicked.connect(self.accept)
        bot_row.addWidget(btn_close)

        layout.addLayout(bot_row)

    def _create_kpi_card(self, title: str, initial_val: str, border_color: str) -> dict:
        frame = QFrame()
        frame.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid #E2E8F0; border-left: 4px solid {border_color}; border-radius: 6px; padding: 10px;")
        fl = QVBoxLayout(frame)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase;")
        lbl_v = QLabel(initial_val)
        lbl_v.setStyleSheet("font-size: 20px; font-weight: 800; color: #0F172A;")

        fl.addWidget(lbl_t)
        fl.addWidget(lbl_v)
        return {"frame": frame, "value_label": lbl_v}

    def _create_findings_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Severity", "Rule ID & Title", "Risk Score", "Asset & Port", "Status"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def _load_sessions(self) -> None:
        self.sessions = self.db_mgr.list_scan_sessions(limit=50)
        self.combo_baseline.clear()
        self.combo_current.clear()

        for s in self.sessions:
            label = f"#{s.id} — {s.target_input} ({s.profile}, {s.start_time[:16].replace('T', ' ')})"
            self.combo_baseline.addItem(label, s.id)
            self.combo_current.addItem(label, s.id)

        # Preselect if requested
        if len(self.sessions) >= 2:
            self.combo_baseline.setCurrentIndex(1)  # Prior session
            self.combo_current.setCurrentIndex(0)   # Latest session
            if self.preselect_session_id:
                for idx, s in enumerate(self.sessions):
                    if s.id == self.preselect_session_id:
                        self.combo_current.setCurrentIndex(idx)
                        break

    def _run_comparison(self) -> None:
        base_id = self.combo_baseline.currentData()
        curr_id = self.combo_current.currentData()

        if base_id == curr_id:
            QMessageBox.warning(self, "Invalid Comparison", "Baseline scan and current scan must be two different sessions.")
            return

        try:
            self.current_comparison = self.generator.compare_scans(base_id, curr_id)
            self._render_comparison_results(self.current_comparison)
            self.btn_export_diff.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Comparison Error", f"Failed to compare scans:\n{e}")

    def _render_comparison_results(self, comp: ScanComparisonResult) -> None:
        # Update KPI cards
        self.card_new["value_label"].setText(f"+{len(comp.new_findings)}")
        self.card_reop["value_label"].setText(f"{len(comp.reopened_findings)}")
        self.card_res["value_label"].setText(f"-{len(comp.resolved_findings)}")
        self.card_pers["value_label"].setText(f"{len(comp.persistent_findings)}")
        self.card_out["value_label"].setText(f"{len(comp.not_reassessed_findings)}")

        # Scope limitations alert
        if comp.has_scope_limitations:
            self.alert_frame.setVisible(True)
            self.alert_msg.setText(comp.limitation_notice)
        else:
            self.alert_frame.setVisible(False)

        # Populate tables
        self._populate_table(self.table_new, comp.new_findings)
        self._populate_table(self.table_reop, comp.reopened_findings)
        self._populate_table(self.table_res, comp.resolved_findings)
        self._populate_table(self.table_pers, comp.persistent_findings)
        self._populate_table(self.table_out, comp.not_reassessed_findings)

        self.tabs.setTabText(0, f"New Findings ({len(comp.new_findings)})")
        self.tabs.setTabText(1, f"Reopened ({len(comp.reopened_findings)})")
        self.tabs.setTabText(2, f"Verified Resolved ({len(comp.resolved_findings)})")
        self.tabs.setTabText(3, f"Persistent ({len(comp.persistent_findings)})")
        self.tabs.setTabText(4, f"Not Reassessed ({len(comp.not_reassessed_findings)})")

    def _populate_table(self, table: QTableWidget, findings: List[SecurityFinding]) -> None:
        table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev_item = QTableWidgetItem(f.severity)
            sev_item.setTextAlignment(Qt.AlignCenter)

            title_str = f"{f.title}\n[{f.rule_id}]"
            title_item = QTableWidgetItem(title_str)

            score_item = QTableWidgetItem(f"{f.risk_score:.1f} ({f.risk_tier})")
            score_item.setTextAlignment(Qt.AlignCenter)

            port_str = f"{f.port_number}/{f.protocol}" if f.port_number else "Host"
            asset_str = f"{f.ip_address} ({port_str})" if f.ip_address else port_str
            asset_item = QTableWidgetItem(asset_str)

            status_item = QTableWidgetItem(f.status)
            status_item.setTextAlignment(Qt.AlignCenter)

            table.setItem(row, 0, sev_item)
            table.setItem(row, 1, title_item)
            table.setItem(row, 2, score_item)
            table.setItem(row, 3, asset_item)
            table.setItem(row, 4, status_item)

    def _export_comparison_report(self) -> None:
        if not self.current_comparison:
            return

        export_dlg = ExportDialog(
            db_mgr=self.db_mgr,
            session_id=self.current_comparison.current_session_id,
            target_name=f"Comparison_{self.current_comparison.baseline_session_id}_vs_{self.current_comparison.current_session_id}",
            parent=self,
        )
        export_dlg.exec()
