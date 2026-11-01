"""Security findings view and interactive audit dialog for NetSentinel AI.

Displays deterministic risk assessments, service observations, transparent scoring
breakdowns, defensive remediation guidance, and lifecycle status management.
"""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import (
    ALL_FINDING_STATUSES,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
    STATUS_NEW,
    STATUS_OPEN,
    STATUS_RESOLVED,
    SecurityFinding,
)
from netsentinel.ui.dialogs.export_dialog import ExportDialog



class FindingDetailDialog(QDialog):
    """Detailed inspection modal for a security finding with lifecycle actions."""

    def __init__(
        self,
        finding: SecurityFinding,
        db_mgr: DatabaseManager,
        on_status_changed_cb=None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.finding = finding
        self.db_mgr = db_mgr
        self.on_status_changed_cb = on_status_changed_cb
        self.setWindowTitle(f"Finding Details — {finding.title}")
        self.setMinimumSize(720, 680)
        self.resize(780, 720)
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 24, 24, 24)
        main_layout.setSpacing(16)

        # 1. Header with Rule ID & Title
        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        rule_label = QLabel(f"Rule ID: {self.finding.rule_id} (v{self.finding.rule_version})")
        rule_label.setStyleSheet("font-size: 11px; font-weight: 700; color: #2563EB; text-transform: uppercase;")
        title_box.addWidget(rule_label)

        title_lbl = QLabel(self.finding.title)
        title_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #0F172A;")
        title_lbl.setWordWrap(True)
        title_box.addWidget(title_lbl)

        main_layout.addLayout(title_box)

        # 2. Status & Scoring Badges Row
        self.badges_layout = QHBoxLayout()
        self.badges_layout.setSpacing(8)
        self._render_badges()
        main_layout.addLayout(self.badges_layout)

        # Scrollable Content Area for Evidence and Remediation
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(14)

        # Target & Discovery Metadata Card
        target_card = QFrame()
        target_card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px;")
        t_layout = QVBoxLayout(target_card)
        t_layout.setContentsMargins(14, 12, 14, 12)
        t_layout.setSpacing(6)

        port_str = (
            f"{self.finding.port_number}/{self.finding.protocol}"
            if self.finding.port_number
            else "Host-Level Observation"
        )
        host_str = self.finding.ip_address or f"Asset #{self.finding.asset_id or 'Unknown'}"
        if self.finding.hostname:
            host_str += f" ({self.finding.hostname})"

        t_lbl = QLabel(f"<b>Target:</b> {host_str} &nbsp;|&nbsp; <b>Service Port:</b> {port_str}")
        t_lbl.setStyleSheet("font-size: 12px; color: #334155;")
        s_lbl = QLabel(f"<b>Session ID:</b> #{self.finding.session_id or 'N/A'} &nbsp;|&nbsp; <b>Observed:</b> {self.finding.timestamp.replace('T', ' ')}")
        s_lbl.setStyleSheet("font-size: 12px; color: #64748B;")

        t_layout.addWidget(t_lbl)
        t_layout.addWidget(s_lbl)
        content_layout.addWidget(target_card)

        # Risk Score Breakdown Card
        risk_card = QFrame()
        risk_card.setStyleSheet("background-color: #F8FAFC; border-left: 4px solid #6366F1; border-radius: 6px;")
        r_layout = QVBoxLayout(risk_card)
        r_layout.setContentsMargins(14, 12, 14, 12)
        r_layout.setSpacing(6)

        r_title = QLabel("Transparent Risk Scoring Formula & Breakdown")
        r_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #4F46E5; text-transform: uppercase;")
        r_layout.addWidget(r_title)

        r_score = QLabel(f"Risk Score: <b>{self.finding.risk_score:.1f} / 100.0</b> &nbsp;(Risk Tier: <b>{self.finding.risk_tier}</b>)")
        r_score.setStyleSheet("font-size: 13px; color: #1E293B;")
        r_layout.addWidget(r_score)

        r_expl = QLabel(self.finding.scoring_explanation or "Formula: BaseSeverityWeight × Confidence × ExposureMultiplier")
        r_expl.setStyleSheet("font-size: 11px; color: #475569; font-family: Consolas, monospace;")
        r_expl.setWordWrap(True)
        r_layout.addWidget(r_expl)

        content_layout.addWidget(risk_card)

        # Description Card
        desc_card = QFrame()
        desc_card.setStyleSheet("background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px;")
        d_layout = QVBoxLayout(desc_card)
        d_layout.setContentsMargins(14, 12, 14, 12)
        d_layout.setSpacing(6)
        d_title = QLabel("Observation Description")
        d_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase;")
        d_text = QLabel(self.finding.description)
        d_text.setStyleSheet("font-size: 13px; color: #1E293B;")
        d_text.setWordWrap(True)
        d_layout.addWidget(d_title)
        d_layout.addWidget(d_text)
        content_layout.addWidget(desc_card)

        # Concrete Raw Evidence Box
        ev_card = QFrame()
        ev_card.setStyleSheet("background-color: #0F172A; border-radius: 6px;")
        e_layout = QVBoxLayout(ev_card)
        e_layout.setContentsMargins(14, 12, 14, 12)
        e_layout.setSpacing(6)
        e_title = QLabel("Concrete Scanner Evidence (No Speculation)")
        e_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8; text-transform: uppercase;")
        e_text = QLabel(self.finding.evidence or "No raw banner evidence recorded.")
        e_text.setStyleSheet("font-size: 12px; color: #38BDF8; font-family: Consolas, monospace;")
        e_text.setWordWrap(True)
        e_layout.addWidget(e_title)
        e_layout.addWidget(e_text)
        content_layout.addWidget(ev_card)

        # Defensive Remediation Guidance Card
        rem_card = QFrame()
        rem_card.setStyleSheet("background-color: #F0FDF4; border-left: 4px solid #16A34A; border-radius: 6px;")
        rem_layout = QVBoxLayout(rem_card)
        rem_layout.setContentsMargins(14, 12, 14, 12)
        rem_layout.setSpacing(6)
        rem_title = QLabel("Defensive Remediation Guidance (Advisory Only)")
        rem_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #15803D; text-transform: uppercase;")
        rem_text = QLabel(self.finding.recommendation)
        rem_text.setStyleSheet("font-size: 12px; color: #166534;")
        rem_text.setWordWrap(True)
        rem_layout.addWidget(rem_title)
        rem_layout.addWidget(rem_text)
        content_layout.addWidget(rem_card)

        # Operator Notes / Audit Trail Card
        if self.finding.user_notes:
            notes_card = QFrame()
            notes_card.setStyleSheet("background-color: #FFFBEB; border: 1px solid #FDE68A; border-radius: 6px;")
            n_layout = QVBoxLayout(notes_card)
            n_layout.setContentsMargins(14, 12, 14, 12)
            n_layout.setSpacing(6)
            n_title = QLabel("Operator Notes & Lifecycle Audit Trail")
            n_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #B45309; text-transform: uppercase;")
            n_text = QLabel(self.finding.user_notes)
            n_text.setStyleSheet("font-size: 11px; color: #78350F; font-family: Consolas, monospace;")
            n_text.setWordWrap(True)
            n_layout.addWidget(n_title)
            n_layout.addWidget(n_text)
            content_layout.addWidget(notes_card)

        content_layout.addStretch()
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

        # Bottom Lifecycle Action Buttons Row
        actions_row = QHBoxLayout()
        actions_row.setSpacing(10)

        # Lifecycle Action Buttons
        self.btn_ack = QPushButton("Acknowledge Risk")
        self.btn_ack.setStyleSheet("background-color: #F1F5F9; color: #334155; border: 1px solid #CBD5E1; border-radius: 4px; padding: 6px 12px; font-weight: 600;")
        self.btn_ack.clicked.connect(lambda: self._handle_status_transition(STATUS_ACKNOWLEDGED))
        actions_row.addWidget(self.btn_ack)

        self.btn_resolve = QPushButton("Mark Resolved")
        self.btn_resolve.setStyleSheet("background-color: #ECFDF5; color: #047857; border: 1px solid #A7F3D0; border-radius: 4px; padding: 6px 12px; font-weight: 600;")
        self.btn_resolve.clicked.connect(lambda: self._handle_status_transition(STATUS_RESOLVED))
        actions_row.addWidget(self.btn_resolve)

        self.btn_fp = QPushButton("Mark False Positive")
        self.btn_fp.setStyleSheet("background-color: #FAF5FF; color: #7E22CE; border: 1px solid #E9D5FF; border-radius: 4px; padding: 6px 12px; font-weight: 600;")
        self.btn_fp.clicked.connect(lambda: self._handle_status_transition(STATUS_FALSE_POSITIVE))
        actions_row.addWidget(self.btn_fp)

        if self.finding.status in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE, STATUS_ACKNOWLEDGED):
            self.btn_reopen = QPushButton("Reopen Finding")
            self.btn_reopen.setStyleSheet("background-color: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; border-radius: 4px; padding: 6px 12px; font-weight: 600;")
            self.btn_reopen.clicked.connect(lambda: self._handle_status_transition(STATUS_OPEN))
            actions_row.addWidget(self.btn_reopen)

        actions_row.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setProperty("class", "secondaryButton")
        btn_close.clicked.connect(self.accept)
        actions_row.addWidget(btn_close)

        main_layout.addLayout(actions_row)

    def _render_badges(self) -> None:
        """Draws rule severity, risk tier, and status badges."""
        while self.badges_layout.count():
            item = self.badges_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Rule Severity Badge
        sev_badge = QLabel(f"RULE SEVERITY: {self.finding.severity.upper()}")
        sev = self.finding.severity.lower()
        if sev == "critical":
            sev_badge.setStyleSheet("background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        elif sev == "high":
            sev_badge.setStyleSheet("background-color: #FFF7ED; color: #EA580C; border: 1px solid #FFEDD5; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        elif sev == "medium":
            sev_badge.setStyleSheet("background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        else:
            sev_badge.setStyleSheet("background-color: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        self.badges_layout.addWidget(sev_badge)

        # Risk Tier Pill (Displaying difference if applicable)
        tier_badge = QLabel(f"RISK TIER: {self.finding.risk_tier.upper()} ({self.finding.risk_score:.1f})")
        tier_badge.setStyleSheet("background-color: #EEF2FF; color: #4338CA; border: 1px solid #C7D2FE; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        self.badges_layout.addWidget(tier_badge)

        # Status Badge
        st = self.finding.status
        st_badge = QLabel(f"STATUS: {st.upper()}")
        if st == STATUS_NEW:
            st_badge.setStyleSheet("background-color: #E0F2FE; color: #0369A1; border: 1px solid #BAE6FD; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        elif st == STATUS_OPEN:
            st_badge.setStyleSheet("background-color: #FEF3C7; color: #B45309; border: 1px solid #FDE68A; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        elif st == STATUS_ACKNOWLEDGED:
            st_badge.setStyleSheet("background-color: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        elif st == STATUS_RESOLVED:
            st_badge.setStyleSheet("background-color: #DCFCE7; color: #15803D; border: 1px solid #BBF7D0; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        else:
            st_badge.setStyleSheet("background-color: #F3E8FF; color: #7E22CE; border: 1px solid #E9D5FF; border-radius: 4px; padding: 3px 8px; font-weight: 700; font-size: 11px;")
        self.badges_layout.addWidget(st_badge)

        self.badges_layout.addStretch()

    def _handle_status_transition(self, new_status: str) -> None:
        """Prompts for operator rationale and updates status in database."""
        if not self.finding.id:
            QMessageBox.warning(self, "Error", "Cannot update status on unpersisted finding.")
            return

        text, ok = QInputDialog.getText(
            self,
            "Operator Audit Notes",
            f"Enter optional operator notes / justification for transitioning to '{new_status}':",
        )
        if not ok:
            return

        notes = text.strip() if text else "Operator updated status via Findings Detail Dialog"
        try:
            success = self.db_mgr.update_finding_status(
                finding_id=self.finding.id,
                new_status=new_status,
                notes=notes,
                user_confirmed=True,
            )
            if success:
                self.finding.status = new_status
                self._render_badges()
                if self.on_status_changed_cb:
                    self.on_status_changed_cb()
                QMessageBox.information(
                    self,
                    "Status Updated",
                    f"Finding status successfully transitioned to '{new_status}'. Audit entry recorded.",
                )
            else:
                QMessageBox.warning(self, "Update Failed", "Could not update finding status.")
        except Exception as e:
            QMessageBox.critical(self, "Transition Error", str(e))


class FindingsView(QWidget):
    """Security findings view with multi-criteria filtering, sorting, and inspection."""

    def __init__(self, db_mgr: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db_mgr = db_mgr
        self.all_findings: List[SecurityFinding] = []
        self._init_ui()
        self.refresh()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # Header Title
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Security Audit Findings")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("Evidence-based risk observations, transparent scoring, and defensive remediation guidance")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)

        header_row.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setProperty("class", "secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export Findings...")
        self.export_btn.setStyleSheet("padding: 7px 16px; background-color: #0284C7; color: #FFFFFF; font-weight: 600; border-radius: 6px; border: none; font-size: 13px;")
        self.export_btn.clicked.connect(self._on_export_clicked)
        header_row.addWidget(self.export_btn)

        layout.addLayout(header_row)

        # KPI Summary Cards Bar
        self.kpi_layout = QHBoxLayout()
        self.kpi_layout.setSpacing(12)
        self._init_kpi_bar()
        layout.addLayout(self.kpi_layout)

        # Filter & Search Controls Bar
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(10)

        # Search field
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search host IP, hostname, title, or rule ID...")
        self.search_input.setStyleSheet("padding: 6px 12px; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 13px;")
        self.search_input.textChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.search_input, stretch=2)

        # Severity Filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.severity_filter, stretch=1)

        # Status Filter
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All Statuses", STATUS_NEW, STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED, STATUS_FALSE_POSITIVE])
        self.status_filter.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.status_filter, stretch=1)

        # Sort Dropdown
        self.sort_combo = QComboBox()
        self.sort_combo.addItems([
            "Sort: Severity Priority",
            "Sort: Risk Score (High to Low)",
            "Sort: Date (Newest First)",
            "Sort: Host IP",
        ])
        self.sort_combo.currentTextChanged.connect(self._apply_filters)
        filter_bar.addWidget(self.sort_combo, stretch=1)

        layout.addLayout(filter_bar)

        # Stacked Container for Cards vs. Empty State
        self.stack = QStackedWidget()

        # 1. Empty State Frame
        self.empty_frame = QFrame()
        self.empty_frame.setProperty("class", "contentCard")
        empty_layout = QVBoxLayout(self.empty_frame)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.setSpacing(12)
        empty_layout.setContentsMargins(40, 60, 40, 60)

        empty_icon = QLabel("🛡️")
        empty_icon.setStyleSheet("font-size: 42px;")
        empty_icon.setAlignment(Qt.AlignCenter)

        self.empty_title = QLabel("No Security Findings Recorded")
        self.empty_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #1E293B;")
        self.empty_title.setAlignment(Qt.AlignCenter)

        self.empty_desc = QLabel(
            "No security observations or vulnerability warnings have been logged in the database. "
            "NetSentinel AI only surfaces verified findings based on real network discovery data."
        )
        self.empty_desc.setStyleSheet("font-size: 13px; color: #64748B; max-width: 480px;")
        self.empty_desc.setWordWrap(True)
        self.empty_desc.setAlignment(Qt.AlignCenter)

        empty_layout.addWidget(empty_icon)
        empty_layout.addWidget(self.empty_title)
        empty_layout.addWidget(self.empty_desc)
        self.stack.addWidget(self.empty_frame)

        # 2. Scroll Area for Finding Cards
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.NoFrame)
        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(12)
        self.scroll_area.setWidget(self.cards_container)

        self.stack.addWidget(self.scroll_area)
        layout.addWidget(self.stack)

    def _init_kpi_bar(self) -> None:
        """Initializes top metric pill cards."""
        self.kpi_total_lbl = QLabel("0")
        self.kpi_active_lbl = QLabel("0")
        self.kpi_ack_lbl = QLabel("0")
        self.kpi_resolved_lbl = QLabel("0")

        self.kpi_layout.addWidget(self._create_metric_pill("Total Findings", self.kpi_total_lbl, "#475569"))
        self.kpi_layout.addWidget(self._create_metric_pill("Active Risks (New/Open)", self.kpi_active_lbl, "#DC2626"))
        self.kpi_layout.addWidget(self._create_metric_pill("Acknowledged", self.kpi_ack_lbl, "#64748B"))
        self.kpi_layout.addWidget(self._create_metric_pill("Resolved", self.kpi_resolved_lbl, "#16A34A"))

    def _create_metric_pill(self, label: str, value_lbl: QLabel, color: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet("background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 6px 12px;")
        h = QHBoxLayout(card)
        h.setContentsMargins(8, 6, 8, 6)
        lbl = QLabel(label)
        lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #64748B;")
        value_lbl.setStyleSheet(f"font-size: 16px; font-weight: 700; color: {color};")
        h.addWidget(lbl)
        h.addStretch()
        h.addWidget(value_lbl)
        return card

    def refresh(self) -> None:
        """Reloads security findings from SQLite and refreshes view."""
        self.all_findings = self.db_mgr.list_security_findings(limit=500)
        self._update_kpi_metrics()
        self._apply_filters()

    def _update_kpi_metrics(self) -> None:
        """Refreshes KPI metric numbers."""
        metrics = self.db_mgr.get_dashboard_metrics()
        self.kpi_total_lbl.setText(str(metrics.get("total_findings", 0)))
        self.kpi_active_lbl.setText(str(metrics.get("active_findings", 0)))
        self.kpi_ack_lbl.setText(str(metrics.get("acknowledged_findings", 0)))
        self.kpi_resolved_lbl.setText(str(metrics.get("resolved_findings", 0)))

    def _apply_filters(self) -> None:
        """Filters and sorts loaded findings in-memory for instant UI reactivity."""
        if not hasattr(self, "all_findings"):
            return

        sev_choice = self.severity_filter.currentText()
        status_choice = self.status_filter.currentText()
        search_query = self.search_input.text().strip().lower()
        sort_choice = self.sort_combo.currentText()

        filtered: List[SecurityFinding] = []
        for f in self.all_findings:
            if sev_choice != "All Severities" and f.severity.lower() != sev_choice.lower():
                continue
            if status_choice != "All Statuses" and f.status != status_choice:
                continue
            if search_query:
                combined_text = f"{f.ip_address} {f.hostname} {f.title} {f.rule_id} {f.description}".lower()
                if search_query not in combined_text:
                    continue
            filtered.append(f)

        # Sorting
        if "Severity Priority" in sort_choice:
            order_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
            filtered.sort(key=lambda x: (order_map.get(x.severity.lower(), 6), -x.risk_score, -(x.id or 0)))
        elif "Risk Score" in sort_choice:
            filtered.sort(key=lambda x: (-x.risk_score, -(x.id or 0)))
        elif "Date" in sort_choice:
            filtered.sort(key=lambda x: x.timestamp, reverse=True)
        elif "Host IP" in sort_choice:
            filtered.sort(key=lambda x: (x.ip_address or "", x.port_number or 0))

        self._render_findings(filtered)

    def _render_findings(self, findings: List[SecurityFinding]) -> None:
        while self.cards_layout.count():
            item = self.cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not findings:
            if self.search_input.text().strip() or self.severity_filter.currentText() != "All Severities":
                self.empty_title.setText("No Matching Findings")
                self.empty_desc.setText("No security findings matched your current search filters.")
            else:
                self.empty_title.setText("No Security Findings Recorded")
                self.empty_desc.setText(
                    "No security findings or vulnerability warnings have been logged in the database. "
                    "NetSentinel AI only surfaces verified findings based on real network discovery data."
                )
            self.stack.setCurrentIndex(0)
            return

        self.stack.setCurrentIndex(1)
        for f in findings:
            card = self._create_finding_card(f)
            self.cards_layout.addWidget(card)

        self.cards_layout.addStretch()

    def _create_finding_card(self, finding: SecurityFinding) -> QFrame:
        card = QFrame()
        card.setProperty("class", "contentCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        # Top Row: Rule Severity Badge + Risk Tier Pill + Status Badge + Title + Timestamp
        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        # Rule Severity Badge
        sev_badge = QLabel(finding.severity.upper())
        sev = finding.severity.lower()
        if sev == "critical":
            sev_badge.setStyleSheet("background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        elif sev == "high":
            sev_badge.setStyleSheet("background-color: #FFF7ED; color: #EA580C; border: 1px solid #FFEDD5; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        elif sev == "medium":
            sev_badge.setStyleSheet("background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        else:
            sev_badge.setStyleSheet("background-color: #EFF6FF; color: #2563EB; border: 1px solid #BFDBFE; border-radius: 4px; padding: 2px 8px; font-weight: 700; font-size: 11px;")
        top_row.addWidget(sev_badge)

        # If rule severity != risk tier, explicitly display risk tier pill!
        if finding.risk_tier.lower() != sev:
            diff_pill = QLabel(f"TIER: {finding.risk_tier.upper()}")
            diff_pill.setStyleSheet("background-color: #EEF2FF; color: #4338CA; border: 1px solid #C7D2FE; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
            top_row.addWidget(diff_pill)

        # Status badge
        st = finding.status
        st_badge = QLabel(st.upper())
        if st == STATUS_NEW:
            st_badge.setStyleSheet("background-color: #E0F2FE; color: #0369A1; border: 1px solid #BAE6FD; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
        elif st == STATUS_OPEN:
            st_badge.setStyleSheet("background-color: #FEF3C7; color: #B45309; border: 1px solid #FDE68A; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
        elif st == STATUS_ACKNOWLEDGED:
            st_badge.setStyleSheet("background-color: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
        elif st == STATUS_RESOLVED:
            st_badge.setStyleSheet("background-color: #DCFCE7; color: #15803D; border: 1px solid #BBF7D0; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
        else:
            st_badge.setStyleSheet("background-color: #F3E8FF; color: #7E22CE; border: 1px solid #E9D5FF; border-radius: 4px; padding: 2px 6px; font-weight: 700; font-size: 10px;")
        top_row.addWidget(st_badge)

        # Title
        title_lbl = QLabel(finding.title)
        title_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        top_row.addWidget(title_lbl)

        top_row.addStretch()

        # Timestamp
        time_lbl = QLabel(finding.timestamp.replace("T", " "))
        time_lbl.setStyleSheet("font-size: 11px; color: #94A3B8;")
        top_row.addWidget(time_lbl)

        layout.addLayout(top_row)

        # Subtitle Row: Host/Port + Risk Score + Rule ID
        sub_row = QHBoxLayout()
        sub_row.setSpacing(8)

        port_text = f":{finding.port_number}/{finding.protocol}" if finding.port_number else " (Host-Level)"
        host_repr = f"🖥️ {finding.ip_address or 'Target'}{port_text}"
        host_badge = QLabel(host_repr)
        host_badge.setStyleSheet("font-size: 12px; font-weight: 600; color: #334155;")
        sub_row.addWidget(host_badge)

        score_badge = QLabel(f"Score: <b>{finding.risk_score:.1f}</b>/100")
        score_badge.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 1px 6px; font-size: 11px; color: #475569;")
        sub_row.addWidget(score_badge)

        rule_badge = QLabel(finding.rule_id)
        rule_badge.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px; padding: 1px 6px; font-size: 11px; color: #64748B; font-family: Consolas, monospace;")
        sub_row.addWidget(rule_badge)

        sub_row.addStretch()
        layout.addLayout(sub_row)

        # Evidence Snippet (Concise)
        if finding.evidence:
            ev_frame = QFrame()
            ev_frame.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 4px;")
            ev_layout = QVBoxLayout(ev_frame)
            ev_layout.setContentsMargins(10, 6, 10, 6)
            ev_lbl = QLabel(finding.evidence)
            ev_lbl.setStyleSheet("font-size: 11px; color: #334155; font-family: Consolas, monospace;")
            ev_lbl.setWordWrap(True)
            ev_layout.addWidget(ev_lbl)
            layout.addWidget(ev_frame)

        # Description and Inspection Button Row
        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(10)

        desc_lbl = QLabel(finding.description)
        desc_lbl.setStyleSheet("font-size: 12px; color: #475569;")
        desc_lbl.setWordWrap(True)
        bottom_row.addWidget(desc_lbl, stretch=3)

        btn_inspect = QPushButton("Inspect Finding & Remediate")
        btn_inspect.setStyleSheet("background-color: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; border-radius: 4px; padding: 6px 12px; font-weight: 600; font-size: 12px;")
        btn_inspect.clicked.connect(lambda _, f=finding: self._open_detail_dialog(f))
        bottom_row.addWidget(btn_inspect, stretch=0)

        layout.addLayout(bottom_row)
        return card

    def _open_detail_dialog(self, finding: SecurityFinding) -> None:
        """Opens modal dialog for in-depth finding inspection and status transitions."""
        dialog = FindingDetailDialog(
            finding=finding,
            db_mgr=self.db_mgr,
            on_status_changed_cb=self.refresh,
            parent=self,
        )
        dialog.exec()

    def _on_export_clicked(self) -> None:
        """Opens multi-format export dialog."""
        dlg = ExportDialog(db_mgr=self.db_mgr, target_name="All_Findings", parent=self)
        dlg.exec()

