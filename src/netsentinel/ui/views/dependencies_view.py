"""Dependency diagnostics view for NetSentinel AI.

Evaluates and clearly categorizes:
1. Required Core Dependencies (Embedded Python, SQLite WAL engine, PySide6 GUI)
2. Optional Discovery Tools (Bundled Nmap vs System Nmap)
3. Advanced Scanning Features (Npcap packet capture driver & Administrator privileges)
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.dependencies import DependencyDetector, DependencyItem, DiagnosticReport


class DependenciesView(QWidget):
    """System dependency and scan capability diagnostic panel."""

    diagnostics_updated = Signal(object)  # emits DiagnosticReport

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._init_ui()
        self.run_diagnostics()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        # Header Title
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("System & Dependency Diagnostics")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("Non-invasive verification of runtimes, network drivers, and scan capabilities")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)

        header_row.addStretch()

        self.recheck_btn = QPushButton("Re-run Diagnostics")
        self.recheck_btn.setProperty("class", "primaryButton")
        self.recheck_btn.clicked.connect(self.run_diagnostics)
        header_row.addWidget(self.recheck_btn)

        layout.addLayout(header_row)

        # Capabilities Overview Card
        self.summary_card = QFrame()
        self.summary_card.setProperty("class", "contentCard")
        summary_layout = QVBoxLayout(self.summary_card)
        summary_layout.setContentsMargins(18, 16, 18, 16)
        summary_layout.setSpacing(10)

        summary_title = QLabel("Scan Capability Matrix")
        summary_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        summary_layout.addWidget(summary_title)

        caps_row = QHBoxLayout()
        caps_row.setSpacing(14)

        self.cap_tcp = self._create_capability_pill("Safe TCP Connect (-sT)", True)
        self.cap_service = self._create_capability_pill("Service Detection (-sV)", False)
        self.cap_raw = self._create_capability_pill("SYN Stealth Scan (-sS)", False)

        caps_row.addWidget(self.cap_tcp["widget"])
        caps_row.addWidget(self.cap_service["widget"])
        caps_row.addWidget(self.cap_raw["widget"])
        caps_row.addStretch()
        summary_layout.addLayout(caps_row)

        layout.addWidget(self.summary_card)

        # Scrollable Area for Categorized Dependency Sections
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        self.content_container = QWidget()
        self.content_layout = QVBoxLayout(self.content_container)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(18)
        scroll.setWidget(self.content_container)

        layout.addWidget(scroll)

    def _create_capability_pill(self, label_text: str, active: bool) -> dict:
        lbl = QLabel(label_text)
        self._style_cap_pill(lbl, active)
        return {"widget": lbl}

    def _style_cap_pill(self, lbl: QLabel, active: bool) -> None:
        if active:
            lbl.setStyleSheet(
                "background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; "
                "border-radius: 4px; padding: 5px 12px; font-weight: 600; font-size: 12px;"
            )
        else:
            lbl.setStyleSheet(
                "background-color: #F8FAFC; color: #94A3B8; border: 1px solid #E2E8F0; "
                "border-radius: 4px; padding: 5px 12px; font-weight: 500; font-size: 12px;"
            )

    def run_diagnostics(self) -> None:
        """Executes dependency detection and updates the UI."""
        report = DependencyDetector.run_diagnostics()
        self.current_report = report

        # Update capability pills
        self._style_cap_pill(self.cap_tcp["widget"], report.can_tcp_connect_scan)
        self._style_cap_pill(self.cap_service["widget"], report.can_service_detect)
        self._style_cap_pill(self.cap_raw["widget"], report.can_raw_syn_scan)

        # Clear existing section cards
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        # Categorize items
        required_items = [i for i in report.items if i.category == "required"]
        optional_items = [i for i in report.items if i.category == "optional"]
        advanced_items = [i for i in report.items if i.category == "advanced"]

        self._add_section_card(
            "1. Required Dependencies (Self-Contained Runtimes)",
            "These components are bundled with NetSentinel AI. No separate Python or database installation is needed.",
            required_items,
        )
        self._add_section_card(
            "2. Network Discovery Utilities (Optional / Bundled)",
            "Nmap binary discovery. If bundled in bin/nmap/nmap.exe, portable execution is used automatically.",
            optional_items,
        )
        self._add_section_card(
            "3. Advanced Scanning Features (Optional / Elevated)",
            "Low-level packet drivers and elevation are only required for SYN stealth scans. Standard TCP connect scanning operates without them.",
            advanced_items,
        )

        self.content_layout.addStretch()
        self.diagnostics_updated.emit(report)

    def _add_section_card(self, title: str, subtitle: str, items: list[DependencyItem]) -> None:
        card = QFrame()
        card.setProperty("class", "contentCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        sec_title = QLabel(title)
        sec_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        sec_desc = QLabel(subtitle)
        sec_desc.setStyleSheet("font-size: 12px; color: #64748B;")
        layout.addWidget(sec_title)
        layout.addWidget(sec_desc)

        # List items
        for item in items:
            row = QFrame()
            row.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 6px;")
            r_layout = QVBoxLayout(row)
            r_layout.setContentsMargins(14, 12, 14, 12)
            r_layout.setSpacing(6)

            top_row = QHBoxLayout()
            name_lbl = QLabel(item.name)
            name_lbl.setStyleSheet("font-size: 13px; font-weight: 600; color: #1E293B;")
            top_row.addWidget(name_lbl)

            top_row.addStretch()

            badge = QLabel(item.version)
            if item.status_level == "ok":
                badge.setStyleSheet("background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;")
            elif item.status_level == "warning":
                badge.setStyleSheet("background-color: #FFFBEB; color: #D97706; border: 1px solid #FDE68A; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;")
            elif item.status_level == "error":
                badge.setStyleSheet("background-color: #FEF2F2; color: #DC2626; border: 1px solid #FECACA; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;")
            else:
                badge.setStyleSheet("background-color: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; border-radius: 4px; padding: 2px 8px; font-weight: 600; font-size: 11px;")
            top_row.addWidget(badge)

            r_layout.addLayout(top_row)

            desc_lbl = QLabel(item.description)
            desc_lbl.setStyleSheet("font-size: 12px; color: #475569;")
            desc_lbl.setWordWrap(True)
            r_layout.addWidget(desc_lbl)

            if item.location:
                loc_lbl = QLabel(f"Path: {item.location}")
                loc_lbl.setStyleSheet("font-size: 11px; color: #64748B; font-family: monospace;")
                r_layout.addWidget(loc_lbl)

            if item.remediation:
                rem_lbl = QLabel(f"Remediation: {item.remediation}")
                rem_lbl.setStyleSheet("font-size: 11px; color: #B45309; font-style: italic;")
                rem_lbl.setWordWrap(True)
                r_layout.addWidget(rem_lbl)

            layout.addWidget(row)

        self.content_layout.addWidget(card)
