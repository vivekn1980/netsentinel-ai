"""Modal export dialog for generating HTML reports, CSV files, and JSON exports.

Executes file generation asynchronously in a background QThread to keep the PySide6
UI completely responsive even for large multi-asset finding databases.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.database import DatabaseManager
from netsentinel.core.reporting.report_generator import ReportGenerator
from netsentinel.core.reporting.report_paths import ReportPaths


class ExportWorker(QThread):
    """Background worker thread executing report and data export asynchronously."""

    export_completed = Signal(bool, str, str)  # success, file_path, message

    def __init__(
        self,
        generator: ReportGenerator,
        format_type: str,
        output_path: Path,
        session_id: Optional[int] = None,
        include_resolved: bool = True,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.generator = generator
        self.format_type = format_type.lower()
        self.output_path = output_path
        self.session_id = session_id
        self.include_resolved = include_resolved

    def run(self) -> None:
        try:
            if self.format_type == "html":
                self.generator.generate_html_report(
                    session_id=self.session_id,
                    output_path=self.output_path,
                    include_resolved=self.include_resolved,
                )
            elif self.format_type == "csv":
                self.generator.export_findings_csv(
                    output_path=self.output_path,
                    session_id=self.session_id,
                    include_resolved=self.include_resolved,
                )
            elif self.format_type == "json":
                self.generator.export_findings_json(
                    output_path=self.output_path,
                    session_id=self.session_id,
                    include_resolved=self.include_resolved,
                )
            else:
                self.export_completed.emit(False, "", f"Unsupported format: {self.format_type}")
                return

            self.export_completed.emit(True, str(self.output_path), "Export successfully generated.")
        except Exception as e:
            self.export_completed.emit(False, "", str(e))


class ExportDialog(QDialog):
    """Interactive multi-format report and data export dialog."""

    def __init__(
        self,
        db_mgr: DatabaseManager,
        session_id: Optional[int] = None,
        target_name: str = "audit",
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.db_mgr = db_mgr
        self.generator = ReportGenerator(db_mgr)
        self.session_id = session_id
        self.target_name = target_name
        self.worker: Optional[ExportWorker] = None

        self.setWindowTitle("Export Security Findings & Audit Reports")
        self.resize(560, 440)
        self.setStyleSheet("background-color: #FFFFFF; font-family: 'Segoe UI', sans-serif;")

        self._init_ui()
        self._update_default_path()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header Title
        title_box = QVBoxLayout()
        title = QLabel("Export Findings & Compliance Reports")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("Choose format, target scope, and destination for audit documentation.")
        subtitle.setStyleSheet("font-size: 12px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Format Selection Card
        format_card = QFrame()
        format_card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;")
        format_l = QVBoxLayout(format_card)
        format_l.setContentsMargins(16, 12, 16, 12)
        format_l.setSpacing(8)

        format_lbl = QLabel("SELECT EXPORT FORMAT")
        format_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569; letter-spacing: 0.05em;")
        format_l.addWidget(format_lbl)

        self.btn_group_format = QButtonGroup(self)
        self.radio_html = QRadioButton("Executive HTML Report (.html) — Standalone offline audit document with charts")
        self.radio_html.setChecked(True)
        self.radio_csv = QRadioButton("CSV Spreadsheet (.csv) — RFC 4180 with Excel injection protection")
        self.radio_json = QRadioButton("Structured JSON (.json) — Schema-versioned (1.0.0) for SIEM / automation")

        self.btn_group_format.addButton(self.radio_html)
        self.btn_group_format.addButton(self.radio_csv)
        self.btn_group_format.addButton(self.radio_json)

        self.radio_html.toggled.connect(self._on_format_changed)
        self.radio_csv.toggled.connect(self._on_format_changed)
        self.radio_json.toggled.connect(self._on_format_changed)

        format_l.addWidget(self.radio_html)
        format_l.addWidget(self.radio_csv)
        format_l.addWidget(self.radio_json)
        layout.addWidget(format_card)

        # Scope & Options Card
        opts_card = QFrame()
        opts_card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;")
        opts_l = QVBoxLayout(opts_card)
        opts_l.setContentsMargins(16, 12, 16, 12)
        opts_l.setSpacing(8)

        opts_lbl = QLabel("SCOPE & INCLUSION OPTIONS")
        opts_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569; letter-spacing: 0.05em;")
        opts_l.addWidget(opts_lbl)

        if self.session_id:
            self.chk_all_sessions = QCheckBox("Export all historical findings (uncheck for current session only)")
            self.chk_all_sessions.setChecked(False)
            self.chk_all_sessions.toggled.connect(self._update_default_path)
            opts_l.addWidget(self.chk_all_sessions)
        else:
            self.chk_all_sessions = None

        self.chk_include_resolved = QCheckBox("Include Resolved and False Positive findings in export")
        self.chk_include_resolved.setChecked(True)
        opts_l.addWidget(self.chk_include_resolved)

        layout.addWidget(opts_card)

        # Output Destination Path
        dest_box = QVBoxLayout()
        dest_lbl = QLabel("Destination File Path:")
        dest_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #334155;")
        dest_box.addWidget(dest_lbl)

        path_row = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setStyleSheet("padding: 6px 10px; border: 1px solid #CBD5E1; border-radius: 4px; font-size: 12px;")
        path_row.addWidget(self.path_input)

        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setStyleSheet("padding: 6px 14px; background-color: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 4px; font-weight: 600;")
        self.btn_browse.clicked.connect(self._browse_destination)
        path_row.addWidget(self.btn_browse)
        dest_box.addLayout(path_row)
        layout.addLayout(dest_box)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar { border: 1px solid #CBD5E1; border-radius: 4px; height: 12px; text-align: center; } QProgressBar::chunk { background-color: #0284C7; }")
        layout.addWidget(self.progress_bar)

        self.status_lbl = QLabel("")
        self.status_lbl.setStyleSheet("font-size: 11px; color: #64748B;")
        layout.addWidget(self.status_lbl)

        layout.addStretch()

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setStyleSheet("padding: 8px 16px; background-color: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 6px; font-weight: 600; color: #475569;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_cancel)

        self.btn_export = QPushButton("Generate Export")
        self.btn_export.setStyleSheet("padding: 8px 20px; background-color: #0284C7; border: none; border-radius: 6px; font-weight: 700; color: #FFFFFF;")
        self.btn_export.clicked.connect(self._start_export)
        btn_row.addWidget(self.btn_export)

        layout.addLayout(btn_row)

    def _get_current_format(self) -> str:
        if self.radio_csv.isChecked():
            return "csv"
        if self.radio_json.isChecked():
            return "json"
        return "html"

    def _on_format_changed(self) -> None:
        self._update_default_path()

    def _update_default_path(self) -> None:
        fmt = self._get_current_format()
        is_all = self.chk_all_sessions and self.chk_all_sessions.isChecked()
        target_name = "All_Findings" if is_all else self.target_name
        prefix = "NetSentinel_Export" if is_all else "NetSentinel_Report"

        try:
            default_path = ReportPaths.build_report_path(
                target_input=target_name,
                extension=fmt,
                prefix=prefix,
            )
            self.path_input.setText(str(default_path))
        except Exception:
            pass

    def _browse_destination(self) -> None:
        fmt = self._get_current_format()
        current_path = self.path_input.text().strip()
        default_dir = str(Path(current_path).parent) if current_path else ""

        filter_str = "HTML Files (*.html)" if fmt == "html" else ("CSV Files (*.csv)" if fmt == "csv" else "JSON Files (*.json)")
        chosen, _ = QFileDialog.getSaveFileName(
            self,
            "Select Export Destination",
            current_path or default_dir,
            f"{filter_str};;All Files (*.*)",
        )
        if chosen:
            self.path_input.setText(chosen)

    def _start_export(self) -> None:
        dest_text = self.path_input.text().strip()
        if not dest_text:
            QMessageBox.warning(self, "Invalid Path", "Please enter or select a valid destination file path.")
            return

        dest_path = Path(dest_text)
        try:
            ReportPaths.ensure_directory_writable(dest_path.parent)
        except Exception as e:
            QMessageBox.critical(self, "Directory Permission Error", str(e))
            return

        fmt = self._get_current_format()
        is_all = bool(self.chk_all_sessions and self.chk_all_sessions.isChecked())
        session_id = None if is_all else self.session_id
        include_resolved = self.chk_include_resolved.isChecked()

        # UI state during async export
        self.btn_export.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_lbl.setText("Generating export in background...")

        self.worker = ExportWorker(
            generator=self.generator,
            format_type=fmt,
            output_path=dest_path,
            session_id=session_id,
            include_resolved=include_resolved,
            parent=self,
        )
        self.worker.export_completed.connect(self._on_export_finished)
        self.worker.start()

    def _on_export_finished(self, success: bool, file_path: str, msg: str) -> None:
        self.btn_export.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.progress_bar.setVisible(False)

        if success:
            self.status_lbl.setText(f"Export created: {Path(file_path).name}")
            resp = QMessageBox.information(
                self,
                "Export Complete",
                f"Export file generated successfully!\n\nDestination:\n{file_path}\n\nWould you like to open the containing folder?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if resp == QMessageBox.Yes:
                folder = str(Path(file_path).parent)
                try:
                    if os.name == "nt":
                        os.startfile(folder)
                except Exception:
                    pass
            self.accept()
        else:
            self.status_lbl.setText("Export failed.")
            QMessageBox.critical(self, "Export Failed", f"Failed to generate export file:\n{msg}")
