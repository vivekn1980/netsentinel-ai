"""Settings view for NetSentinel AI.

Manages application information, data directories, portable mode status,
and secure DPAPI credentials for optional AI integration.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.config import APP_NAME, APP_VERSION, ConfigManager


class SettingsView(QWidget):
    """Application preferences and secure configuration panel."""

    clear_requested = Signal()

    def __init__(self, config_mgr: ConfigManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.config_mgr = config_mgr
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        # Header Title
        title_box = QVBoxLayout()
        title = QLabel("Settings & Preferences")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("System configuration, storage location, and secure credential vault")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)

        # Scroll Area for Setting Cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        container = QWidget()
        cards_layout = QVBoxLayout(container)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(16)
        scroll.setWidget(container)

        # 1. Application Information Card
        app_card = QFrame()
        app_card.setProperty("class", "contentCard")
        app_layout = QVBoxLayout(app_card)
        app_layout.setContentsMargins(18, 16, 18, 16)
        app_layout.setSpacing(12)

        app_title = QLabel("Application Information")
        app_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        app_layout.addWidget(app_title)

        app_info_grid = QVBoxLayout()
        app_info_grid.setSpacing(6)
        app_info_grid.addWidget(self._create_info_row("Product Name", APP_NAME))
        app_info_grid.addWidget(self._create_info_row("Version", f"{APP_VERSION} (Milestone 1)"))
        app_info_grid.addWidget(self._create_info_row("Developer", "Vivek Nigam"))
        app_info_grid.addWidget(self._create_info_row("Target Platform", "Windows 10 / 11 64-bit"))
        app_info_grid.addWidget(self._create_info_row("Distribution Format", "Standalone Portable Executable (NetSentinelAI.exe)"))
        app_info_grid.addWidget(self._create_info_row("Host Requirements", "No separate Python, Node.js, PostgreSQL, or Nmap required"))
        app_layout.addLayout(app_info_grid)
        cards_layout.addWidget(app_card)

        # 2. Data Storage & Portability Card
        storage_card = QFrame()
        storage_card.setProperty("class", "contentCard")
        storage_layout = QVBoxLayout(storage_card)
        storage_layout.setContentsMargins(18, 16, 18, 16)
        storage_layout.setSpacing(12)

        storage_title = QLabel("Storage & Portability")
        storage_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        storage_layout.addWidget(storage_title)

        storage_rows = QVBoxLayout()
        storage_rows.setSpacing(6)
        storage_rows.addWidget(self._create_info_row("Current Storage Mode", self.config_mgr.storage_mode_label))
        storage_rows.addWidget(self._create_info_row("Active Data Directory", str(self.config_mgr.data_dir)))
        storage_rows.addWidget(self._create_info_row("Database File", str(self.config_mgr.db_file)))
        storage_rows.addWidget(self._create_info_row("Config File", str(self.config_mgr.config_file)))
        storage_layout.addLayout(storage_rows)

        # Open Data Folder and Clear Data Buttons
        btn_row = QHBoxLayout()
        self.open_dir_btn = QPushButton("Open Data Folder in File Explorer")
        self.open_dir_btn.setProperty("class", "secondaryButton")
        self.open_dir_btn.clicked.connect(self._open_data_folder)
        btn_row.addWidget(self.open_dir_btn)

        self.clear_data_btn = QPushButton("Clear All Scan Data...")
        self.clear_data_btn.setStyleSheet(
            "QPushButton { background-color: #FEE2E2; color: #DC2626; border: 1px solid #FCA5A5; "
            "padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; } "
            "QPushButton:hover { background-color: #DC2626; color: #FFFFFF; border-color: #DC2626; }"
        )
        self.clear_data_btn.clicked.connect(self._on_clear_data_clicked)
        btn_row.addWidget(self.clear_data_btn)

        btn_row.addStretch()
        storage_layout.addLayout(btn_row)

        cards_layout.addWidget(storage_card)

        # 3. Secure AI Configuration Placeholder Card (DPAPI Protected)
        ai_card = QFrame()
        ai_card.setProperty("class", "contentCard")
        ai_layout = QVBoxLayout(ai_card)
        ai_layout.setContentsMargins(18, 16, 18, 16)
        ai_layout.setSpacing(14)

        ai_title = QLabel("AI Security Explanations (Optional Integration)")
        ai_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        ai_desc = QLabel(
            "Configure an AI provider to receive transparent security explanations and defensive remediation advice. "
            "Security Policy: NetSentinel AI never transmits scan results without user review and stores all API keys "
            "using Windows DPAPI encryption (never in plaintext)."
        )
        ai_desc.setStyleSheet("font-size: 12px; color: #64748B;")
        ai_desc.setWordWrap(True)

        ai_layout.addWidget(ai_title)
        ai_layout.addWidget(ai_desc)

        # AI Provider Selection
        prov_row = QHBoxLayout()
        prov_lbl = QLabel("AI Provider:")
        prov_lbl.setFixedWidth(130)
        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems([
            "Disabled (Local Only)",
            "Google Gemini (gemini-2.5-flash)",
            "OpenAI (gpt-4o-mini)",
            "Anthropic Claude (claude-3-5-haiku)",
        ])
        prov_row.addWidget(prov_lbl)
        prov_row.addWidget(self.ai_provider_combo)
        ai_layout.addLayout(prov_row)

        # API Key Input (Password masked)
        key_row = QHBoxLayout()
        key_lbl = QLabel("API Key:")
        key_lbl.setFixedWidth(130)
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("Enter provider API key (masked)")
        if self.config_mgr.has_ai_key():
            self.api_key_input.setPlaceholderText("•••••••••••••••• [Stored in Windows DPAPI Vault]")

        key_row.addWidget(key_lbl)
        key_row.addWidget(self.api_key_input)
        ai_layout.addLayout(key_row)

        # Status & Save Action
        actions_row = QHBoxLayout()
        self.ai_status_badge = QLabel(
            "✓ Key Encrypted (Windows DPAPI)" if self.config_mgr.has_ai_key() else "No Key Configured"
        )
        if self.config_mgr.has_ai_key():
            self.ai_status_badge.setStyleSheet("background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;")
        else:
            self.ai_status_badge.setStyleSheet("background-color: #F1F5F9; color: #64748B; border: 1px solid #CBD5E1; border-radius: 4px; padding: 4px 10px; font-weight: 500; font-size: 11px;")

        actions_row.addWidget(self.ai_status_badge)
        actions_row.addStretch()

        self.save_key_btn = QPushButton("Save Credentials Securely")
        self.save_key_btn.setProperty("class", "primaryButton")
        self.save_key_btn.clicked.connect(self._save_ai_credentials)
        actions_row.addWidget(self.save_key_btn)
        ai_layout.addLayout(actions_row)

        cards_layout.addWidget(ai_card)
        cards_layout.addStretch()

        layout.addWidget(scroll)

    def _create_info_row(self, label: str, value: str) -> QWidget:
        row = QWidget()
        l = QHBoxLayout(row)
        l.setContentsMargins(0, 2, 0, 2)
        lbl = QLabel(label)
        lbl.setStyleSheet("font-weight: 600; color: #475569; font-size: 12px;")
        lbl.setFixedWidth(200)

        val = QLabel(value)
        val.setStyleSheet("color: #0F172A; font-size: 12px;")
        val.setTextInteractionFlags(Qt.TextSelectableByMouse)

        l.addWidget(lbl)
        l.addWidget(val)
        l.addStretch()
        return row

    def _open_data_folder(self) -> None:
        try:
            os.startfile(str(self.config_mgr.data_dir))
        except Exception as e:
            QMessageBox.warning(self, "Explorer Error", f"Unable to open directory: {e}")

    def _on_clear_data_clicked(self) -> None:
        self.clear_requested.emit()

    def _save_ai_credentials(self) -> None:
        new_key = self.api_key_input.text().strip()
        provider = self.ai_provider_combo.currentText()

        self.config_mgr.config.ai_provider = provider
        if new_key:
            self.config_mgr.set_ai_key(new_key)
            self.ai_status_badge.setText("✓ Key Encrypted (Windows DPAPI)")
            self.ai_status_badge.setStyleSheet("background-color: #ECFDF5; color: #059669; border: 1px solid #A7F3D0; border-radius: 4px; padding: 4px 10px; font-weight: 600; font-size: 11px;")
            self.api_key_input.clear()
            self.api_key_input.setPlaceholderText("•••••••••••••••• [Stored in Windows DPAPI Vault]")
            QMessageBox.information(
                self,
                "Security Confirmation",
                "API Key has been encrypted with Windows DPAPI and safely stored. It is never stored in plaintext."
            )
        else:
            self.config_mgr.save()
            QMessageBox.information(self, "Settings Saved", "Configuration preferences updated.")
