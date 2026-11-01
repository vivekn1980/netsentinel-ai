"""Asset inventory view for NetSentinel AI.

Displays discovered network hosts, operating system signatures, open port tallies,
risk classifications, and first/last seen timestamps with column sorting and detail dialog.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netsentinel.core.database import DatabaseManager


class AssetDetailDialog(QDialog):
    """Modal dialog displaying comprehensive details and open ports for a specific asset."""

    def __init__(self, asset, ports, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(f"Asset Details — {asset.ip_address}")
        self.resize(650, 480)
        self.setStyleSheet("background-color: #FFFFFF; font-family: 'Segoe UI', sans-serif;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header Info Card
        card = QFrame()
        card.setStyleSheet("background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px;")
        card_l = QVBoxLayout(card)
        card_l.setContentsMargins(16, 14, 16, 14)
        card_l.setSpacing(6)

        title = QLabel(f"🖥️  {asset.ip_address} ({asset.hostname or 'No Hostname'})")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #0F172A;")
        card_l.addWidget(title)

        os_info = asset.os_name or "Operating System Not Identified"
        if asset.os_accuracy:
            os_info += f" ({asset.os_accuracy}% accuracy)"
        mac_info = f"MAC: {asset.mac_address}" if asset.mac_address else "MAC: Unknown"
        sub = QLabel(f"{os_info}  •  {mac_info}  •  Risk: {asset.risk_level}")
        sub.setStyleSheet("font-size: 12px; color: #64748B;")
        card_l.addWidget(sub)

        layout.addWidget(card)

        # Ports Table
        ports_title = QLabel(f"Identified Network Ports ({len(ports)})")
        ports_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #0F172A;")
        layout.addWidget(ports_title)

        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Product / Version"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setRowCount(len(ports))

        for row, p in enumerate(ports):
            p_item = QTableWidgetItem(str(p.port_number))
            p_item.setTextAlignment(Qt.AlignCenter)
            proto_item = QTableWidgetItem(p.protocol.upper())
            proto_item.setTextAlignment(Qt.AlignCenter)
            state_item = QTableWidgetItem(p.state)
            state_item.setTextAlignment(Qt.AlignCenter)
            svc_item = QTableWidgetItem(p.service_name or "—")
            prod = f"{p.product} {p.version}".strip() or "—"
            prod_item = QTableWidgetItem(prod)

            table.setItem(row, 0, p_item)
            table.setItem(row, 1, proto_item)
            table.setItem(row, 2, state_item)
            table.setItem(row, 3, svc_item)
            table.setItem(row, 4, prod_item)

        layout.addWidget(table)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setProperty("class", "primaryButton")
        close_btn.setStyleSheet(
            "background-color: #2563EB; color: white; padding: 6px 18px; border-radius: 6px; font-weight: 600;"
        )
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)


class InventoryView(QWidget):
    """Network asset inventory view backed by SQLite with real discovery records."""

    def __init__(self, db_mgr: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db_mgr = db_mgr
        self._init_ui()
        self.refresh()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        # Header Title & Action Toolbar
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Network Asset Inventory")
        title.setStyleSheet("font-size: 20px; font-weight: 700; color: #0F172A;")
        subtitle = QLabel("Discovered endpoints, operating systems, and active exposed services (Double-click to view ports)")
        subtitle.setStyleSheet("font-size: 13px; color: #64748B;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_row.addLayout(title_box)

        header_row.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by IP, Hostname, or OS...")
        self.search_input.setFixedWidth(260)
        self.search_input.textChanged.connect(self._apply_filter)
        header_row.addWidget(self.search_input)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setProperty("class", "secondaryButton")
        self.refresh_btn.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_btn)

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

        empty_icon = QLabel("🖥️")
        empty_icon.setStyleSheet("font-size: 42px;")
        empty_icon.setAlignment(Qt.AlignCenter)

        empty_title = QLabel("No Network Assets Discovered Yet")
        empty_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #1E293B;")
        empty_title.setAlignment(Qt.AlignCenter)

        empty_desc = QLabel(
            "Execute an authorized discovery scan from the Dashboard to identify active hosts, "
            "inspect running services, and populate your inventory."
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
            "IP Address", "Hostname", "Operating System", "Open Ports",
            "Risk Level", "First Seen", "Last Seen"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)

        table_layout.addWidget(self.table)
        self.stack.addWidget(self.table_frame)

        layout.addWidget(self.stack)

    def refresh(self) -> None:
        """Loads actual assets from SQLite database."""
        assets = self.db_mgr.list_assets(limit=300)
        self.all_assets = assets

        if not assets:
            self.stack.setCurrentIndex(0)
            return

        self.stack.setCurrentIndex(1)
        self._populate_table(assets)

    def _populate_table(self, assets) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(assets))
        self.rendered_assets = assets

        for row, asset in enumerate(assets):
            ip_item = QTableWidgetItem(asset.ip_address)
            ip_item.setData(Qt.UserRole, asset.id)
            ip_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)

            host_item = QTableWidgetItem(asset.hostname or "—")
            host_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)

            os_str = asset.os_name or "Unknown OS"
            if asset.os_accuracy > 0:
                os_str += f" ({asset.os_accuracy}%)"
            os_item = QTableWidgetItem(os_str)

            ports_item = QTableWidgetItem(f"{asset.open_ports_count} open")
            ports_item.setTextAlignment(Qt.AlignCenter)

            risk_item = QTableWidgetItem(asset.risk_level)
            risk_item.setTextAlignment(Qt.AlignCenter)

            first_seen_item = QTableWidgetItem(asset.first_seen.replace("T", " "))
            last_seen_item = QTableWidgetItem(asset.last_seen.replace("T", " "))

            self.table.setItem(row, 0, ip_item)
            self.table.setItem(row, 1, host_item)
            self.table.setItem(row, 2, os_item)
            self.table.setItem(row, 3, ports_item)
            self.table.setItem(row, 4, risk_item)
            self.table.setItem(row, 5, first_seen_item)
            self.table.setItem(row, 6, last_seen_item)

        self.table.setSortingEnabled(True)

    def _apply_filter(self, query: str) -> None:
        """Filters table rows based on search input."""
        q = query.strip().lower()
        if not hasattr(self, "all_assets") or not self.all_assets:
            return

        filtered = [
            a for a in self.all_assets
            if q in a.ip_address.lower() or q in a.hostname.lower() or q in a.os_name.lower()
        ]
        self._populate_table(filtered)

    def _on_item_double_clicked(self, item: QTableWidgetItem) -> None:
        """Opens detailed asset dialog showing all open ports and services."""
        row = item.row()
        ip_item = self.table.item(row, 0)
        if not ip_item:
            return

        asset_id = ip_item.data(Qt.UserRole)
        if not asset_id:
            return

        asset = self.db_mgr.get_asset(asset_id)
        if not asset:
            return

        ports = self.db_mgr.get_ports_for_asset(asset_id)
        dlg = AssetDetailDialog(asset, ports, self)
        dlg.exec()
