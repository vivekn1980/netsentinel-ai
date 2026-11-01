"""Headless integration test for PySide6 MainWindow and views."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# Ensure Qt runs offscreen for CI / headless testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication, QMessageBox

from netsentinel.core.config import ConfigManager
from netsentinel.core.database import DatabaseManager
from netsentinel.core.models import Asset, Port, ScanSession, SecurityFinding
from netsentinel.ui.main_window import MainWindow


@pytest.fixture(scope="session")
def qapp():
    """Provides a single persistent QApplication instance for headless tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(["--platform", "offscreen"])
    yield app


def test_main_window_headless_initialization(qapp, tmp_path: Path):
    """Test that MainWindow, sidebar, and all 6 views initialize cleanly without errors."""
    data_dir = tmp_path / "test_data"
    config_mgr = ConfigManager(explicit_data_dir=data_dir)
    db_mgr = DatabaseManager(config_mgr.db_file)

    # Pre-populate some DB records to test non-empty rendering
    asset = Asset(ip_address="192.168.1.100", hostname="host-test.lan")
    aid = db_mgr.upsert_asset(asset)
    db_mgr.add_port(Port(asset_id=aid, port_number=80, service_name="http"))
    db_mgr.create_scan_session(ScanSession(target_input="192.168.1.100", profile="tcp_connect", status="completed"))
    db_mgr.add_security_finding(
        SecurityFinding(
            asset_id=aid,
            severity="Medium",
            title="HTTP Server Header Information Disclosure",
            description="Web server reveals exact banner version in HTTP headers.",
            recommendation="Configure ServerTokens Prod in web server configuration.",
        )
    )

    window = MainWindow(config_mgr, db_mgr)
    assert window is not None
    assert window.stack.count() == 6
    assert window.credit_label.text() == "Developed by: Vivek Nigam"

    # Test switching to every tab
    for view_idx in range(6):
        window._switch_view(view_idx)
        assert window.stack.currentIndex() == view_idx

    # Verify dashboard metrics updated
    metrics = db_mgr.get_dashboard_metrics()
    assert metrics["total_assets"] == 1
    assert metrics["open_ports"] == 1
    assert metrics["completed_scans"] == 1
    assert metrics["total_findings"] == 1

    # Verify inventory table has row
    assert window.inventory_view.table.rowCount() == 1

    # Verify history table has row
    assert window.history_view.table.rowCount() == 1

    # Clean up window
    window.close()


def test_app_main_test_gui_clean_exit(tmp_path: Path):
    """Test that python -m netsentinel.app --test-gui initializes GUI and cleanly exits with code 0."""
    import subprocess
    data_dir = tmp_path / "gui_test_data"
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    res = subprocess.run(
        [sys.executable, "-m", "netsentinel.app", "--test-gui", "--data-dir", str(data_dir)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert res.returncode == 0, f"App exited with {res.returncode}: {res.stderr}"


def test_ui_clear_buttons_exist_and_wired(qapp, tmp_path: Path):
    """Verify that clear buttons exist in both Settings and History views."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_buttons_test")
    db_mgr = DatabaseManager(config_mgr.db_file)
    window = MainWindow(config_mgr, db_mgr)

    assert hasattr(window.settings_view, "clear_data_btn")
    assert window.settings_view.clear_data_btn.isEnabled()
    assert "Clear All Scan Data" in window.settings_view.clear_data_btn.text()

    assert hasattr(window.history_view, "clear_btn")
    assert window.history_view.clear_btn.isEnabled()
    assert "Clear All History" in window.history_view.clear_btn.text()
    window.close()


def test_ui_clear_data_cancel_preserves_records(qapp, tmp_path: Path, monkeypatch):
    """Verify that cancelling the confirmation dialog leaves all database records intact."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_cancel_test")
    db_mgr = DatabaseManager(config_mgr.db_file)

    # Populate records
    aid = db_mgr.upsert_asset(Asset(ip_address="192.168.1.1", hostname="router.lan"))
    db_mgr.create_scan_session(ScanSession(target_input="192.168.1.1", profile="tcp_connect", status="completed"))

    window = MainWindow(config_mgr, db_mgr)

    # Mock QMessageBox.exec so it leaves clickedButton() as None or Cancel
    monkeypatch.setattr(QMessageBox, "exec", lambda self: 0)

    # Trigger clear via Settings button
    window.settings_view.clear_data_btn.click()

    # Verify records were NOT deleted
    assert len(db_mgr.list_assets()) == 1
    assert len(db_mgr.list_scan_sessions()) == 1
    window.close()


def test_ui_clear_confirmation_dialog_cancel_default_enter_escape(qapp, tmp_path: Path, monkeypatch):
    """Verify confirmation dialog attributes: Cancel is default focused, Enter and Escape cancel, explicit confirm required."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_dialog_test")
    db_mgr = DatabaseManager(config_mgr.db_file)

    # Populate records
    aid = db_mgr.upsert_asset(Asset(ip_address="192.168.1.1", hostname="router.lan"))
    db_mgr.create_scan_session(ScanSession(target_input="192.168.1.1", profile="tcp_connect", status="completed"))

    window = MainWindow(config_mgr, db_mgr)

    # 1. Test Enter key / Default button behavior:
    # When Enter is pressed in a dialog, Qt triggers the default button.
    # We verify that defaultButton() is Cancel (RejectRole), escapeButton() is Cancel, and executing defaultButton leaves data intact.
    dialog_inspected = {}

    def mock_exec_enter(self):
        default_btn = self.defaultButton()
        escape_btn = self.escapeButton()
        dialog_inspected["default_btn_text"] = default_btn.text() if default_btn else ""
        dialog_inspected["default_btn_role"] = self.buttonRole(default_btn) if default_btn else None
        dialog_inspected["escape_btn_text"] = escape_btn.text() if escape_btn else ""
        dialog_inspected["escape_btn_role"] = self.buttonRole(escape_btn) if escape_btn else None
        dialog_inspected["dialog_stylesheet"] = self.styleSheet()
        dialog_inspected["cancel_btn_stylesheet"] = default_btn.styleSheet() if default_btn else ""
        # Simulating Enter: clickedButton becomes defaultButton (Cancel)
        self._clicked_button = default_btn
        return 0

    monkeypatch.setattr(QMessageBox, "exec", mock_exec_enter)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: getattr(self, "_clicked_button", None))

    window.settings_view.clear_data_btn.click()

    assert dialog_inspected["default_btn_text"] == "Cancel"
    assert dialog_inspected["default_btn_role"] == QMessageBox.RejectRole
    assert dialog_inspected["escape_btn_text"] == "Cancel"
    assert dialog_inspected["escape_btn_role"] == QMessageBox.RejectRole
    # Verify explicit high-contrast light theme styling
    assert "#FFFFFF" in dialog_inspected["dialog_stylesheet"]
    assert "#0F172A" in dialog_inspected["dialog_stylesheet"]
    assert "#F1F5F9" in dialog_inspected["cancel_btn_stylesheet"]
    # Data must be preserved
    assert len(db_mgr.list_assets()) == 1
    assert len(db_mgr.list_scan_sessions()) == 1

    # 2. Test Escape key behavior:
    def mock_exec_escape(self):
        escape_btn = self.escapeButton()
        self._clicked_button = escape_btn
        return 0

    monkeypatch.setattr(QMessageBox, "exec", mock_exec_escape)
    window.history_view.clear_btn.click()

    # Data must still be preserved
    assert len(db_mgr.list_assets()) == 1
    assert len(db_mgr.list_scan_sessions()) == 1

    # 3. Test explicit selection of Destructive Confirm button:
    def mock_exec_confirm(self):
        for btn in self.buttons():
            if self.buttonRole(btn) == QMessageBox.DestructiveRole:
                self._clicked_button = btn
                return 0
        return 0

    monkeypatch.setattr(QMessageBox, "exec", mock_exec_confirm)
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)
    window.settings_view.clear_data_btn.click()

    # Now data is cleared
    assert len(db_mgr.list_assets()) == 0
    assert len(db_mgr.list_scan_sessions()) == 0
    window.close()


def test_ui_clear_data_success_and_views_synchronized(qapp, tmp_path: Path, monkeypatch):
    """Verify confirming clear deletes records, vacuums, and refreshes all views to empty states."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_success_test")
    db_mgr = DatabaseManager(config_mgr.db_file)

    # Populate records
    aid = db_mgr.upsert_asset(Asset(ip_address="192.168.1.5", hostname="nas.lan"))
    db_mgr.add_port(Port(asset_id=aid, port_number=445, service_name="microsoft-ds"))
    db_mgr.create_scan_session(ScanSession(target_input="192.168.1.5", profile="tcp_connect", status="completed"))
    db_mgr.add_security_finding(
        SecurityFinding(
            asset_id=aid,
            severity="Medium",
            title="SMB Signing Disabled",
            description="SMB signing not required.",
            recommendation="Enable SMB signing.",
        )
    )

    window = MainWindow(config_mgr, db_mgr)

    # Simulate user clicking "Permanently Erase All Data" on confirmation dialog
    def mock_msgbox_exec(self):
        # Find destructive button
        for btn in self.buttons():
            if self.buttonRole(btn) == QMessageBox.DestructiveRole:
                self._clicked_button = btn
                return 0
        return 0

    monkeypatch.setattr(QMessageBox, "exec", mock_msgbox_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: getattr(self, "_clicked_button", None))
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: None)

    # Trigger clear via History button
    window.history_view.clear_btn.click()

    # 1. Database is completely empty
    assert len(db_mgr.list_assets()) == 0
    assert len(db_mgr.list_scan_sessions()) == 0
    assert len(db_mgr.list_security_findings()) == 0

    # 2. Views are synchronized to empty states
    metrics = db_mgr.get_dashboard_metrics()
    assert metrics["total_assets"] == 0
    assert metrics["open_ports"] == 0
    assert metrics["total_findings"] == 0

    assert window.inventory_view.stack.currentIndex() == 0  # Empty state frame
    assert window.history_view.stack.currentIndex() == 0    # Empty state frame
    assert window.findings_view.stack.currentIndex() == 0   # Empty state frame
    assert len(window.findings_view.all_findings) == 0

    # 3. Status bar updated
    assert "cleared" in window.statusBar.currentMessage().lower()
    window.close()


def test_ui_clear_blocked_when_scan_active(qapp, tmp_path: Path, monkeypatch):
    """Verify that clear operation is blocked and warns user if a scan is active."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_scan_block_test")
    db_mgr = DatabaseManager(config_mgr.db_file)
    window = MainWindow(config_mgr, db_mgr)

    # Simulate active background worker
    mock_worker = MagicMock()
    mock_worker.isRunning.return_value = True
    window.active_worker = mock_worker

    warning_called = False
    def mock_warning(parent, title, text):
        nonlocal warning_called
        warning_called = True
        assert "Cannot clear database" in text

    monkeypatch.setattr(QMessageBox, "warning", mock_warning)

    window._handle_clear_all_data()
    assert warning_called is True
    window.close()


def test_ui_scan_startup_blocked_when_clearing(qapp, tmp_path: Path, monkeypatch):
    """Verify that scan startup is blocked if database clearing is currently active."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_scan_block2_test")
    db_mgr = DatabaseManager(config_mgr.db_file)
    window = MainWindow(config_mgr, db_mgr)

    # Acquire clear lock
    assert db_mgr.acquire_clear_lock() is True

    warning_called = False
    def mock_warning(parent, title, text):
        nonlocal warning_called
        warning_called = True
        assert "Database Busy" in title

    monkeypatch.setattr(QMessageBox, "warning", mock_warning)

    window._handle_scan_request("127.0.0.1", "tcp_connect")
    assert warning_called is True
    assert window.active_worker is None

    db_mgr.release_clear_lock()
    window.close()


def test_ui_clear_database_failure_handling(qapp, tmp_path: Path, monkeypatch):
    """Verify that database deletion failure shows critical dialog and re-enables UI controls."""
    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "ui_fail_test")
    db_mgr = DatabaseManager(config_mgr.db_file)
    window = MainWindow(config_mgr, db_mgr)

    from netsentinel.core.database import DataResetResult
    monkeypatch.setattr(db_mgr, "clear_all_data", lambda: DataResetResult(records_cleared=False, error="I/O Error"))

    critical_called = False
    def mock_critical(parent, title, text):
        nonlocal critical_called
        critical_called = True
        assert "I/O Error" in text

    def mock_msgbox_exec(self):
        for btn in self.buttons():
            if self.buttonRole(btn) == QMessageBox.DestructiveRole:
                self._clicked_button = btn
                return 0
        return 0

    monkeypatch.setattr(QMessageBox, "exec", mock_msgbox_exec)
    monkeypatch.setattr(QMessageBox, "clickedButton", lambda self: getattr(self, "_clicked_button", None))
    monkeypatch.setattr(QMessageBox, "critical", mock_critical)

    window._handle_clear_all_data()
    assert critical_called is True
    assert window.settings_view.clear_data_btn.isEnabled()
    assert window.history_view.clear_btn.isEnabled()
    window.close()


def test_scan_detail_dialog_tabs_and_hosts_rendering(qapp, tmp_path: Path):
    """Verify that ScanDetailDialog presents Discovered Hosts tab and Discovered Services tab."""
    from netsentinel.ui.views.history_view import ScanDetailDialog
    from netsentinel.ui.views.inventory_view import AssetDetailDialog
    from netsentinel.core.models import DiscoveredHost, ScanResult

    config_mgr = ConfigManager(explicit_data_dir=tmp_path / "scan_detail_test")
    db_mgr = DatabaseManager(config_mgr.db_file)

    # 1. Simulate a Host Discovery Scan (2 hosts, 0 ports)
    sid = db_mgr.create_scan_session(
        ScanSession(
            target_input="192.168.1.0/24",
            profile="Host Discovery Ping Sweep (-sn)",
            status="running",
        )
    )

    scan_res = ScanResult(
        success=True,
        elapsed_seconds=6.5,
        hosts=[
            DiscoveredHost(ip_address="192.168.1.1", hostname="gateway.lan", mac_address="5C:64:8E:CB:BF:00"),
            DiscoveredHost(ip_address="192.168.1.16", hostname="TCL6DXZ4J4", mac_address="BC:D2:2C:1B:24:C0"),
        ],
    )
    db_mgr.save_scan_results(sid, scan_res, command_str="nmap -sn 192.168.1.0/24")

    details = db_mgr.get_session_details(sid)
    dlg = ScanDetailDialog(details, db_mgr=db_mgr)

    # Verify tabs exist
    assert dlg.tabs.count() == 2
    assert "Discovered Hosts (2)" in dlg.tabs.tabText(0)
    assert "Discovered Services (0)" in dlg.tabs.tabText(1)
    assert dlg.tabs.currentIndex() == 0

    # Verify hosts table rows and values
    assert dlg.hosts_table.rowCount() == 2
    assert dlg.hosts_table.item(0, 0).text() == "192.168.1.1"
    assert dlg.hosts_table.item(0, 1).text() == "gateway.lan"
    assert dlg.hosts_table.item(0, 2).text() == "5C:64:8E:CB:BF:00"
    assert dlg.hosts_table.item(1, 0).text() == "192.168.1.16"
    assert dlg.hosts_table.item(1, 1).text() == "TCL6DXZ4J4"

    # 2. Simulate double click on host row opens AssetDetailDialog
    opened_dialog = False
    def mock_asset_dlg_exec(self):
        nonlocal opened_dialog
        opened_dialog = True
        return 0

    with patch.object(AssetDetailDialog, "exec", mock_asset_dlg_exec):
        dlg._on_host_double_clicked(dlg.hosts_table.item(0, 0))
        assert opened_dialog is True

    dlg.close()


