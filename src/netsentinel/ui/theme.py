"""Modern Windows light theme and styling for NetSentinel AI desktop UI."""

from __future__ import annotations

# Color Palette Constants
COLOR_BG_WINDOW = "#F8FAFC"        # Slate 50
COLOR_BG_CARD = "#FFFFFF"          # Pure White
COLOR_BG_SIDEBAR = "#FFFFFF"       # White Sidebar
COLOR_BG_INPUT = "#FFFFFF"         # White Input
COLOR_BORDER = "#E2E8F0"           # Slate 200
COLOR_BORDER_FOCUS = "#3B82F6"     # Blue 500
COLOR_TEXT_PRIMARY = "#0F172A"     # Slate 900
COLOR_TEXT_MUTED = "#64748B"       # Slate 500
COLOR_TEXT_LIGHT = "#94A3B8"       # Slate 400
COLOR_PRIMARY = "#2563EB"          # Blue 600
COLOR_PRIMARY_HOVER = "#1D4ED8"    # Blue 700
COLOR_PRIMARY_LIGHT = "#EFF6FF"    # Blue 50
COLOR_SUCCESS = "#059669"          # Emerald 600
COLOR_SUCCESS_BG = "#ECFDF5"       # Emerald 50
COLOR_WARNING = "#D97706"          # Amber 600
COLOR_WARNING_BG = "#FFFBEB"       # Amber 50
COLOR_DANGER = "#DC2626"           # Red 600
COLOR_DANGER_BG = "#FEF2F2"        # Red 50
COLOR_INFO = "#0284C7"             # Sky 600
COLOR_INFO_BG = "#F0F9FF"          # Sky 50

LIGHT_THEME_QSS = f"""
/* Global Reset and Typography */
QWidget {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', sans-serif;
    font-size: 13px;
    color: {COLOR_TEXT_PRIMARY};
    background-color: transparent;
}}

QMainWindow {{
    background-color: {COLOR_BG_WINDOW};
}}

/* Header Bar */
#topHeader {{
    background-color: {COLOR_BG_CARD};
    border-bottom: 1px solid {COLOR_BORDER};
    padding: 8px 16px;
}}

#appTitle {{
    font-size: 16px;
    font-weight: 700;
    color: {COLOR_TEXT_PRIMARY};
}}

#appSubtitle {{
    font-size: 11px;
    font-weight: 500;
    color: {COLOR_TEXT_MUTED};
}}

/* Sidebar */
#sidebarFrame {{
    background-color: {COLOR_BG_SIDEBAR};
    border-right: 1px solid {COLOR_BORDER};
}}

#navButton {{
    background-color: transparent;
    border: none;
    border-radius: 6px;
    padding: 10px 14px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
    color: {COLOR_TEXT_MUTED};
}}

#navButton:hover {{
    background-color: #F1F5F9;
    color: {COLOR_TEXT_PRIMARY};
}}

#navButton[active="true"] {{
    background-color: {COLOR_PRIMARY_LIGHT};
    color: {COLOR_PRIMARY};
    font-weight: 600;
    border-left: 3px solid {COLOR_PRIMARY};
}}

/* Content Card Panels */
QFrame.contentCard {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
}}

/* Typography Headings */
QLabel.viewTitle {{
    font-size: 18px;
    font-weight: 700;
    color: {COLOR_TEXT_PRIMARY};
}}

QLabel.viewSubtitle {{
    font-size: 13px;
    color: {COLOR_TEXT_MUTED};
}}

QLabel.cardTitle {{
    font-size: 14px;
    font-weight: 600;
    color: {COLOR_TEXT_PRIMARY};
}}

QLabel.metricValue {{
    font-size: 26px;
    font-weight: 700;
    color: {COLOR_PRIMARY};
}}

QLabel.metricLabel {{
    font-size: 12px;
    font-weight: 500;
    color: {COLOR_TEXT_MUTED};
}}

/* Push Buttons */
QPushButton.primaryButton {{
    background-color: {COLOR_PRIMARY};
    color: #FFFFFF;
    font-weight: 600;
    border-radius: 6px;
    padding: 8px 18px;
    border: none;
}}

QPushButton.primaryButton:hover {{
    background-color: {COLOR_PRIMARY_HOVER};
}}

QPushButton.primaryButton:disabled {{
    background-color: #94A3B8;
    color: #F1F5F9;
}}

QPushButton.secondaryButton {{
    background-color: #FFFFFF;
    color: {COLOR_TEXT_PRIMARY};
    font-weight: 500;
    border-radius: 6px;
    padding: 7px 16px;
    border: 1px solid {COLOR_BORDER};
}}

QPushButton.secondaryButton:hover {{
    background-color: #F8FAFC;
    border-color: #CBD5E1;
}}

/* Input Controls */
QLineEdit, QComboBox {{
    background-color: {COLOR_BG_INPUT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    color: {COLOR_TEXT_PRIMARY};
    font-size: 13px;
}}

QLineEdit:focus, QComboBox:focus {{
    border: 1.5px solid {COLOR_BORDER_FOCUS};
    outline: none;
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: none;
}}

/* Checkbox */
QCheckBox {{
    spacing: 8px;
    font-size: 13px;
    color: {COLOR_TEXT_PRIMARY};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1.5px solid {COLOR_BORDER};
    background-color: #FFFFFF;
}}

QCheckBox::indicator:checked {{
    background-color: {COLOR_PRIMARY};
    border-color: {COLOR_PRIMARY};
}}

/* Table Styling */
QTableWidget {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    gridline-color: #F1F5F9;
    color: {COLOR_TEXT_PRIMARY};
    selection-background-color: {COLOR_PRIMARY_LIGHT};
    selection-color: {COLOR_PRIMARY};
}}

QTableWidget::item {{
    padding: 8px;
    border-bottom: 1px solid #F1F5F9;
}}

QHeaderView::section {{
    background-color: #F8FAFC;
    color: {COLOR_TEXT_MUTED};
    font-size: 12px;
    font-weight: 600;
    padding: 8px;
    border: none;
    border-bottom: 1px solid {COLOR_BORDER};
    text-align: left;
}}

/* Status and Pill Badges */
QLabel.badgeOk {{
    background-color: {COLOR_SUCCESS_BG};
    color: {COLOR_SUCCESS};
    border: 1px solid #A7F3D0;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}

QLabel.badgeWarning {{
    background-color: {COLOR_WARNING_BG};
    color: {COLOR_WARNING};
    border: 1px solid #FDE68A;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}

QLabel.badgeDanger {{
    background-color: {COLOR_DANGER_BG};
    color: {COLOR_DANGER};
    border: 1px solid #FECACA;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}

QLabel.badgeInfo {{
    background-color: {COLOR_INFO_BG};
    color: {COLOR_INFO};
    border: 1px solid #BAE6FD;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}

QLabel.badgeNeutral {{
    background-color: #F1F5F9;
    color: {COLOR_TEXT_MUTED};
    border: 1px solid {COLOR_BORDER};
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}}

/* Scrollbar */
QScrollBar:vertical {{
    background: #F8FAFC;
    width: 8px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background: #CBD5E1;
    border-radius: 4px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background: #94A3B8;
}}

/* Status Bar */
QStatusBar {{
    background-color: {COLOR_BG_CARD};
    border-top: 1px solid {COLOR_BORDER};
    color: {COLOR_TEXT_MUTED};
    font-size: 12px;
}}

/* Dialogs, Popups & Message Boxes */
QDialog, QMessageBox {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_TEXT_PRIMARY};
}}

QMessageBox QLabel {{
    color: {COLOR_TEXT_PRIMARY};
    background-color: transparent;
    font-size: 13px;
}}

QMessageBox QPushButton {{
    background-color: #F1F5F9;
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid #CBD5E1;
    border-radius: 6px;
    padding: 7px 18px;
    font-size: 12px;
    font-weight: 600;
    min-width: 80px;
}}

QMessageBox QPushButton:hover {{
    background-color: #E2E8F0;
    border-color: #94A3B8;
}}

QMessageBox QPushButton:focus {{
    border: 2px solid {COLOR_PRIMARY};
    outline: none;
}}

/* Tab Widgets */
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background-color: {COLOR_BG_CARD};
    border-radius: 6px;
    top: -1px;
}}

QTabBar::tab {{
    background-color: #F8FAFC;
    color: {COLOR_TEXT_MUTED};
    border: 1px solid {COLOR_BORDER};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
    margin-right: 4px;
}}

QTabBar::tab:selected {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_PRIMARY};
    border-color: {COLOR_BORDER};
    border-bottom: 2px solid {COLOR_PRIMARY};
}}

QTabBar::tab:hover:!selected {{
    background-color: #F1F5F9;
    color: {COLOR_TEXT_PRIMARY};
}}
"""
