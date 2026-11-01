# NetSentinel AI

**Standalone Windows Network Discovery & AI Security Auditing Desktop Application**

NetSentinel AI is a self-contained desktop application designed for Windows 10 and Windows 11 (64-bit). It delivers autonomous network discovery, authorized target scanning, inventory tracking, transparent risk assessment, and defensive security auditing without requiring end users to install Python, Node.js, PostgreSQL, or Nmap.

---

## Key Capabilities (Milestone 1)

- **Pure Windows Desktop Experience**: Native PySide6 interface featuring a clean, professional light-theme design system.
- **Self-Contained & Runtime-Free**: Single-file portable executable (`NetSentinelAI.exe`). No host Python or runtime dependencies required.
- **Embedded SQLite Storage**: Robust local database using WAL (Write-Ahead Logging) mode, foreign key enforcement, and automated integrity validation.
- **Dual Storage Modes**:
  - **Standard Mode**: Stores data in `%LOCALAPPDATA%\NetSentinelAI\`.
  - **Portable Mode**: Invoked via `--portable`, stores all data in a local `data/` directory adjacent to the executable (ideal for USB/removable media).
- **Target Safety Guardrails**:
  - Full support for IPv4, IPv6, CIDR blocks, and RFC 1123 hostnames.
  - Subnet breadth limits to prevent accidental sweeps (maximum /16).
  - Strict rejection of shell metacharacters and command injection attempts.
  - Public IP warnings and mandatory explicit authorization confirmation before discovery runs.
- **Comprehensive Dependency Diagnostics**:
  - Non-invasive detection of bundled vs. system Nmap.
  - Safe registry probing of Npcap / WinPcap packet drivers.
  - UAC elevation check distinguishing safe unprivileged TCP connect scanning from raw socket SYN stealth scanning.
- **Secure AI Credential Vault**:
  - Uses Windows DPAPI (`crypt32.dll`) to encrypt AI API keys at rest.
  - Zero plaintext credential storage in configuration files.

---

## Directory Structure

```
NetSentinel AI/
├── bin/                       # Bundled portable third-party binaries (e.g. Nmap)
├── build/                     # PyInstaller temporary compilation cache
├── dist/                      # PyInstaller single-file portable output (NetSentinelAI.exe)
├── scripts/
│   └── build_exe.py           # Automated build and self-test verification script
├── src/
│   └── netsentinel/
│       ├── __init__.py        # Version and package metadata
│       ├── app.py             # Application entry point and CLI router
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py      # Paths, settings, portable mode, and DPAPI vault
│       │   ├── database.py    # SQLite WAL schema, integrity checks, and CRUD operations
│       │   ├── dependencies.py# Nmap, Npcap, SQLite, and privilege diagnostic detector
│       │   ├── models.py      # Dataclasses (Asset, Port, ScanSession, SecurityFinding, AuditLog)
│       │   └── validator.py   # Strict target validation and security checks
│       └── ui/
│           ├── __init__.py
│           ├── main_window.py # Main application window shell & navigation sidebar
│           ├── theme.py       # Modern Windows light-theme stylesheet and palette
│           └── views/
│               ├── dashboard_view.py    # KPI metrics and authorized target launcher
│               ├── inventory_view.py    # Discovered host asset table with empty state
│               ├── history_view.py      # Scan history and compliance audit log
│               ├── findings_view.py     # Security findings and defensive recommendations
│               ├── dependencies_view.py # Categorized runtime and driver diagnostic panel
│               └── settings_view.py     # Storage mode, paths, and secure AI settings
├── tests/
│   ├── test_config.py         # Config persistence and DPAPI tests
│   ├── test_database.py       # SQLite CRUD, WAL mode, and integrity tests
│   ├── test_dependencies.py   # Dependency detection and capability logic tests
│   ├── test_ui_headless.py    # Headless PySide6 offscreen GUI initialization test
│   └── test_validator.py      # Security checks, injection prevention, and CIDR tests
├── netsentinel.spec           # PyInstaller single-file build specification
├── pyproject.toml             # Project package and pytest configuration
└── requirements.txt           # Python dependency specification
```

---

## Development Environment Setup

NetSentinel AI is developed for Python 3.10+ 64-bit on Windows 10/11.

### 1. Create and Activate Virtual Environment
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
pip install -e .
```

---

## Running the Application

### Option A: Standalone Executable (Recommended for End Users)

No Python, Git, or runtime installation required. The pre-built single-file binary is located at `dist\NetSentinelAI.exe`.

#### 1. Launch Directly (Standard Mode)
* **GUI / File Explorer**: Double-click [`dist\NetSentinelAI.exe`](dist/NetSentinelAI.exe).
* **Command Prompt / PowerShell**:
  ```powershell
  .\dist\NetSentinelAI.exe
  ```
  *In Standard Mode, all configuration and local SQLite database files are stored in `%LOCALAPPDATA%\NetSentinelAI\`.*

#### 2. Launch in Portable Mode
Ideal for running from a USB thumb drive, external SSD, or an isolated directory without touching the host profile:
```powershell
.\dist\NetSentinelAI.exe --portable
```
*In Portable Mode, all database records, scan history, and export files are strictly confined to `data\` and `reports\` folders adjacent to the executable.*

#### 3. Headless System Health Check
Verifies system compatibility, Nmap availability, driver status, and database WAL integrity from the command line without opening the GUI:
```powershell
.\dist\NetSentinelAI.exe --health-check
```

#### 4. Headless GUI Startup Verification
Initializes the full Qt event loop, validates main window widgets, and terminates gracefully (used for automated validation):
```powershell
.\dist\NetSentinelAI.exe --test-gui
```

---

### Option B: Running from Source (Developers)

Requires Python 3.10+ (64-bit) on Windows 10/11.

#### 1. Setup Virtual Environment
```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

#### 2. Launch Application
* **Standard Mode GUI**:
  ```powershell
  .venv\Scripts\python.exe -m netsentinel.app
  ```
* **Portable Mode GUI**:
  ```powershell
  .venv\Scripts\python.exe -m netsentinel.app --portable
  ```
* **Health Check**:
  ```powershell
  .venv\Scripts\python.exe -m netsentinel.app --health-check
  ```
* **Run Test Suite (228 Automated Tests)**:
  ```powershell
  .venv\Scripts\pytest.exe -v
  ```

---

## Step-by-Step User Workflow Guide

1. **Verify Engine Diagnostics**:
   * Open the dashboard and observe the top status badges:
     * **Storage Mode**: `Standard Mode` or `Portable Mode`
     * **Privileges**: `Standard User (TCP Connect Only)` or `Elevated Admin`
     * **Nmap Engine**: `Ready (TCP Connect)` or `Ready (Elevated Raw Sockets)`
   * If Nmap is missing, follow the [Nmap Installation Guide](#nmap-discovery-engine-setup--installation) below.

2. **Configure Target & Scan Profile**:
   * In the **Authorized Scan Console**, enter an authorized network scope:
     * Single IPv4: `192.168.1.1`
     * IPv4 Subnet: `192.168.1.0/24` (Max breadth: `/16` / 65,536 hosts)
     * IPv6 Host: `::1` or `fe80::1`
     * Domain / Hostname: `scanme.nmap.org`
   * Select a Scan Profile:
     * **Host Discovery Ping Sweep (`-sn`)**: Identifies live hosts without transport port scanning.
     * **Safe TCP Connect Scan (`-sT`)**: Standard unprivileged TCP connect scan against common enterprise service ports.
     * **Quick Vulnerability & Service Audit (`-sV`)**: Probes banners and service versions on open ports.
     * **Comprehensive Security Audit**: In-depth port auditing and service analysis.

3. **Authorize and Execute**:
   * Check the mandatory confirmation checkbox: *"I certify that I am explicitly authorized to perform security auditing on this target network."*
   * Click **Start Discovery Scan**.
   * Monitor live progress, duration counter, and real-time terminal output. To safely abort an active scan, click **Cancel Scan** (active processes are reaped gracefully and partial results are preserved).

4. **Review Assets & Findings**:
   * **Discovered Assets**: View discovered network devices, hostnames, MAC addresses, and operating system estimates. Double-click any row to open the deep-dive Asset Inspection dialog.
   * **Security Findings**: Review identified vulnerabilities, transparent risk scores (0–100), risk tiers (`Critical`, `High`, `Medium`, `Low`, `Info`), and step-by-step remediation procedures.
   * **Scan History**: Review historical audit sessions. Double-click any scan session to open the **Scan Session Inspection** dialog featuring dedicated **🖥️ Discovered Hosts** and **🔌 Discovered Services** tabs.

5. **Generate Compliance Reports**:
   * Navigate to **Settings > Export Reports** (or click **Export Session Report** from any historical scan session).
   * Choose from three offline, air-gapped formats:
     * **HTML Executive Report**: Clean, printable summary with risk breakdown and remediation tables.
     * **CSV Inventory Export**: Spreadsheet-ready host and service inventory.
     * **JSON SIEM Export**: Machine-parseable security event stream adhering to schema v1.0.0.

6. **Database Maintenance & Clear History**:
   * In **History** or **Settings**, click **Clear All History...**
   * Review the high-contrast confirmation dialog listing all data categories to be deleted.
   * Cancel is selected by default; clicking **Permanently Erase All Data** executes an atomic foreign-key-safe purge and SQLite VACUUM compaction.


---

## Nmap Discovery Engine Setup & Installation

NetSentinel AI discovers and verifies Nmap using multi-path candidate evaluation:
1. **Standard Windows Installations**: `C:\Program Files\Nmap\nmap.exe`, `C:\Program Files (x86)\Nmap\nmap.exe`, and `%LOCALAPPDATA%\Programs\Nmap\nmap.exe`.
2. **Windows Registry App Paths**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\nmap.exe`.
3. **System PATH**: Any `nmap.exe` available on `%PATH%`.
4. **Portable Application Directory**: `bin/nmap/nmap.exe` (or `bin/nmap.exe`, `nmap/nmap.exe`, `nmap.exe`) relative to `NetSentinelAI.exe` or bundle root.

---

### Method 1: Install Nmap using Windows Package Manager (Recommended)

**Step 1: Open PowerShell or Command Prompt**

Open Windows PowerShell or Command Prompt (running as Administrator is recommended if installing system-wide drivers).

**Step 2: Install Nmap**

Run the following command:

```powershell
winget install Insecure.Nmap
```

*(Package ID verified: `Insecure.Nmap` from the Windows Package Manager Community Repository, official Nmap Project distribution).*

**Step 3: Complete installation**

Wait for the installation to complete successfully. This installs Nmap into `C:\Program Files (x86)\Nmap\` and registers system PATH and Registry App Paths.

**Step 4: Restart NetSentinel AI**

Close and reopen NetSentinel AI (or click **Dependencies > Re-run Diagnostics**) so it can detect the newly installed Nmap engine.

**Step 5: Verify engine readiness**

Check the engine status badge on the dashboard.

Expected status:
```text
Nmap Engine: Ready (TCP Connect)
```

**Step 6: Run your first authorized scan**

1. Enter `127.0.0.1` or an authorized local network range (e.g. `192.168.1.0/24`).
2. Select the **Safe TCP Connect Scan** profile.
3. Confirm the target authorization checkbox.
4. Click **Start Discovery Scan**.
5. Review discovered hosts, open ports, and offline security observations.

#### Troubleshooting

If the engine still displays `Missing`:
1. Open the **Dependencies** diagnostics section in the application.
2. Click **Re-run Diagnostics**.
3. Verify that the Nmap installation completed successfully and that `nmap.exe` exists in `C:\Program Files (x86)\Nmap\`.
4. Restart NetSentinel AI.
5. Review the diagnostic message if the engine remains unavailable.

If the engine displays `Launch Error` or reports exit code `0xC0000135 (STATUS_DLL_NOT_FOUND)`:
Official 32-bit Nmap packages require the Microsoft Visual C++ 2013 (x86) runtime (`MSVCR120.dll`). Run:
```powershell
winget install Microsoft.VCRedist.2013.x86
```

#### Important Security & Operational Notes

- **Zero Silent Mutations**: NetSentinel AI will never silently download Nmap, install packet filter drivers, or alter your system configuration.
- **Privilege Separation**: Safe TCP Connect scanning operates with standard unprivileged user permissions. Advanced capabilities (raw SYN stealth scanning `-sS` and OS fingerprinting) require local Administrator privileges and an installed Npcap packet-capture driver.
- **Authorization Guardrail**: Never scan targets without explicit, documented authorization. Only scan systems you own or are legally authorized to assess.

---

### Method 2: Fully Portable Placement (No Installation / USB Drive)

To deploy NetSentinel AI with network scanning on portable media without modifying system settings or registry:
1. Download the official Nmap Windows portable archive from [nmap.org](https://nmap.org/dist/nmap-7.95-win32.zip).
2. Create a `bin\nmap\` folder adjacent to `NetSentinelAI.exe`.
3. Copy `nmap.exe` and `nmap-services` from the ZIP into `bin\nmap\`:
   ```text
   dist\
   ├── NetSentinelAI.exe
   └── bin\
       └── nmap\
           ├── nmap.exe
           └── nmap-services
   ```
4. Launch `NetSentinelAI.exe`; the engine badge will switch to `Nmap Engine: Ready (TCP Connect)`.

---

## Running Automated Tests

The test suite covers target security validation, SQLite database operations, configuration encryption, dependency detection, and offscreen headless UI rendering.

```powershell
.venv\Scripts\pytest.exe -v
```

---

## Packaging Portable Single-File Executable

To compile `dist/NetSentinelAI.exe` and execute automated health verification on the built binary:

```powershell
.venv\Scripts\python.exe scripts/build_exe.py
```

Or run PyInstaller directly:
```powershell
.venv\Scripts\pyinstaller.exe netsentinel.spec --noconfirm
```

Test the compiled single-file EXE:
```powershell
.\dist\NetSentinelAI.exe --health-check
.\dist\NetSentinelAI.exe --portable --health-check
```
<img width="1297" height="726" alt="image" src="https://github.com/user-attachments/assets/bc7d724f-19a0-4e91-aeea-a971e0ff4eed" />
