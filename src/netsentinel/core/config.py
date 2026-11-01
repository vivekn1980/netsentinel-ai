"""Configuration and directory management for NetSentinel AI.

Handles standard Windows %LOCALAPPDATA% data storage, portable mode,
configuration persistence, and secure handling of sensitive settings.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

APP_NAME = "NetSentinel AI"
APP_DIR_NAME = "NetSentinelAI"
APP_VERSION = "0.1.0"
CONFIG_FILENAME = "config.json"
DATABASE_FILENAME = "netsentinel.db"


@dataclass
class AppConfig:
    """Application configuration options."""
    version: str = APP_VERSION
    theme: str = "light"
    default_scan_profile: str = "tcp_connect"
    max_concurrent_hosts: int = 16
    ping_timeout_ms: int = 500
    safe_target_whitelist: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
    require_scan_confirmation: bool = True
    ai_provider: str = "disabled"  # "disabled", "gemini", "openai", "anthropic"
    ai_model: str = "gemini-2.5-flash"
    ai_encrypted_key: str = ""  # DPAPI-encrypted base64 string, never plaintext
    auto_refresh_inventory: bool = True


class DPAPISecurity:
    """Windows Data Protection API (DPAPI) helper for encrypting sensitive credentials.
    
    Uses standard Windows crypt32.dll without external third-party dependencies.
    """

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    @classmethod
    def is_available(cls) -> bool:
        return sys.platform == "win32" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "crypt32")

    @classmethod
    def protect(cls, plaintext: str) -> str:
        """Encrypt a string using the current Windows user's credentials."""
        if not plaintext or not cls.is_available():
            return ""
        try:
            import base64
            crypt32 = ctypes.windll.crypt32
            data_bytes = plaintext.encode("utf-8")
            blob_in = cls.DATA_BLOB(len(data_bytes), ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)))
            blob_out = cls.DATA_BLOB()
            res = crypt32.CryptProtectData(
                ctypes.byref(blob_in),
                "NetSentinelAI_Credential",
                None,
                None,
                None,
                0x01,  # CRYPTPROTECT_UI_FORBIDDEN
                ctypes.byref(blob_out),
            )
            if not res:
                return ""
            out_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return base64.b64encode(out_bytes).decode("ascii")
        except Exception:
            return ""

    @classmethod
    def unprotect(cls, encrypted_b64: str) -> str:
        """Decrypt a DPAPI string for the current Windows user."""
        if not encrypted_b64 or not cls.is_available():
            return ""
        try:
            import base64
            crypt32 = ctypes.windll.crypt32
            raw_bytes = base64.b64decode(encrypted_b64.encode("ascii"))
            blob_in = cls.DATA_BLOB(len(raw_bytes), ctypes.cast(ctypes.create_string_buffer(raw_bytes), ctypes.POINTER(ctypes.c_byte)))
            blob_out = cls.DATA_BLOB()
            res = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                0x01,  # CRYPTPROTECT_UI_FORBIDDEN
                ctypes.byref(blob_out),
            )
            if not res:
                return ""
            out_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return out_bytes.decode("utf-8")
        except Exception:
            return ""


class ConfigManager:
    """Manages application paths, configuration loading, persistence, and storage mode."""

    def __init__(self, portable_requested: bool = False, explicit_data_dir: Optional[Path] = None):
        self._portable_requested = portable_requested
        self._explicit_data_dir = explicit_data_dir
        self._data_dir: Path = self._determine_data_dir()
        self._config_file = self._data_dir / CONFIG_FILENAME
        self._db_file = self._data_dir / DATABASE_FILENAME
        self._logs_dir = self._data_dir / "logs"
        self._config = AppConfig()
        self.load()

    @staticmethod
    def get_app_root() -> Path:
        """Returns the directory containing the running executable or script."""
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent.parent.parent.parent

    @staticmethod
    def get_bundle_dir() -> Path:
        """Returns PyInstaller extraction directory (_MEIPASS) or source root."""
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            return Path(sys._MEIPASS).resolve()
        return Path(__file__).resolve().parent.parent.parent.parent

    def _determine_data_dir(self) -> Path:
        """Resolves the writable storage directory with strict portable handling."""
        if self._explicit_data_dir is not None:
            target = Path(self._explicit_data_dir).resolve()
            self._ensure_writable_directory(target, "Custom data directory")
            self._is_portable = False
            return target

        app_root = self.get_app_root()
        portable_flag_file = app_root / "portable.flag"
        adjacent_data_dir = app_root / "data"

        # Explicit portable request or presence of portable indicator
        if self._portable_requested or portable_flag_file.exists() or adjacent_data_dir.is_dir():
            target = adjacent_data_dir
            try:
                self._ensure_writable_directory(target, "Portable data directory")
                self._is_portable = True
                return target
            except Exception as e:
                if self._portable_requested:
                    # Do not silently fall back to non-portable location when portable mode was explicitly requested!
                    raise PermissionError(
                        f"Portable mode was explicitly requested, but portable directory '{target}' "
                        f"cannot be used: {e}"
                    ) from e
                # If only auto-detected via flag/folder and failed, fall through to AppData

        # Standard Windows %LOCALAPPDATA% location
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            base_dir = Path(local_app_data)
        else:
            base_dir = Path.home() / "AppData" / "Local"

        target = base_dir / APP_DIR_NAME
        self._ensure_writable_directory(target, "Standard AppData directory")
        self._is_portable = False
        return target

    def _ensure_writable_directory(self, path: Path, description: str) -> None:
        """Ensures the directory exists and is writable."""
        path.mkdir(parents=True, exist_ok=True)
        test_file = path / ".write_test.tmp"
        try:
            test_file.write_text("test", encoding="utf-8")
            test_file.unlink(missing_ok=True)
        except Exception as e:
            raise PermissionError(f"{description} at '{path}' is not writable: {e}") from e

    @property
    def is_portable(self) -> bool:
        """Returns True if the application is running in portable storage mode."""
        return self._is_portable

    @property
    def storage_mode_label(self) -> str:
        """Human-readable description of current storage mode."""
        if self._is_portable:
            return "Portable Mode (Local Directory)"
        return "Standard Mode (Windows %LOCALAPPDATA%)"

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def config_file(self) -> Path:
        return self._config_file

    @property
    def db_file(self) -> Path:
        return self._db_file

    @property
    def logs_dir(self) -> Path:
        self._logs_dir.mkdir(parents=True, exist_ok=True)
        return self._logs_dir

    @property
    def config(self) -> AppConfig:
        return self._config

    def load(self) -> AppConfig:
        """Load configuration from JSON file or create defaults."""
        if self._config_file.exists():
            try:
                data = json.loads(self._config_file.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if hasattr(self._config, k):
                        setattr(self._config, k, v)
            except Exception:
                # Corrupt or unreadable config, preserve safe defaults
                pass
        return self._config

    def save(self) -> None:
        """Persist current configuration to JSON file."""
        try:
            data = asdict(self._config)
            self._config_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            raise IOError(f"Failed to save configuration to '{self._config_file}': {e}") from e

    def set_ai_key(self, api_key: str) -> None:
        """Securely store AI key using DPAPI encryption. Never saves plaintext."""
        if not api_key:
            self._config.ai_encrypted_key = ""
        else:
            encrypted = DPAPISecurity.protect(api_key)
            self._config.ai_encrypted_key = encrypted
        self.save()

    def get_ai_key(self) -> str:
        """Decrypts and returns the AI key in memory."""
        if not self._config.ai_encrypted_key:
            return ""
        return DPAPISecurity.unprotect(self._config.ai_encrypted_key)

    def has_ai_key(self) -> bool:
        """Returns True if an encrypted AI key is configured."""
        return bool(self._config.ai_encrypted_key)
