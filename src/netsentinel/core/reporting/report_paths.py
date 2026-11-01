"""Safe report destination path resolver for NetSentinel AI.

Handles standard Windows Documents storage, portable mode relative paths,
safe directory creation, filename sanitization, Windows reserved names,
and write-permission verification without silent fallbacks.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from netsentinel.core.config import ConfigManager

# Reserved Windows DOS device names
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Invalid filename characters on Windows: < > : " / \ | ? * and control chars
INVALID_CHARS_REGEX = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class ReportPaths:
    """Manages report and export directory resolution, sanitization, and verification."""

    @classmethod
    def get_windows_documents_directory(cls) -> Path:
        """Resolves the user's personal Documents folder using Windows Shell API.
        
        Correctly resolves redirected folders and OneDrive-synced Documents on Windows 10/11.
        Falls back to Path.home() / 'Documents' on non-Windows or if Shell API fails.
        """
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes

                # CSIDL_PERSONAL = 0x0005 (My Documents folder)
                CSIDL_PERSONAL = 5
                SHGFP_TYPE_CURRENT = 0
                buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
                result = ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_PERSONAL, None, SHGFP_TYPE_CURRENT, buf)
                if result == 0 and buf.value:
                    return Path(buf.value)
            except Exception:
                pass

        return Path.home() / "Documents"

    @classmethod
    def get_default_reports_directory(cls, is_portable: Optional[bool] = None) -> Path:
        """Resolves the default reports directory based on application storage mode.
        
        Portable mode: <app_root>/reports/
        Standard mode: %USERPROFILE%/Documents/NetSentinel/Reports/ (via Windows Shell API)
        """
        if is_portable is None:
            # Auto-detect using existing ConfigManager conventions
            cfg_mgr = ConfigManager()
            is_portable = cfg_mgr.is_portable

        if is_portable:
            reports_dir = ConfigManager.get_app_root() / "reports"
        else:
            # Use User Documents / NetSentinel / Reports with Shell API
            user_docs = cls.get_windows_documents_directory()
            reports_dir = user_docs / "NetSentinel" / "Reports"

        cls.ensure_directory_writable(reports_dir)
        return reports_dir

    @classmethod
    def ensure_directory_writable(cls, target_dir: Path) -> None:
        """Creates target directory if missing and verifies write permissions.
        
        Raises PermissionError if directory cannot be created or is not writable.
        Never silently falls back to an unexpected location.
        """
        target_dir = Path(target_dir).resolve()
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise PermissionError(
                f"Failed to create report destination directory '{target_dir}': {e}"
            ) from e

        # Probe writability with a temporary test file
        test_file = target_dir / f".probe_write_test_{os.getpid()}_{datetime.now().strftime('%f')}"
        try:
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("probe")
            if test_file.exists():
                test_file.unlink(missing_ok=True)
        except Exception as e:
            raise PermissionError(
                f"Report destination directory '{target_dir}' is not writable: {e}"
            ) from e

    @classmethod
    def sanitize_filename(cls, name: str, fallback_prefix: str = "report") -> str:
        """Sanitizes a candidate filename string for Windows filesystem safety.
        
        - Replaces invalid Windows characters with underscores
        - Strips leading and trailing dots/spaces
        - Handles Windows reserved device names (CON, PRN, AUX, etc.)
        - Ensures result is non-empty
        """
        if not name or not name.strip():
            return fallback_prefix

        # Replace invalid Windows filename characters
        sanitized = INVALID_CHARS_REGEX.sub("_", name.strip())

        # Collapse multiple underscores
        sanitized = re.sub(r"_+", "_", sanitized)

        # Windows filenames cannot end in a period or space
        sanitized = sanitized.strip(". ")

        if not sanitized:
            sanitized = fallback_prefix

        # Check against Windows reserved device names
        stem = Path(sanitized).stem.upper()
        if stem in WINDOWS_RESERVED_NAMES:
            sanitized = f"NetSentinel_{sanitized}"

        return sanitized

    @classmethod
    def build_report_path(
        cls,
        target_input: str,
        extension: str,
        prefix: str = "NetSentinel_Report",
        directory: Optional[Path] = None,
        is_portable: Optional[bool] = None,
        timestamp: Optional[datetime] = None,
    ) -> Path:
        """Constructs a collision-resistant, sanitized export file path budgeted against Windows MAX_PATH (260).
        
        Format: <dir>/<prefix>_<SanitizedTarget>_<YYYYMMDD_HHMMSS>.<ext>
        If total path would exceed Windows MAX_PATH (260), dynamically hashes and budgets the target portion.
        If the file already exists, appends _1, _2, etc. while staying strictly within MAX_PATH.
        """
        dest_dir = directory or cls.get_default_reports_directory(is_portable=is_portable)
        dest_dir_str = str(Path(dest_dir).resolve())
        dir_len = len(dest_dir_str) + 1  # includes trailing separator
        max_path_allowed = 259  # Windows MAX_PATH (260) minus null terminator

        # Max filename length permitted by NTFS is 255, and bounded by MAX_PATH - dir_len
        max_filename_budget = min(255, max_path_allowed - dir_len)
        if max_filename_budget < 15:
            raise ValueError(
                f"Destination directory path is too deep for Windows MAX_PATH ({dir_len} characters): '{dest_dir}'. "
                f"Please choose a shallower destination directory."
            )

        cls.ensure_directory_writable(dest_dir)

        # Adaptively compress prefix if filename budget is tightly constrained
        effective_prefix = prefix
        if max_filename_budget < 45 and prefix.startswith("NetSentinel_"):
            effective_prefix = "NSR"

        ext = extension.lstrip(".")
        ts = (timestamp or datetime.now()).strftime("%Y%m%d_%H%M%S")
        sanitized_target = cls.sanitize_filename(target_input, fallback_prefix="audit")

        # Reserve collision suffix headroom (_99 -> 4 chars) and extension (.ext)
        collision_headroom = 4
        # Structure: <prefix>_<target>_<ts>.<ext>
        fixed_overhead = len(effective_prefix) + 1 + 1 + len(ts) + 1 + len(ext) + collision_headroom
        available_target_len = max_filename_budget - fixed_overhead

        if available_target_len < 4 and len(ts) > 8:
            # Fall back to compact 8-character timestamp (YYYYMMDD) to preserve target characters
            ts = ts[:8]
            fixed_overhead = len(effective_prefix) + 1 + 1 + len(ts) + 1 + len(ext) + collision_headroom
            available_target_len = max_filename_budget - fixed_overhead

        if len(sanitized_target) > available_target_len:
            # Calculate SHA-256 hash suffix of original target
            target_hash = hashlib.sha256(target_input.encode("utf-8")).hexdigest()[:8]
            if available_target_len > 12:
                keep_chars = max(4, available_target_len - 9)  # 8 chars hash + 1 underscore
                sanitized_target = f"{sanitized_target[:keep_chars]}_{target_hash}"
            elif available_target_len >= 8:
                sanitized_target = target_hash[:available_target_len]
            else:
                sanitized_target = "t"

        candidate_name = f"{effective_prefix}_{sanitized_target}_{ts}.{ext}"
        candidate_name = cls.sanitize_filename(candidate_name)

        target_path = dest_dir / candidate_name
        counter = 1
        base_stem = target_path.stem
        while target_path.exists():
            suffix = f"_{counter}"
            full_filename = f"{base_stem}{suffix}.{ext}"
            if len(dest_dir_str) + 1 + len(full_filename) > max_path_allowed:
                max_stem_len = max_path_allowed - (len(dest_dir_str) + 1 + len(suffix) + 1 + len(ext))
                candidate_stem = base_stem[:max(1, max_stem_len)]
            else:
                candidate_stem = base_stem
            target_path = dest_dir / f"{candidate_stem}{suffix}.{ext}"
            counter += 1

        return target_path
