"""Unit tests for ReportPaths resolution, Windows sanitization, and writability checks."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from netsentinel.core.reporting.report_paths import ReportPaths, WINDOWS_RESERVED_NAMES


def test_sanitize_filename_invalid_characters():
    dirty = 'test<file>:name"with/slashes\\and|pipes?and*stars.html'
    clean = ReportPaths.sanitize_filename(dirty)
    assert "<" not in clean
    assert ">" not in clean
    assert ":" not in clean
    assert '"' not in clean
    assert "/" not in clean
    assert "\\" not in clean
    assert "|" not in clean
    assert "?" not in clean
    assert "*" not in clean
    assert clean.endswith(".html")


def test_sanitize_filename_reserved_windows_names():
    for reserved in ["CON", "prn", "Aux", "nul", "COM1", "lpt9"]:
        clean = ReportPaths.sanitize_filename(f"{reserved}.html")
        assert not clean.upper().startswith(f"{reserved.upper()}.")
        assert "NetSentinel_" in clean


def test_sanitize_filename_empty_and_whitespace():
    assert ReportPaths.sanitize_filename("") == "report"
    assert ReportPaths.sanitize_filename("   ") == "report"
    assert ReportPaths.sanitize_filename("...   ") == "report"


def test_collision_avoidance(tmp_path: Path):
    from datetime import datetime
    fixed_ts = datetime(2026, 1, 1, 12, 0, 0)
    target = "192.168.1.1"
    # Generate initial file
    path1 = ReportPaths.build_report_path(target, "html", directory=tmp_path, timestamp=fixed_ts)
    path1.touch()

    # Generate next file with same target, directory, and timestamp to trigger collision
    path2 = ReportPaths.build_report_path(target, "html", directory=tmp_path, timestamp=fixed_ts)
    assert path2 != path1
    assert path2.name.endswith(".html")
    assert "_1.html" in path2.name


def test_portable_vs_standard_destination_resolution(tmp_path: Path):
    # Test explicit portable resolution
    port_dir = ReportPaths.get_default_reports_directory(is_portable=True)
    assert port_dir.name == "reports"
    assert port_dir.is_dir()

    # Test explicit standard resolution
    std_dir = ReportPaths.get_default_reports_directory(is_portable=False)
    assert "NetSentinel" in str(std_dir)
    assert std_dir.name == "Reports"
    assert std_dir.is_dir()


def test_unwritable_directory_raises_permission_error(tmp_path: Path, monkeypatch):
    # Mock open to simulate read-only / permission denied
    def mock_open_raise(*args, **kwargs):
        raise OSError("Access is denied")

    monkeypatch.setattr("builtins.open", mock_open_raise)

    with pytest.raises(PermissionError) as exc_info:
        ReportPaths.ensure_directory_writable(tmp_path)
    assert "not writable" in str(exc_info.value)


def test_windows_documents_directory_resolution():
    """Verifies that get_windows_documents_directory returns a valid Path."""
    docs = ReportPaths.get_windows_documents_directory()
    assert isinstance(docs, Path)
    assert "Documents" in str(docs)


def test_windows_documents_directory_fallback(monkeypatch):
    """Verifies fallback to Path.home() / 'Documents' when shell API fails."""
    import ctypes
    # Simulate shell API failure (non-zero return code)
    monkeypatch.setattr(ctypes.windll.shell32, "SHGetFolderPathW", lambda *args: 1)
    docs = ReportPaths.get_windows_documents_directory()
    assert docs == Path.home() / "Documents"


def test_build_report_path_max_path_dynamic_budgeting_long_target(tmp_path: Path):
    """Verifies that a 250-character target input is budgeted with SHA-256 hash without exceeding MAX_PATH."""
    long_target = "subdomain." + "verylongorganizationdomainname" * 8 + ".internal.network.example.org"
    assert len(long_target) > 200

    report_path = ReportPaths.build_report_path(
        target_input=long_target,
        extension="html",
        directory=tmp_path,
    )

    path_str = str(report_path.resolve())
    # Strictly enforce Windows MAX_PATH constraint (<= 259 characters)
    assert len(path_str) <= 259
    assert report_path.name.endswith(".html")
    # Verify that SHA-256 hash suffix is present in the filename
    stem = report_path.stem
    parts = stem.split("_")
    # The hash is an 8-char hex string
    assert len(parts[-2]) == 8 or any(len(p) == 8 for p in parts)


def test_build_report_path_deep_directory(tmp_path: Path):
    """Verifies that a deeply nested directory path dynamically budgets the filename to stay <= 259."""
    # Create a deep path (e.g. 150+ chars)
    deep_dir = tmp_path
    for segment in ["a" * 20, "b" * 20, "c" * 20, "d" * 20, "e" * 20]:
        deep_dir = deep_dir / segment
    deep_dir.mkdir(parents=True, exist_ok=True)

    report_path = ReportPaths.build_report_path(
        target_input="192.168.1.100",
        extension="json",
        directory=deep_dir,
    )

    path_str = str(report_path.resolve())
    assert len(path_str) <= 259
    assert report_path.name.endswith(".json")


def test_build_report_path_repeated_collision_under_max_path(tmp_path: Path):
    """Verifies that multiple collision suffixes do not push the path over MAX_PATH."""
    from datetime import datetime
    fixed_ts = datetime(2026, 1, 1, 12, 0, 0)
    target = "test-collision-target"
    path1 = ReportPaths.build_report_path(target, "csv", directory=tmp_path, timestamp=fixed_ts)
    path1.touch()
    path2 = ReportPaths.build_report_path(target, "csv", directory=tmp_path, timestamp=fixed_ts)
    path2.touch()
    path3 = ReportPaths.build_report_path(target, "csv", directory=tmp_path, timestamp=fixed_ts)
    path3.touch()

    assert len(str(path3.resolve())) <= 259
    assert "_2.csv" in path3.name


def test_build_report_path_overly_deep_directory_raises_value_error(tmp_path: Path):
    """Verifies that an excessively deep directory (leaving < 15 chars for filename) raises a clean ValueError."""
    # Build an ultra-deep directory path exceeding 246 characters
    ultra_deep = tmp_path
    for segment in ["nest_" + "x" * 25 for _ in range(8)]:
        ultra_deep = ultra_deep / segment

    with pytest.raises(ValueError, match="Destination directory path is too deep for Windows MAX_PATH"):
        ReportPaths.build_report_path(
            target_input="192.168.1.1",
            extension="pdf",
            directory=ultra_deep,
        )


def test_build_report_path_adaptive_prefix_compression(tmp_path: Path):
    """Verifies that when filename budget is between 15 and 45 chars, prefix is compressed to NSR_."""
    # Create directory that leaves ~35 characters for filename
    # max_path_allowed = 259; dir_len around 225
    cur_len = len(str(tmp_path.resolve()))
    target_dir_len = 224
    needed_len = max(1, target_dir_len - cur_len - 1)
    tight_dir = tmp_path / ("d" * needed_len)
    tight_dir.mkdir(parents=True, exist_ok=True)

    report_path = ReportPaths.build_report_path(
        target_input="10.0.0.1",
        extension="html",
        directory=tight_dir,
    )

    assert len(str(report_path.resolve())) <= 259
    assert report_path.name.startswith("NSR_")


def test_build_report_path_unicode_targets(tmp_path: Path):
    """Verifies that Unicode targets (e.g. Cyrillic, accented) are handled safely without corruption."""
    unicode_target = "тест-сервер.локал"
    path = ReportPaths.build_report_path(unicode_target, "html", directory=tmp_path)
    assert path.name.endswith(".html")
    assert len(str(path.resolve())) <= 259
    # Touch file to prove Windows NTFS handles it seamlessly
    path.touch()
    assert path.exists()

