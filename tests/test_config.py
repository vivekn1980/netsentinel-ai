"""Tests for ConfigManager and DPAPISecurity."""

import json
from pathlib import Path
import pytest

from netsentinel.core.config import ConfigManager, DPAPISecurity, AppConfig


def test_config_explicit_data_dir(tmp_path: Path):
    """Test using an explicit custom data directory."""
    custom_dir = tmp_path / "custom_data"
    mgr = ConfigManager(explicit_data_dir=custom_dir)
    assert mgr.data_dir == custom_dir
    assert mgr.is_portable is False
    assert mgr.db_file == custom_dir / "netsentinel.db"
    assert mgr.config_file == custom_dir / "config.json"
    assert custom_dir.is_dir()


def test_config_save_and_load(tmp_path: Path):
    """Test saving and loading configuration options."""
    mgr = ConfigManager(explicit_data_dir=tmp_path)
    mgr.config.default_scan_profile = "service_detect"
    mgr.config.max_concurrent_hosts = 32
    mgr.save()

    # Verify file was written
    assert mgr.config_file.exists()
    content = json.loads(mgr.config_file.read_text(encoding="utf-8"))
    assert content["default_scan_profile"] == "service_detect"
    assert content["max_concurrent_hosts"] == 32

    # Load with a new manager instance
    mgr2 = ConfigManager(explicit_data_dir=tmp_path)
    assert mgr2.config.default_scan_profile == "service_detect"
    assert mgr2.config.max_concurrent_hosts == 32


def test_dpapi_encryption():
    """Test DPAPI encryption and decryption on Windows."""
    if not DPAPISecurity.is_available():
        pytest.skip("DPAPI not available on non-Windows test runners")

    secret = "AI_KEY_TEST_SECRET_VALUE_12345"
    protected = DPAPISecurity.protect(secret)
    assert protected != ""
    assert protected != secret  # Must be encrypted

    unprotected = DPAPISecurity.unprotect(protected)
    assert unprotected == secret


def test_secure_ai_key_storage(tmp_path: Path):
    """Test that ConfigManager encrypts AI keys and never saves plaintext in config.json."""
    mgr = ConfigManager(explicit_data_dir=tmp_path)
    raw_key = "test_super_secret_api_key_xyz"

    mgr.set_ai_key(raw_key)

    # Inspect config file directly to ensure raw key is NOT present
    raw_json = mgr.config_file.read_text(encoding="utf-8")
    assert raw_key not in raw_json, "Plaintext API key must NEVER be written to config.json"

    if DPAPISecurity.is_available():
        assert mgr.has_ai_key() is True
        decrypted = mgr.get_ai_key()
        assert decrypted == raw_key
