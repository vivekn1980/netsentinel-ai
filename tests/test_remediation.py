"""Unit tests for defensive remediation guidance and standards references."""

from __future__ import annotations

import pytest

from netsentinel.core.remediation import RemediationProvider


def test_remediation_guidance_all_rules():
    rule_ids = [
        "RULE-EXP-TELNET",
        "RULE-EXP-FTP",
        "RULE-EXP-HTTP-CLEAR",
        "RULE-EXP-SMB",
        "RULE-EXP-RDP",
        "RULE-EXP-SSH",
        "RULE-EXP-DB",
        "RULE-EXP-ADMIN",
        "RULE-OBS-BROAD-PORTS",
        "RULE-OBS-UNKNOWN-SERVICE",
        "RULE-OBS-LEGACY-VERSION",
    ]

    for rid in rule_ids:
        guidance = RemediationProvider.get_remediation(rid)
        assert guidance is not None
        assert len(guidance.summary) > 20
        assert len(guidance.steps) >= 2
        assert len(guidance.standards_references) >= 1
        assert len(guidance.verification_advice) > 10

        text = guidance.formatted_text()
        assert "Recommended Defensive Actions:" in text
        assert "Standards & Hardening References:" in text
        assert "Verification:" in text


def test_remediation_safety_constraint():
    """Ensure remediation text never contains dangerous automatic commands."""
    guidance = RemediationProvider.get_remediation("RULE-EXP-TELNET")
    text = guidance.formatted_text().lower()

    # Must be advisory only
    assert "confirm whether" in text or "assess" in text or "review" in text or "migrate" in text
    # Should reference standard authorities
    assert "cis controls" in text or "nist" in text
