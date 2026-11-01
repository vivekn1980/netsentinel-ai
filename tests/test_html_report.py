"""Unit tests for offline HTML report generator, escaping, and completeness banners."""

from __future__ import annotations

import re
from pathlib import Path
import pytest

from netsentinel.core.models import (
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_FAILED,
    ScanSession,
    SecurityFinding,
    STATUS_OPEN,
)
from netsentinel.core.reporting.html_report import HtmlReportGenerator


def test_html_report_zero_external_resources():
    session = ScanSession(
        id=1,
        target_input="192.168.1.1",
        profile="tcp_connect",
        status="completed",
        hosts_discovered=1,
        ports_found=2,
    )
    finding = SecurityFinding(
        id=1,
        asset_id=1,
        rule_id="RULE-EXP-TELNET",
        title="Telnet service exposed",
        description="Cleartext protocol",
        recommendation="Use SSH",
        severity="High",
        risk_score=70.0,
        risk_tier="High",
        status=STATUS_OPEN,
        port_number=23,
    )

    html_content = HtmlReportGenerator.generate_report([finding], session=session)

    # Strictly verify NO external HTTP or HTTPS URLs (fonts, CDN, analytics, images)
    # Search for http:// or https:// anywhere in the document
    urls = re.findall(r'https?://[^\s"\'<>]+', html_content)
    assert urls == [], f"Found forbidden external network URLs in HTML report: {urls}"

    # Verify presence of inline CSS and inline SVG
    assert "<style>" in html_content
    assert "<svg" in html_content
    assert "</svg>" in html_content


def test_html_escaping_prevents_xss():
    # Construct finding with malicious payload injection attempts
    malicious_finding = SecurityFinding(
        id=2,
        asset_id=1,
        rule_id="RULE-EXP-HTTP-CLEAR",
        title='Malicious <script>alert("xss")</script> Title',
        description='Description with <img src=x onerror=alert(1)> and "quotes"',
        recommendation='Recommendation with <iframe src="evil.com"></iframe>',
        severity="Medium",
        risk_score=36.0,
        risk_tier="Medium",
        status=STATUS_OPEN,
        port_number=80,
        evidence='Banner: <script>document.cookie="stolen"</script>',
        user_notes='Operator note with <b onmouseover="calc()">hover me</b>',
        ip_address='192.168.1.100<script>',
        hostname='evil-server.local"><script>alert(2)</script>',
    )

    html_content = HtmlReportGenerator.generate_report([malicious_finding])

    # Unescaped script, img, or iframe tags must NEVER appear in the HTML
    assert "<script>" not in html_content
    assert "</script>" not in html_content
    assert "<img" not in html_content
    assert "<iframe" not in html_content
    assert "<b onmouseover" not in html_content

    # Escaped representations must be present
    assert "&lt;script&gt;" in html_content
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_content


def test_html_report_completeness_banners():
    finding = SecurityFinding(
        id=3,
        asset_id=1,
        rule_id="RULE-EXP-SSH",
        title="SSH exposed",
        description="",
        recommendation="",
        severity="Low",
        risk_score=15.0,
        risk_tier="Low",
        status=STATUS_OPEN,
    )

    # 1. Cancelled scan session
    session_cancelled = ScanSession(
        id=5,
        target_input="10.0.0.1",
        status="cancelled",
        hosts_discovered=1,
    )
    html_cancelled = HtmlReportGenerator.generate_report([finding], session=session_cancelled)
    assert "Partial / Inconclusive Scan Assessment (Cancelled)" in html_cancelled
    assert "Scan was cancelled by the user" in html_cancelled

    # 2. Failed scan session
    session_failed = ScanSession(
        id=6,
        target_input="10.0.0.1",
        status="failed",
        error_message="Host network interface down",
    )
    html_failed = HtmlReportGenerator.generate_report([finding], session=session_failed)
    assert "Partial / Inconclusive Scan Assessment (Failed)" in html_failed
    assert "Host network interface down" in html_failed

    # 3. Completed scan session
    session_ok = ScanSession(
        id=7,
        target_input="10.0.0.1",
        status="completed",
        hosts_discovered=1,
        ports_found=1,
        configured_ports="22",
    )
    html_ok = HtmlReportGenerator.generate_report([finding], session=session_ok)
    assert "Assessment Status: Completed for configured scope" in html_ok
    assert "Partial / Inconclusive" not in html_ok
