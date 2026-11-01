"""Unit tests for NetSentinel AI risk scoring engine."""

from __future__ import annotations

import pytest

from netsentinel.core.risk_engine import RiskCalculationResult, RiskEngine


def test_exposure_classification():
    # Loopback addresses (0.85)
    mult, label = RiskEngine.classify_exposure("127.0.0.1")
    assert mult == 0.85
    assert "Loopback" in label

    mult, _ = RiskEngine.classify_exposure("::1")
    assert mult == 0.85

    mult, _ = RiskEngine.classify_exposure("localhost")
    assert mult == 0.85

    # Private RFC1918 addresses (1.00)
    mult, label = RiskEngine.classify_exposure("192.168.1.1")
    assert mult == 1.00
    assert "Private" in label

    mult, _ = RiskEngine.classify_exposure("10.0.0.5")
    assert mult == 1.00

    mult, _ = RiskEngine.classify_exposure("172.16.50.2")
    assert mult == 1.00

    # Public IPv4 (1.15)
    mult, label = RiskEngine.classify_exposure("8.8.8.8")
    assert mult == 1.15
    assert "Public IPv4" in label

    mult, _ = RiskEngine.classify_exposure("1.1.1.1")
    assert mult == 1.15

    # Public IPv6 (1.15)
    mult, label = RiskEngine.classify_exposure("2001:4860:4860::8888")
    assert mult == 1.15
    assert "Public IPv6" in label

    # IPv6 ULA Unique Local Address (fc00::/7, fd00::/8) -> Private 1.00
    mult, label = RiskEngine.classify_exposure("fd12:3456:789a::1")
    assert mult == 1.00
    assert "Private" in label

    # IPv6 Link-Local (fe80::/10) -> Local 0.85
    mult, label = RiskEngine.classify_exposure("fe80::1ff:fe00:1")
    assert mult == 0.85
    assert "Link-Local" in label

    # IPv4 Link-Local (169.254.0.0/16) -> Local 0.85
    mult, label = RiskEngine.classify_exposure("169.254.100.5")
    assert mult == 0.85
    assert "Link-Local" in label

    # Multicast / Reserved -> Local 0.85
    mult, label = RiskEngine.classify_exposure("224.0.0.1")
    assert mult == 0.85

    # Unparseable hostname fallback (1.00)
    mult, label = RiskEngine.classify_exposure("myserver.corp.local")
    assert mult == 1.00
    assert "Private" in label or "Fallback" in label


def test_risk_score_calculation_formula():
    # Critical rule (90) * 1.0 confidence * 1.0 exposure = 90.0 (Critical tier)
    res = RiskEngine.calculate_score(
        rule_severity="Critical",
        confidence=1.0,
        target_ip_or_host="192.168.1.1",
        confidence_rationale="Banner Confirmed",
    )
    assert res.base_weight == 90.0
    assert res.confidence == 1.0
    assert res.exposure_multiplier == 1.00
    assert res.risk_score == 90.0
    assert res.risk_tier == "Critical"
    assert "Base: 90" in res.scoring_explanation

    # High rule (70) * 0.7 confidence (heuristic) * 1.0 exposure = 49.0 (Medium tier)
    # Notice: Rule severity remains High, while risk tier is Medium!
    res2 = RiskEngine.calculate_score(
        rule_severity="High",
        confidence=0.7,
        target_ip_or_host="192.168.1.1",
        confidence_rationale="Port Heuristic",
    )
    assert res2.rule_severity == "High"
    assert res2.risk_score == 49.0
    assert res2.risk_tier == "Medium"
    assert res2.rule_severity != res2.risk_tier

    # Public IP multiplier test: High (70) * 1.0 * 1.15 = 80.5 (High tier)
    res3 = RiskEngine.calculate_score(
        rule_severity="High",
        confidence=1.0,
        target_ip_or_host="8.8.8.8",
    )
    assert res3.risk_score == 80.5
    assert res3.risk_tier == "High"

    # Loopback reduction test: Medium (40) * 1.0 * 0.85 = 34.0 (Low tier)
    res4 = RiskEngine.calculate_score(
        rule_severity="Medium",
        confidence=1.0,
        target_ip_or_host="127.0.0.1",
    )
    assert res4.risk_score == 34.0
    assert res4.risk_tier == "Low"


def test_confidence_validation_and_clamping():
    # Confidence > 1.0 clamped to 1.0
    res_high = RiskEngine.calculate_score("Critical", 1.5, "192.168.1.1")
    assert res_high.confidence == 1.0
    assert res_high.risk_score == 90.0

    # Confidence < 0.1 clamped to 0.1
    res_low = RiskEngine.calculate_score("Critical", -0.5, "192.168.1.1")
    assert res_low.confidence == 0.1
    assert res_low.risk_score == 9.0
    assert res_low.risk_tier == "Info"


def test_score_capping_at_100():
    # Critical (90) * 1.0 * 1.15 (public) = 103.5 -> capped at 100.0
    res = RiskEngine.calculate_score("Critical", 1.0, "8.8.8.8")
    assert res.risk_score == 100.0
    assert res.risk_tier == "Critical"


def test_risk_tiers_mapping():
    assert RiskEngine.calculate_risk_tier(95.0) == "Critical"
    assert RiskEngine.calculate_risk_tier(85.0) == "Critical"
    assert RiskEngine.calculate_risk_tier(84.9) == "High"
    assert RiskEngine.calculate_risk_tier(65.0) == "High"
    assert RiskEngine.calculate_risk_tier(64.9) == "Medium"
    assert RiskEngine.calculate_risk_tier(35.0) == "Medium"
    assert RiskEngine.calculate_risk_tier(34.9) == "Low"
    assert RiskEngine.calculate_risk_tier(15.0) == "Low"
    assert RiskEngine.calculate_risk_tier(14.9) == "Info"
    assert RiskEngine.calculate_risk_tier(0.0) == "Info"
