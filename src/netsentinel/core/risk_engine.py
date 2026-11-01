"""Transparent, reproducible risk scoring engine for NetSentinel AI.

Calculates numerical risk scores (0.0 to 100.0) and assigns risk tiers based on
rule severity, confidence of evidence, and network exposure.

Formula:
    RiskScore = round(min(100.0, BaseSeverityWeight * Confidence * ExposureMultiplier), 1)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class RiskCalculationResult:
    """Detailed breakdown of a deterministic risk score calculation."""
    rule_severity: str
    base_weight: float
    confidence: float
    exposure_multiplier: float
    exposure_category: str
    risk_score: float
    risk_tier: str
    scoring_explanation: str


class RiskEngine:
    """Deterministic, transparent risk scoring engine."""

    # Base severity weights (0-100 specification)
    BASE_SEVERITY_WEIGHTS: Dict[str, float] = {
        "Critical": 90.0,
        "High": 70.0,
        "Medium": 40.0,
        "Low": 20.0,
        "Info": 5.0,
    }

    # Exposure multipliers
    EXPOSURE_PUBLIC: float = 1.15
    EXPOSURE_PRIVATE: float = 1.00
    EXPOSURE_LOOPBACK: float = 0.85

    # Score tier thresholds
    TIER_CRITICAL_MIN: float = 85.0
    TIER_HIGH_MIN: float = 65.0
    TIER_MEDIUM_MIN: float = 35.0
    TIER_LOW_MIN: float = 15.0

    @classmethod
    def classify_exposure(cls, target_ip_or_host: str) -> Tuple[float, str]:
        """Classifies network exposure for an IP address or hostname.

        Classification logic:
        - Loopback / Local addresses (127.0.0.0/8, ::1, localhost): 0.85
        - RFC1918 Private & Link-local IPv4/IPv6: 1.00
        - Validated Globally Routable Public IPs (IPv4/IPv6): 1.15
        - Non-parseable hostnames / unrecognized targets: Conservative fallback 1.00 (Private LAN)
        """
        raw = target_ip_or_host.strip().lower()
        if raw in ("localhost", "127.0.0.1", "::1"):
            return cls.EXPOSURE_LOOPBACK, "Loopback / Localhost"

        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            # Not a direct IP address (e.g. hostname like scanme.nmap.org or server.corp.local)
            # Conservative fallback: treat as standard private/internal network unless known
            if raw.endswith(".local") or raw.endswith(".lan") or raw.endswith(".internal"):
                return cls.EXPOSURE_PRIVATE, "Private Internal Hostname"
            # Unverified hostname fallback
            return cls.EXPOSURE_PRIVATE, "Unclassified Hostname (Default Private LAN)"

        if ip.is_loopback:
            return cls.EXPOSURE_LOOPBACK, "Loopback Address"
        if ip.is_link_local:
            return cls.EXPOSURE_LOOPBACK, "Link-Local Address"
        if ip.is_private:
            return cls.EXPOSURE_PRIVATE, "Private RFC1918 / ULA Network"
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return cls.EXPOSURE_LOOPBACK, "Special / Reserved Network"

        # Valid global public address
        if ip.is_global:
            label = "Public IPv4 Internet Address" if ip.version == 4 else "Public IPv6 Internet Address"
            return cls.EXPOSURE_PUBLIC, label

        # Fallback
        return cls.EXPOSURE_PRIVATE, "Standard Network (Fallback)"

    @classmethod
    def calculate_risk_tier(cls, score: float) -> str:
        """Assigns the risk tier category based on the numerical score (0.0 to 100.0).

        Tiers:
        - Critical: 85.0 – 100.0
        - High: 65.0 – 84.9
        - Medium: 35.0 – 64.9
        - Low: 15.0 – 34.9
        - Info: 0.0 – 14.9
        """
        if score >= cls.TIER_CRITICAL_MIN:
            return "Critical"
        if score >= cls.TIER_HIGH_MIN:
            return "High"
        if score >= cls.TIER_MEDIUM_MIN:
            return "Medium"
        if score >= cls.TIER_LOW_MIN:
            return "Low"
        return "Info"

    @classmethod
    def calculate_score(
        cls,
        rule_severity: str,
        confidence: float,
        target_ip_or_host: str,
        confidence_rationale: str = "",
    ) -> RiskCalculationResult:
        """Calculates numerical risk score and returns a transparent breakdown.

        Args:
            rule_severity: Rule severity ("Critical", "High", "Medium", "Low", "Info").
            confidence: Evidence strength (validated between 0.1 and 1.0).
            target_ip_or_host: Target address for exposure classification.
            confidence_rationale: Optional text explaining confidence rating.
        """
        # 1. Base weight
        normalized_sev = rule_severity.capitalize()
        base_weight = cls.BASE_SEVERITY_WEIGHTS.get(normalized_sev, 20.0)

        # 2. Validate and clamp confidence
        validated_confidence = max(0.1, min(1.0, float(confidence)))

        # 3. Classify exposure
        exposure_multiplier, exposure_category = cls.classify_exposure(target_ip_or_host)

        # 4. Compute risk score
        raw_score = base_weight * validated_confidence * exposure_multiplier
        risk_score = round(min(100.0, max(0.0, raw_score)), 1)

        # 5. Determine risk tier
        risk_tier = cls.calculate_risk_tier(risk_score)

        # 6. Compose scoring explanation
        conf_desc = f" ({confidence_rationale})" if confidence_rationale else ""
        scoring_explanation = (
            f"Base: {base_weight:.0f} ({normalized_sev}) × "
            f"Confidence: {validated_confidence:.2f}{conf_desc} × "
            f"Exposure: {exposure_multiplier:.2f} ({exposure_category}) = "
            f"{risk_score:.1f} / 100.0 [Risk Tier: {risk_tier}]"
        )

        return RiskCalculationResult(
            rule_severity=normalized_sev,
            base_weight=base_weight,
            confidence=validated_confidence,
            exposure_multiplier=exposure_multiplier,
            exposure_category=exposure_category,
            risk_score=risk_score,
            risk_tier=risk_tier,
            scoring_explanation=scoring_explanation,
        )
