"""Standalone, 100% offline HTML security assessment report generator.

Produces self-contained single-file HTML5 reports with inline CSS, inline SVG charts,
print styling, HTML-escaped dynamic values, and transparent scan completeness banners.
Zero external CDNs, remote fonts, or network requests are used.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from netsentinel.core.config import APP_VERSION
from netsentinel.core.models import (
    ASSESSMENT_STATUS_CANCELLED,
    ASSESSMENT_STATUS_COMPLETED,
    ASSESSMENT_STATUS_FAILED,
    ASSESSMENT_STATUS_INCONCLUSIVE,
    ASSESSMENT_STATUS_PARTIAL,
    ScanComparisonResult,
    ScanSession,
    SecurityFinding,
    STATUS_ACKNOWLEDGED,
    STATUS_FALSE_POSITIVE,
    STATUS_RESOLVED,
)
from netsentinel.core.remediation import RemediationProvider
from netsentinel.core.reporting.diff_engine import DiffEngine

SEVERITY_COLORS = {
    "Critical": {"bg": "#FEF2F2", "text": "#991B1B", "border": "#FCA5A5", "bar": "#EF4444"},
    "High": {"bg": "#FFF7ED", "text": "#C2410C", "border": "#FDBA74", "bar": "#F97316"},
    "Medium": {"bg": "#FFFBEB", "text": "#B45309", "border": "#FDE68A", "bar": "#F59E0B"},
    "Low": {"bg": "#EFF6FF", "text": "#1D4ED8", "border": "#BFDBFE", "bar": "#3B82F6"},
    "Info": {"bg": "#F8FAFC", "text": "#475569", "border": "#CBD5E1", "bar": "#94A3B8"},
}


class HtmlReportGenerator:
    """Generates self-contained, offline HTML security audit reports."""

    @classmethod
    def generate_report(
        cls,
        findings: List[SecurityFinding],
        session: Optional[ScanSession] = None,
        comparison_result: Optional[ScanComparisonResult] = None,
        output_file: Optional[Union[str, Path]] = None,
        include_resolved: bool = True,
        asset_details_map: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> str:
        """Renders an executive security report as a standalone HTML document."""
        asset_map = asset_details_map or {}

        # Filter findings based on user preference
        if not include_resolved:
            display_findings = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]
        else:
            display_findings = list(findings)

        # Sort findings: Risk Score descending, then severity rank
        sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        display_findings.sort(
            key=lambda x: (x.risk_score, sev_rank.get(x.severity, 0)),
            reverse=True,
        )

        # Completeness evaluation
        if session:
            completeness, has_limitations, limitation_notice = DiffEngine.evaluate_completeness(session)
        else:
            completeness = ASSESSMENT_STATUS_COMPLETED
            has_limitations = False
            limitation_notice = "Findings aggregated across multiple scan sessions."

        # Risk metrics calculations
        active = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]
        scores = [f.risk_score for f in active]
        max_score = max(scores) if scores else 0.0
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        tier_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in active:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            tier_counts[f.risk_tier] = tier_counts.get(f.risk_tier, 0) + 1

        # Max risk tier determination
        if max_score >= 85.0:
            overall_tier = "Critical"
        elif max_score >= 65.0:
            overall_tier = "High"
        elif max_score >= 35.0:
            overall_tier = "Medium"
        elif max_score >= 15.0:
            overall_tier = "Low"
        else:
            overall_tier = "Info" if active else "None"

        # Generate HTML components
        css = cls._render_inline_css()
        header = cls._render_header(session)
        banner = cls._render_completeness_banner(completeness, has_limitations, limitation_notice)
        kpi_cards = cls._render_kpi_cards(session, len(active), len(findings), max_score, avg_score, overall_tier)
        charts_svg = cls._render_svg_charts(sev_counts, max_score, overall_tier)
        diff_section = cls._render_comparison_section(comparison_result) if comparison_result else ""
        findings_table = cls._render_findings_table(display_findings, asset_map)
        remediation_section = cls._render_remediation_summary(display_findings)
        appendix = cls._render_metadata_appendix(session)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetSentinel AI — Security Assessment Report</title>
  <style>
{css}
  </style>
</head>
<body>
  <div class="report-container">
    {header}
    {banner}
    {kpi_cards}
    {charts_svg}
    {diff_section}
    {findings_table}
    {remediation_section}
    {appendix}
    <footer class="report-footer">
      <p>Generated entirely offline by <strong>NetSentinel AI v{html.escape(APP_VERSION)}</strong> &bull; Zero external network telemetry &bull; Confidential Security Audit</p>
    </footer>
  </div>
</body>
</html>
"""

        if output_file:
            target_path = Path(output_file).resolve()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(html_doc)

        return html_doc

    @classmethod
    def _render_inline_css(cls) -> str:
        return """
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px 16px;
      background-color: #F8FAFC;
      color: #0F172A;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .report-container {
      max-width: 1040px;
      margin: 0 auto;
      background: #FFFFFF;
      border: 1px solid #E2E8F0;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
      padding: 36px 40px;
    }
    header {
      border-bottom: 2px solid #E2E8F0;
      padding-bottom: 24px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }
    .logo-badge {
      display: inline-block;
      background: #0F172A;
      color: #38BDF8;
      font-weight: 800;
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 4px;
      margin-bottom: 8px;
    }
    h1 { margin: 0 0 6px 0; font-size: 24px; font-weight: 700; color: #0F172A; }
    .subtitle { margin: 0; font-size: 13px; color: #64748B; }
    .meta-box { text-align: right; font-size: 12px; color: #64748B; }
    .meta-box strong { color: #0F172A; }
    
    /* Completeness Alerts */
    .alert-banner {
      padding: 14px 18px;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 13px;
    }
    .alert-warning {
      background-color: #FFFBEB;
      border: 1px solid #FCD34D;
      color: #92400E;
    }
    .alert-danger {
      background-color: #FEF2F2;
      border: 1px solid #FCA5A5;
      color: #991B1B;
    }
    .alert-info {
      background-color: #F0FDF4;
      border: 1px solid #BBF7D0;
      color: #166534;
    }
    .alert-banner strong { display: block; font-size: 14px; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .kpi-card {
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 8px;
      padding: 16px 20px;
      text-align: center;
    }
    .kpi-title { font-size: 11px; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
    .kpi-value { font-size: 26px; font-weight: 800; color: #0F172A; margin-bottom: 4px; }
    .kpi-sub { font-size: 11px; color: #94A3B8; }

    /* Visual Charts Bar */
    .charts-row {
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      margin-bottom: 32px;
      background: #F8FAFC;
      border: 1px solid #E2E8F0;
      border-radius: 8px;
      padding: 20px;
    }
    .chart-box { flex: 1; min-width: 280px; }
    .chart-title { font-size: 13px; font-weight: 700; color: #334155; margin-bottom: 12px; }

    /* Tables */
    h2 { font-size: 18px; font-weight: 700; color: #0F172A; margin: 32px 0 16px 0; border-bottom: 1px solid #E2E8F0; padding-bottom: 8px; }
    .table-wrapper { overflow-x: auto; margin-bottom: 28px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
    th { background: #F1F5F9; color: #475569; font-weight: 700; padding: 10px 12px; border-bottom: 2px solid #CBD5E1; }
    td { padding: 12px; border-bottom: 1px solid #E2E8F0; vertical-align: top; }
    tr:nth-child(even) td { background-color: #FAFAFA; }
    tr:hover td { background-color: #F1F5F9; }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      border: 1px solid transparent;
    }
    .badge-critical { background: #FEF2F2; color: #991B1B; border-color: #FCA5A5; }
    .badge-high { background: #FFF7ED; color: #C2410C; border-color: #FDBA74; }
    .badge-medium { background: #FFFBEB; color: #B45309; border-color: #FDE68A; }
    .badge-low { background: #EFF6FF; color: #1D4ED8; border-color: #BFDBFE; }
    .badge-info { background: #F8FAFC; color: #475569; border-color: #CBD5E1; }
    .badge-resolved { background: #ECFDF5; color: #059669; border-color: #A7F3D0; }
    .badge-ack { background: #F1F5F9; color: #475569; border-color: #CBD5E1; }
    .badge-fp { background: #FAF5FF; color: #7E22CE; border-color: #E9D5FF; }

    .evidence-block {
      background: #0F172A;
      color: #E2E8F0;
      font-family: Consolas, monospace;
      font-size: 11px;
      padding: 8px 12px;
      border-radius: 4px;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 6px;
    }
    .remediation-block {
      background: #F0FDF4;
      border-left: 3px solid #10B981;
      padding: 8px 12px;
      font-size: 12px;
      color: #065F46;
      margin-top: 6px;
    }
    .ref-tag {
      display: inline-block;
      background: #E2E8F0;
      color: #334155;
      font-size: 10px;
      padding: 1px 6px;
      border-radius: 3px;
      margin-right: 4px;
      margin-top: 4px;
    }
    .report-footer {
      border-top: 1px solid #E2E8F0;
      margin-top: 40px;
      padding-top: 20px;
      font-size: 11px;
      color: #94A3B8;
      text-align: center;
    }

    @media print {
      body { background: #FFFFFF; padding: 0; }
      .report-container { border: none; box-shadow: none; padding: 0; max-width: 100%; }
      tr { page-break-inside: avoid; }
      .evidence-block { background: #F1F5F9; color: #0F172A; border: 1px solid #CBD5E1; }
    }
"""

    @classmethod
    def _render_header(cls, session: Optional[ScanSession]) -> str:
        target = session.target_input if session else "Multi-Target Scope"
        scan_id = f"Session #{session.id}" if session and session.id else "Consolidated Audit"
        start_time = session.start_time.replace("T", " ") if session else datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""
    <header>
      <div>
        <span class="logo-badge">NetSentinel AI &bull; Security Audit</span>
        <h1>Security Assessment Report</h1>
        <p class="subtitle">Target Scope: <strong>{html.escape(target)}</strong> &bull; {html.escape(scan_id)}</p>
      </div>
      <div class="meta-box">
        <div>Generated: <strong>{html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</strong></div>
        <div>Scan Timestamp: <strong>{html.escape(start_time)}</strong></div>
        <div>Mode: <strong>100% Offline / Standalone</strong></div>
      </div>
    </header>
"""

    @classmethod
    def _render_completeness_banner(cls, completeness: str, has_limitations: bool, notice: str) -> str:
        if completeness == ASSESSMENT_STATUS_COMPLETED and not has_limitations:
            return f"""
    <div class="alert-banner alert-info">
      <strong>Assessment Status: {html.escape(completeness)}</strong>
      <p>{html.escape(notice)} <em>Notice: Unexamined ports, non-probed UDP protocols, and firewalled services are unassessed and cannot be deemed secure.</em></p>
    </div>
"""

        alert_class = "alert-danger" if completeness in (ASSESSMENT_STATUS_FAILED, ASSESSMENT_STATUS_CANCELLED) else "alert-warning"
        return f"""
    <div class="alert-banner {alert_class}">
      <strong>Partial / Inconclusive Scan Assessment ({html.escape(completeness)})</strong>
      <p>{html.escape(notice)}</p>
      <p><strong>Limitation:</strong> Findings in this report represent partial observations only and must not be considered a comprehensive or exhaustive security verification.</p>
    </div>
"""

    @classmethod
    def _render_kpi_cards(
        cls,
        session: Optional[ScanSession],
        active_count: int,
        total_count: int,
        max_score: float,
        avg_score: float,
        overall_tier: str,
    ) -> str:
        hosts_str = str(session.hosts_discovered) if session else "—"
        ports_str = str(session.ports_found) if session else "—"
        dur_str = f"{session.duration_seconds:.1f}s" if session and session.duration_seconds > 0 else "—"

        return f"""
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Discovered Hosts</div>
        <div class="kpi-value">{html.escape(hosts_str)}</div>
        <div class="kpi-sub">Duration: {html.escape(dur_str)}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Open Services</div>
        <div class="kpi-value">{html.escape(ports_str)}</div>
        <div class="kpi-sub">Active Listeners</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Active Risk Observations</div>
        <div class="kpi-value">{active_count}</div>
        <div class="kpi-sub">{total_count} total recorded</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Max Risk Score</div>
        <div class="kpi-value">{max_score:.1f}</div>
        <div class="kpi-sub">Tier: <strong>{html.escape(overall_tier)}</strong></div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Average Risk Score</div>
        <div class="kpi-value">{avg_score:.1f}</div>
        <div class="kpi-sub">Across active findings</div>
      </div>
    </div>
"""

    @classmethod
    def _render_svg_charts(cls, sev_counts: Dict[str, int], max_score: float, overall_tier: str) -> str:
        total = sum(sev_counts.values()) or 1
        bars_html = []
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            cnt = sev_counts.get(s, 0)
            pct = round((cnt / total) * 100, 1)
            color = SEVERITY_COLORS[s]["bar"]
            bars_html.append(f"""
        <div style="margin-bottom: 8px;">
          <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 2px;">
            <span><strong>{s}</strong>: {cnt}</span>
            <span>{pct}%</span>
          </div>
          <div style="background: #E2E8F0; border-radius: 4px; height: 10px; width: 100%; overflow: hidden;">
            <div style="background: {color}; width: {pct}%; height: 100%;"></div>
          </div>
        </div>
""")

        # Inline SVG circular gauge for max risk score
        meter_pct = min(100.0, max(0.0, max_score))
        stroke_dash = f"{meter_pct * 2.83:.1f}, 283"
        meter_color = SEVERITY_COLORS.get(overall_tier, SEVERITY_COLORS["Low"])["bar"]

        svg_gauge = f"""
      <svg width="120" height="120" viewBox="0 0 120 120" style="display: block; margin: 0 auto;">
        <circle cx="60" cy="60" r="45" fill="none" stroke="#E2E8F0" stroke-width="10" />
        <circle cx="60" cy="60" r="45" fill="none" stroke="{meter_color}" stroke-width="10"
                stroke-dasharray="{stroke_dash}" stroke-linecap="round"
                transform="rotate(-90 60 60)" />
        <text x="60" y="58" text-anchor="middle" font-size="20" font-weight="bold" fill="#0F172A">{max_score:.1f}</text>
        <text x="60" y="74" text-anchor="middle" font-size="10" font-weight="bold" fill="#64748B">{html.escape(overall_tier.upper())}</text>
      </svg>
"""

        return f"""
    <div class="charts-row">
      <div class="chart-box" style="flex: 2;">
        <div class="chart-title">Observed Severity Distribution</div>
        {''.join(bars_html)}
      </div>
      <div class="chart-box" style="text-align: center;">
        <div class="chart-title">Peak Posture Risk Index</div>
        {svg_gauge}
        <div style="font-size: 11px; color: #64748B; margin-top: 6px;">Formula: Severity &times; Confidence &times; Exposure</div>
      </div>
    </div>
"""

    @classmethod
    def _render_comparison_section(cls, comp: ScanComparisonResult) -> str:
        new_cnt = len(comp.new_findings)
        reop_cnt = len(comp.reopened_findings)
        res_cnt = len(comp.resolved_findings)
        pers_cnt = len(comp.persistent_findings)
        out_cnt = len(comp.not_reassessed_findings)

        limitation_box = ""
        if comp.has_scope_limitations:
            limitation_box = f"""
      <div class="alert-banner alert-warning" style="margin-top: 12px;">
        <strong>Comparison Scope Limitation</strong>
        <p>{html.escape(comp.limitation_notice)}</p>
      </div>
"""

        return f"""
    <h2>Historical Scan Comparison &bull; Baseline #{comp.baseline_session_id} vs Current #{comp.current_session_id}</h2>
    <div class="kpi-grid">
      <div class="kpi-card" style="border-left: 4px solid #EF4444;">
        <div class="kpi-title">New Findings</div>
        <div class="kpi-value">+{new_cnt}</div>
        <div class="kpi-sub">Introduced</div>
      </div>
      <div class="kpi-card" style="border-left: 4px solid #F59E0B;">
        <div class="kpi-title">Reopened Findings</div>
        <div class="kpi-value">{reop_cnt}</div>
        <div class="kpi-sub">Previously resolved</div>
      </div>
      <div class="kpi-card" style="border-left: 4px solid #10B981;">
        <div class="kpi-title">Verified Resolved</div>
        <div class="kpi-value">-{res_cnt}</div>
        <div class="kpi-sub">Confirmed closed</div>
      </div>
      <div class="kpi-card" style="border-left: 4px solid #3B82F6;">
        <div class="kpi-title">Persistent</div>
        <div class="kpi-value">{pers_cnt}</div>
        <div class="kpi-sub">Unchanged</div>
      </div>
      <div class="kpi-card" style="border-left: 4px solid #94A3B8;">
        <div class="kpi-title">Not Reassessed</div>
        <div class="kpi-value">{out_cnt}</div>
        <div class="kpi-sub">Out of scope</div>
      </div>
    </div>
    {limitation_box}
"""

    @classmethod
    def _render_findings_table(cls, findings: List[SecurityFinding], asset_map: Dict[int, Dict[str, Any]]) -> str:
        if not findings:
            return """
    <h2>Security Risk Observations</h2>
    <p style="color: #64748B; font-style: italic;">No security findings or risk observations recorded for the specified criteria.</p>
"""

        rows = []
        for f in findings:
            asset_info = asset_map.get(f.asset_id or 0, {})
            ip_str = f.ip_address or asset_info.get("ip_address", "Unknown Host")
            host_str = f.hostname or asset_info.get("hostname", "")
            target_display = f"{ip_str} ({host_str})" if host_str else ip_str

            port_display = f"{f.port_number}/{f.protocol}" if f.port_number is not None else "Host-Level"

            sev_class = f"badge-{f.severity.lower()}"
            tier_class = f"badge-{f.risk_tier.lower()}"
            status_class = "badge-resolved" if f.status == STATUS_RESOLVED else ("badge-ack" if f.status == STATUS_ACKNOWLEDGED else ("badge-fp" if f.status == STATUS_FALSE_POSITIVE else "badge-info"))

            # Evidence snippet
            evidence_html = f'<div class="evidence-block">{html.escape(f.evidence)}</div>' if f.evidence else ""

            # Remediation snippet
            rec_html = f'<div class="remediation-block"><strong>Defensive Action:</strong> {html.escape(f.recommendation)}</div>' if f.recommendation else ""

            # User notes
            notes_html = f'<div style="font-size: 11px; color: #78350F; margin-top: 4px;"><strong>Operator Note:</strong> {html.escape(f.user_notes)}</div>' if f.user_notes else ""

            rows.append(f"""
      <tr>
        <td>
          <span class="badge {sev_class}">{html.escape(f.severity)}</span>
          <div style="font-size: 11px; color: #64748B; font-family: monospace; margin-top: 4px;">{html.escape(f.rule_id)}</div>
        </td>
        <td>
          <div style="font-weight: 700; color: #0F172A; font-size: 14px;">{html.escape(f.title)}</div>
          <div style="font-size: 12px; color: #475569; margin-top: 4px;">{html.escape(f.description)}</div>
          {evidence_html}
          {rec_html}
          {notes_html}
        </td>
        <td>
          <strong>{f.risk_score:.1f}</strong>
          <div><span class="badge {tier_class}">{html.escape(f.risk_tier)}</span></div>
        </td>
        <td>
          <div style="font-weight: 600;">{html.escape(target_display)}</div>
          <div style="font-size: 11px; color: #64748B;">{html.escape(port_display)}</div>
        </td>
        <td>
          <span class="badge {status_class}">{html.escape(f.status)}</span>
        </td>
      </tr>
""")

        return f"""
    <h2>Security Risk Observations ({len(findings)})</h2>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th style="width: 130px;">Severity & Rule</th>
            <th>Observation & Defensive Guidance</th>
            <th style="width: 100px;">Risk Score</th>
            <th style="width: 180px;">Asset & Port</th>
            <th style="width: 110px;">Lifecycle</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
"""

    @classmethod
    def _render_remediation_summary(cls, findings: List[SecurityFinding]) -> str:
        # Group active findings by rule_id for prioritized checklist
        active_findings = [f for f in findings if f.status not in (STATUS_RESOLVED, STATUS_FALSE_POSITIVE)]
        if not active_findings:
            return ""

        rule_groups: Dict[str, List[SecurityFinding]] = {}
        for f in active_findings:
            rule_groups.setdefault(f.rule_id, []).append(f)

        checklist_items = []
        for rule_id, f_list in rule_groups.items():
            first_f = f_list[0]
            guidance = RemediationProvider.get_remediation(rule_id)
            affected_hosts = sorted({f.ip_address for f in f_list if f.ip_address})
            hosts_preview = ", ".join(affected_hosts[:5])
            if len(affected_hosts) > 5:
                hosts_preview += f" (+{len(affected_hosts)-5} more)"

            steps_html = "".join([f"<li>{html.escape(step)}</li>" for step in guidance.steps])
            refs_html = "".join([f'<span class="ref-tag">{html.escape(ref)}</span>' for ref in guidance.standards_references])

            checklist_items.append(f"""
      <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
          <div>
            <strong>{html.escape(first_f.title)}</strong>
            <span class="badge badge-{first_f.severity.lower()}" style="margin-left: 8px;">{html.escape(first_f.severity)}</span>
          </div>
          <span style="font-size: 11px; color: #64748B;">{len(f_list)} occurrence(s)</span>
        </div>
        <div style="font-size: 12px; color: #475569; margin-bottom: 8px;">
          Affected Asset(s): <strong>{html.escape(hosts_preview or 'Observed Hosts')}</strong>
        </div>
        <div style="font-size: 12px; margin-bottom: 8px;">
          <ul style="margin: 4px 0 0 18px; padding: 0;">
            {steps_html}
          </ul>
        </div>
        <div>
          {refs_html}
        </div>
      </div>
""")

        return f"""
    <h2>Prioritized Defensive Action Plan</h2>
    <p style="font-size: 13px; color: #64748B; margin-bottom: 16px;">
      Actionable defensive remediation steps mapped directly to CIS Controls v8 and NIST SP 800 standards.
      Operator confirmation required prior to implementation.
    </p>
    {''.join(checklist_items)}
"""

    @classmethod
    def _render_metadata_appendix(cls, session: Optional[ScanSession]) -> str:
        if not session:
            return ""

        return f"""
    <h2>Scan Scope & Technical Metadata Appendix</h2>
    <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 16px; font-size: 12px;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;">
        <div><strong>Scan Session ID:</strong> #{session.id}</div>
        <div><strong>Target Input:</strong> {html.escape(session.target_input)}</div>
        <div><strong>Profile:</strong> {html.escape(session.profile)}</div>
        <div><strong>Configured Ports:</strong> {html.escape(session.configured_ports or 'Default Profile Ports')}</div>
        <div><strong>Start Time:</strong> {html.escape(session.start_time.replace("T", " "))}</div>
        <div><strong>End Time:</strong> {html.escape((session.end_time or "In Progress").replace("T", " "))}</div>
        <div><strong>Duration:</strong> {session.duration_seconds:.2f} seconds</div>
        <div><strong>Scanner Engine:</strong> {html.escape(session.nmap_version or "Bundled Native TCP Connect")}</div>
      </div>
      <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #E2E8F0;">
        <strong>Command Executed:</strong>
        <code style="display: block; background: #E2E8F0; padding: 6px 10px; border-radius: 4px; font-size: 11px; margin-top: 4px; word-break: break-all;">
          {html.escape(session.command_executed or "Native Port Probing")}
        </code>
      </div>
      {f'<div style="margin-top: 8px; color: #DC2626;"><strong>Diagnostics:</strong> {html.escape(session.error_message)}</div>' if session.error_message else ''}
    </div>
"""
