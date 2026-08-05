"""
PDF Report Generator — Tenable-Style Format
============================================
Generates a professional vulnerability assessment PDF report
inspired by Tenable's Vulnerability Management Program Health report format.

Structure:
    Page 1:  Cover page
    Page 2:  Executive Summary + Risk Overview
    Chapter 1: Critical & High Priority Vulnerabilities
    Chapter 2: Medium Severity Vulnerabilities
    Chapter 3: Low Severity Vulnerabilities
    Chapter 4: Technology & CVE Findings
    Chapter 5: Remediation Checklist
    Appendix:  Scan Metadata & Methodology

Install:
    pip install xhtml2pdf jinja2
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "Critical":      ("#7B0000", "#FFE5E5"),
    "High":          ("#C0392B", "#FDECEA"),
    "Medium":        ("#E67E22", "#FEF3E2"),
    "Low":           ("#2980B9", "#EBF5FB"),
    "Informational": ("#7F8C8D", "#F2F3F4"),
}

OWASP_SHORT = {
    "A01:2021 - Broken Access Control":                      "A01 - Broken Access Control",
    "A02:2021 - Cryptographic Failures":                     "A02 - Cryptographic Failures",
    "A03:2021 - Injection":                                  "A03 - Injection",
    "A04:2021 - Insecure Design":                            "A04 - Insecure Design",
    "A05:2021 - Security Misconfiguration":                  "A05 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components":         "A06 - Vulnerable Components",
    "A07:2021 - Identification and Authentication Failures": "A07 - Auth Failures",
    "A08:2021 - Software and Data Integrity Failures":       "A08 - Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures":   "A09 - Logging Failures",
    "A10:2021 - Server-Side Request Forgery":                "A10 - SSRF",
}


class PDFGenerator:
    def __init__(self, output_dir: str = "reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _severity_badge(self, severity: str) -> str:
        text_color, bg_color = SEVERITY_COLORS.get(severity, ("#333", "#eee"))
        return f'<span style="background:{bg_color}; color:{text_color}; padding:2px 8px; font-weight:700; font-size:10px; border:1px solid {text_color};">{severity.upper()}</span>'

    def _chapter_header(self, number: str, title: str, subtitle: str = "") -> str:
        return f"""
        <table style="width:100%; border-collapse:collapse; margin:8px 0 6px 0;">
            <tr>
                <td style="background:#1a1a2e; color:#A8C6FA; padding:6px 12px; font-size:11px; font-weight:700; width:60px;">
                    CHAPTER {number}
                </td>
                <td style="background:#1a1a2e; color:#FFFFFF; padding:6px 16px; font-size:14px; font-weight:700;">
                    {title}
                </td>
            </tr>
        </table>
        {"<p style='font-size:11px; color:#555; margin:0 0 12px 0; line-height:1.6;'>" + subtitle + "</p>" if subtitle else ""}
        """

    def _finding_block(self, finding: dict, index: int) -> str:
        sev = finding.get("severity", "Low")
        text_color, bg_color = SEVERITY_COLORS.get(sev, ("#333", "#eee"))
        owasp = OWASP_SHORT.get(finding.get("owasp_category", ""), finding.get("owasp_category", ""))
        recommendation = finding.get("recommendation") or finding.get("solution", "Review and remediate this finding.")
        business_impact = finding.get("business_impact", "")
        evidence = finding.get("evidence", "")
        row_bg = "#FAFAFA" if index % 2 == 0 else "#FFFFFF"

        return f"""
        <table style="width:100%; border-collapse:collapse; margin-bottom:4px; background:{row_bg}; border:1px solid #E8E8E8;">
            <tr>
                <td style="background:{bg_color}; border-left:4px solid {text_color}; padding:8px 12px; width:90px; vertical-align:top;">
                    <div style="color:{text_color}; font-weight:700; font-size:10px;">{sev.upper()}</div>
                    <div style="color:{text_color}; font-weight:700; font-size:13px;">{finding.get("cvss_score", "N/A")}</div>
                    <div style="color:{text_color}; font-size:9px;">CVSS</div>
                </td>
                <td style="padding:8px 12px; vertical-align:top;">
                    <div style="font-weight:700; font-size:12px; color:#1a1a2e; margin-bottom:3px;">
                        {finding.get("vuln_type", "Unknown")}
                    </div>
                    <div style="font-size:10px; color:#666; margin-bottom:4px;">
                        {owasp} &nbsp;|&nbsp; {finding.get("affected_url", "N/A")[:80]}{"..." if len(finding.get("affected_url","")) > 80 else ""}
                    </div>
                    <div style="font-size:11px; color:#333; margin-bottom:4px;">
                        <strong>Recommendation:</strong> {recommendation[:300]}{"..." if len(recommendation) > 300 else ""}
                    </div>
                    {f'<div style="font-size:10px; color:#555;"><strong>Business Impact:</strong> {business_impact}</div>' if business_impact else ""}
                    {f'<div style="font-size:10px; color:#888; margin-top:3px;"><strong>Evidence:</strong> <code>{evidence[:120]}</code></div>' if evidence else ""}
                </td>
            </tr>
        </table>"""

    def _build_html(self, scan_data: dict) -> str:
        scan_id      = scan_data.get("scan_id", "N/A")
        target_url   = scan_data.get("url") or scan_data.get("target", "N/A")
        created_at   = scan_data.get("created_at", datetime.utcnow().isoformat())
        summary      = scan_data.get("summary", {})
        exec_summary = scan_data.get("executive_summary", "No executive summary available.")
        findings     = scan_data.get("findings", [])

        try:
            date_str = datetime.fromisoformat(created_at).strftime("%B %d, %Y %H:%M UTC")
        except Exception:
            date_str = created_at

        # Determine overall risk
        if summary.get("critical", 0) > 0:
            overall_risk, risk_color = "CRITICAL RISK", "#7B0000"
        elif summary.get("high", 0) > 0:
            overall_risk, risk_color = "HIGH RISK", "#C0392B"
        elif summary.get("medium", 0) > 0:
            overall_risk, risk_color = "MEDIUM RISK", "#E67E22"
        else:
            overall_risk, risk_color = "LOW RISK", "#2980B9"

        # Split findings by severity
        critical_high = [f for f in findings if f.get("severity") in ("Critical", "High")]
        medium        = [f for f in findings if f.get("severity") == "Medium"]
        low           = [f for f in findings if f.get("severity") == "Low"]
        cve_findings  = [f for f in findings if f.get("tool") in ("nvd_lookup", "nuclei")]

        # OWASP distribution
        owasp_counts = {}
        for f in findings:
            cat = OWASP_SHORT.get(f.get("owasp_category", ""), f.get("owasp_category", "Unknown"))
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        owasp_rows = ""
        for cat, count in sorted(owasp_counts.items(), key=lambda x: -x[1])[:8]:
            pct = int((count / max(summary.get("total", 1), 1)) * 100)
            owasp_rows += f"""
            <tr>
                <td style="padding:5px 8px; font-size:11px; border-bottom:1px solid #ECF0F1;">{cat}</td>
                <td style="padding:5px 8px; text-align:center; font-weight:700; font-size:11px; border-bottom:1px solid #ECF0F1;">{count}</td>
                <td style="padding:5px 8px; border-bottom:1px solid #ECF0F1;">
                    <div style="background:#3498DB; height:8px; width:{min(pct*2, 100)}%;"></div>
                </td>
            </tr>"""

        # Chapter 1 — Critical & High
        ch1_content = ""
        if critical_high:
            for i, f in enumerate(critical_high):
                ch1_content += self._finding_block(f, i)
        else:
            ch1_content = '<p style="color:#27AE60; font-size:12px; padding:16px; background:#EAFAF1; border-left:4px solid #27AE60;">✓ No Critical or High severity vulnerabilities detected.</p>'

        # Chapter 2 — Medium
        ch2_content = ""
        for i, f in enumerate(medium[:50]):  # cap at 50
            ch2_content += self._finding_block(f, i)
        if len(medium) > 50:
            ch2_content += f'<p style="font-size:11px; color:#666; text-align:center; padding:8px;">... and {len(medium) - 50} more medium findings. See Excel export for complete list.</p>'
        if not medium:
            ch2_content = '<p style="color:#27AE60; font-size:12px; padding:16px; background:#EAFAF1; border-left:4px solid #27AE60;">✓ No Medium severity vulnerabilities detected.</p>'

        # Chapter 3 — Low (summary table only, not full blocks)
        low_rows = ""
        for f in low[:30]:
            owasp = OWASP_SHORT.get(f.get("owasp_category", ""), f.get("owasp_category", ""))
            low_rows += f"""
            <tr>
                <td style="padding:6px 8px; font-size:11px; border-bottom:1px solid #ECF0F1;">{f.get("vuln_type","")[:60]}</td>
                <td style="padding:6px 8px; font-size:11px; border-bottom:1px solid #ECF0F1; color:#2980B9;">{f.get("cvss_score","")}</td>
                <td style="padding:6px 8px; font-size:10px; color:#666; border-bottom:1px solid #ECF0F1;">{owasp}</td>
                <td style="padding:6px 8px; font-size:10px; color:#888; border-bottom:1px solid #ECF0F1;">{f.get("affected_url","")[:50]}{"..." if len(f.get("affected_url","")) > 50 else ""}</td>
            </tr>"""
        if len(low) > 30:
            low_rows += f'<tr><td colspan="4" style="padding:8px; font-size:11px; color:#666; text-align:center;">... and {len(low)-30} more low findings in Excel export.</td></tr>'

        ch3_content = f"""
        <table style="width:100%; border-collapse:collapse; border:1px solid #ECF0F1;">
            <thead>
                <tr style="background:#2C3E50; color:white;">
                    <th style="padding:8px; text-align:left; font-size:11px;">Vulnerability</th>
                    <th style="padding:8px; text-align:left; font-size:11px; width:50px;">CVSS</th>
                    <th style="padding:8px; text-align:left; font-size:11px;">OWASP</th>
                    <th style="padding:8px; text-align:left; font-size:11px;">Affected URL</th>
                </tr>
            </thead>
            <tbody>{low_rows if low_rows else '<tr><td colspan="4" style="padding:12px; color:#27AE60; text-align:center;">✓ No Low severity vulnerabilities detected.</td></tr>'}</tbody>
        </table>"""

        # Chapter 4 — CVE / Tech findings
        ch4_content = ""
        if cve_findings:
            for i, f in enumerate(cve_findings[:20]):
                ch4_content += self._finding_block(f, i)
        else:
            ch4_content = '<p style="font-size:11px; color:#666; padding:12px; background:#F8F9FA;">No CVE findings detected. Technology fingerprinting found no software versions with known vulnerabilities.</p>'

        # Chapter 5 — Remediation checklist
        checklist_rows = ""
        priority_findings = [f for f in findings if f.get("severity") in ("Critical", "High", "Medium")][:25]
        for i, f in enumerate(priority_findings):
            text_color, bg_color = SEVERITY_COLORS.get(f.get("severity","Low"), ("#333","#eee"))
            checklist_rows += f"""
            <tr style="background:{'#FAFAFA' if i%2==0 else '#FFFFFF'};">
                <td style="padding:8px; text-align:center; font-size:14px; border-bottom:1px solid #ECF0F1;">☐</td>
                <td style="padding:8px; border-bottom:1px solid #ECF0F1;">
                    <span style="background:{bg_color}; color:{text_color}; padding:1px 6px; font-size:10px; font-weight:700;">{f.get("severity","").upper()}</span>
                </td>
                <td style="padding:8px; font-size:11px; font-weight:600; border-bottom:1px solid #ECF0F1;">{f.get("vuln_type","")[:60]}</td>
                <td style="padding:8px; font-size:10px; color:#666; border-bottom:1px solid #ECF0F1;">{f.get("affected_url","")[:50]}</td>
                <td style="padding:8px; font-size:10px; color:#333; border-bottom:1px solid #ECF0F1;">{(f.get("recommendation") or f.get("solution",""))[:120]}{"..." if len(f.get("recommendation") or f.get("solution","")) > 120 else ""}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    * {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{ font-family:Arial, sans-serif; color:#2C3E50; font-size:12px; }}
    code {{ font-family:monospace; background:#F0F0F0; padding:1px 4px; font-size:10px; }}
    .page-break {{ page-break-before:always; }}
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════ -->
<!-- COVER PAGE                                  -->
<!-- ═══════════════════════════════════════════ -->
<table style="width:100%; background:#1a1a2e; page-break-after:always; margin-bottom:0;">
    <tr>
        <td style="padding:60px 50px; color:white;">
            <!-- Top bar -->
            <table style="width:100%; margin-bottom:50px;">
                <tr>
                    <td style="color:#A8C6FA; font-size:12px; font-weight:700; letter-spacing:2px;">
                        VULNERABILITY ASSESSMENT REPORT
                    </td>
                    <td style="text-align:right; color:#A8C6FA; font-size:11px;">
                        Powered by OWASP ZAP + Groq AI
                    </td>
                </tr>
            </table>

            <!-- Risk badge -->
            <div style="background:{risk_color}; display:inline-block; padding:6px 16px; margin-bottom:20px; font-size:12px; font-weight:700; letter-spacing:1px; color:white;">
                {overall_risk}
            </div>

            <!-- Title -->
            <div style="font-size:28px; font-weight:700; color:#FFFFFF; margin-bottom:8px; line-height:1.2;">
                Website Security<br/>Assessment Report
            </div>
            <div style="font-size:14px; color:#A8C6FA; margin-bottom:50px;">
                AI-Powered Vulnerability Detection &amp; Risk Analysis
            </div>

            <!-- Metadata box -->
            <table style="width:100%; background:#2C3E6E; border-collapse:collapse;">
                <tr>
                    <td style="padding:12px 16px; color:#A8C6FA; font-size:11px; font-weight:700; width:160px; border-bottom:1px solid #3a4a7e;">TARGET URL</td>
                    <td style="padding:12px 16px; color:#FFFFFF; font-size:11px; border-bottom:1px solid #3a4a7e;">{target_url}</td>
                </tr>
                <tr>
                    <td style="padding:12px 16px; color:#A8C6FA; font-size:11px; font-weight:700; border-bottom:1px solid #3a4a7e;">SCAN DATE</td>
                    <td style="padding:12px 16px; color:#FFFFFF; font-size:11px; border-bottom:1px solid #3a4a7e;">{date_str}</td>
                </tr>
                <tr>
                    <td style="padding:12px 16px; color:#A8C6FA; font-size:11px; font-weight:700; border-bottom:1px solid #3a4a7e;">TOTAL FINDINGS</td>
                    <td style="padding:12px 16px; color:#FFFFFF; font-size:11px; border-bottom:1px solid #3a4a7e;">{summary.get("total",0)} vulnerabilities identified</td>
                </tr>
                <tr>
                    <td style="padding:12px 16px; color:#A8C6FA; font-size:11px; font-weight:700;">SCAN ID</td>
                    <td style="padding:12px 16px; color:#888; font-size:10px;">{scan_id}</td>
                </tr>
            </table>

            <!-- Severity summary -->
            <table style="width:100%; margin-top:30px; border-collapse:collapse;">
                <tr>
                    <td style="background:#7B0000; padding:16px; text-align:center; width:20%;">
                        <div style="color:white; font-size:28px; font-weight:700;">{summary.get("critical",0)}</div>
                        <div style="color:#FFB3B3; font-size:10px; font-weight:700; letter-spacing:1px;">CRITICAL</div>
                    </td>
                    <td style="background:#C0392B; padding:16px; text-align:center; width:20%;">
                        <div style="color:white; font-size:28px; font-weight:700;">{summary.get("high",0)}</div>
                        <div style="color:#FFD0CC; font-size:10px; font-weight:700; letter-spacing:1px;">HIGH</div>
                    </td>
                    <td style="background:#E67E22; padding:16px; text-align:center; width:20%;">
                        <div style="color:white; font-size:28px; font-weight:700;">{summary.get("medium",0)}</div>
                        <div style="color:#FFE8CC; font-size:10px; font-weight:700; letter-spacing:1px;">MEDIUM</div>
                    </td>
                    <td style="background:#2980B9; padding:16px; text-align:center; width:20%;">
                        <div style="color:white; font-size:28px; font-weight:700;">{summary.get("low",0)}</div>
                        <div style="color:#CCE5FF; font-size:10px; font-weight:700; letter-spacing:1px;">LOW</div>
                    </td>
                    <td style="background:#2C3E50; padding:16px; text-align:center; width:20%;">
                        <div style="color:white; font-size:28px; font-weight:700;">{summary.get("total",0)}</div>
                        <div style="color:#BDC3C7; font-size:10px; font-weight:700; letter-spacing:1px;">TOTAL</div>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>

<!-- ═══════════════════════════════════════════ -->
<!-- EXECUTIVE SUMMARY                           -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:16px 40px;">
    <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
        <tr>
            <td style="background:#1a1a2e; color:#A8C6FA; padding:5px 12px; font-size:10px; font-weight:700; width:180px;">EXECUTIVE SUMMARY</td>
            <td style="background:#1a1a2e; color:#FFFFFF; padding:5px 16px; font-size:13px; font-weight:700;">Risk Overview &amp; Recommendations</td>
        </tr>
    </table>

    <p style="font-size:11px; color:#444; line-height:1.6; margin-bottom:20px; padding:16px; background:#F8F9FA; border-left:4px solid #1a1a2e;">
        {exec_summary}
    </p>

    <!-- OWASP Distribution -->
    <table style="width:100%; border-collapse:collapse; margin-bottom:20px; border:1px solid #ECF0F1;">
        <thead>
            <tr style="background:#2C3E50; color:white;">
                <th style="padding:8px 10px; text-align:left; font-size:11px;">OWASP Top 10 Category</th>
                <th style="padding:8px 10px; text-align:center; font-size:11px; width:60px;">Count</th>
                <th style="padding:8px 10px; font-size:11px;">Distribution</th>
            </tr>
        </thead>
        <tbody>{owasp_rows}</tbody>
    </table>

    <!-- Table of contents -->
    <table style="width:100%; border-collapse:collapse; border:1px solid #ECF0F1;">
        <thead>
            <tr style="background:#2C3E50; color:white;">
                <th colspan="2" style="padding:8px 12px; text-align:left; font-size:11px;">REPORT CHAPTERS</th>
            </tr>
        </thead>
        <tbody>
            <tr style="background:#FDECEA;">
                <td style="padding:8px 12px; font-size:11px; font-weight:700; width:120px; border-bottom:1px solid #ECF0F1;">Chapter 1</td>
                <td style="padding:8px 12px; font-size:11px; border-bottom:1px solid #ECF0F1;">Critical &amp; High Priority Vulnerabilities ({len(critical_high)} findings) — <strong>Address Immediately</strong></td>
            </tr>
            <tr style="background:#FEF3E2;">
                <td style="padding:8px 12px; font-size:11px; font-weight:700; border-bottom:1px solid #ECF0F1;">Chapter 2</td>
                <td style="padding:8px 12px; font-size:11px; border-bottom:1px solid #ECF0F1;">Medium Severity Vulnerabilities ({len(medium)} findings) — Address in Next Sprint</td>
            </tr>
            <tr style="background:#EBF5FB;">
                <td style="padding:8px 12px; font-size:11px; font-weight:700; border-bottom:1px solid #ECF0F1;">Chapter 3</td>
                <td style="padding:8px 12px; font-size:11px; border-bottom:1px solid #ECF0F1;">Low Severity Vulnerabilities ({len(low)} findings) — Address When Feasible</td>
            </tr>
            <tr>
                <td style="padding:8px 12px; font-size:11px; font-weight:700; border-bottom:1px solid #ECF0F1;">Chapter 4</td>
                <td style="padding:8px 12px; font-size:11px; border-bottom:1px solid #ECF0F1;">Technology &amp; CVE Findings ({len(cve_findings)} findings)</td>
            </tr>
            <tr style="background:#FAFAFA;">
                <td style="padding:8px 12px; font-size:11px; font-weight:700;">Chapter 5</td>
                <td style="padding:8px 12px; font-size:11px;">Remediation Checklist — Prioritized Action Items</td>
            </tr>
        </tbody>
    </table>

    <p style="font-size:10px; color:#999; margin-top:16px; text-align:center;">
        ⚠ This report is generated by an automated scanner. Results should be reviewed by a qualified security professional before remediation actions are taken. This tool does not replace a professional penetration test.
    </p>
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- CHAPTER 1: CRITICAL & HIGH                  -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    {self._chapter_header("1", "Critical &amp; High Priority Vulnerabilities",
        "The following vulnerabilities represent the highest risk to your organization and should be addressed immediately. "
        "These findings have been confirmed by automated scanning engines and enriched with AI-generated remediation guidance.")}
    {ch1_content}
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- CHAPTER 2: MEDIUM                           -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    {self._chapter_header("2", "Medium Severity Vulnerabilities",
        "Medium severity findings represent meaningful security weaknesses that should be addressed in the next development cycle. "
        "While not immediately exploitable in most cases, these issues can be chained with other vulnerabilities to enable attacks.")}
    {ch2_content}
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- CHAPTER 3: LOW                              -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    {self._chapter_header("3", "Low Severity Vulnerabilities",
        "Low severity findings are security improvements that, while not immediately critical, represent security best practice gaps. "
        "These should be addressed as part of regular security hygiene and hardening activities.")}
    {ch3_content}
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- CHAPTER 4: CVE & TECH                       -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    {self._chapter_header("4", "Technology &amp; CVE Findings",
        "The following findings were identified through technology fingerprinting and cross-referenced against the NVD (National Vulnerability Database). "
        "Known CVEs in detected software versions represent concrete, publicly documented exploitation paths.")}
    {ch4_content}
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- CHAPTER 5: REMEDIATION CHECKLIST            -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    {self._chapter_header("5", "Remediation Checklist",
        "Use this checklist to track remediation progress. Items are ordered by severity — address Critical and High findings first. "
        "Check off each item as it is resolved and re-scan to verify.")}
    <table style="width:100%; border-collapse:collapse; border:1px solid #ECF0F1;">
        <thead>
            <tr style="background:#1a1a2e; color:white;">
                <th style="padding:8px; width:30px; font-size:11px;">✓</th>
                <th style="padding:8px; width:70px; font-size:11px;">Severity</th>
                <th style="padding:8px; font-size:11px;">Vulnerability</th>
                <th style="padding:8px; font-size:11px; width:140px;">Affected URL</th>
                <th style="padding:8px; font-size:11px;">Recommended Fix</th>
            </tr>
        </thead>
        <tbody>
            {checklist_rows if checklist_rows else '<tr><td colspan="5" style="padding:12px; text-align:center; color:#27AE60;">✓ No high-priority items to remediate.</td></tr>'}
        </tbody>
    </table>
</div>

<!-- ═══════════════════════════════════════════ -->
<!-- APPENDIX: METHODOLOGY                       -->
<!-- ═══════════════════════════════════════════ -->
<div style="padding:8px 40px;">
    <table style="width:100%; border-collapse:collapse; margin-bottom:16px;">
        <tr>
            <td style="background:#2C3E50; color:#BDC3C7; padding:5px 12px; font-size:10px; font-weight:700; width:100px;">APPENDIX</td>
            <td style="background:#2C3E50; color:#FFFFFF; padding:5px 16px; font-size:13px; font-weight:700;">Scan Methodology &amp; Tool Information</td>
        </tr>
    </table>

    <table style="width:100%; border-collapse:collapse; margin-bottom:16px; border:1px solid #ECF0F1;">
        <thead>
            <tr style="background:#ECF0F1;">
                <th style="padding:8px 12px; text-align:left; font-size:11px; font-weight:700;">Scanning Module</th>
                <th style="padding:8px 12px; text-align:left; font-size:11px; font-weight:700;">Purpose</th>
                <th style="padding:8px 12px; text-align:left; font-size:11px; font-weight:700;">Detection Type</th>
            </tr>
        </thead>
        <tbody>
            <tr style="border-bottom:1px solid #ECF0F1;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">OWASP ZAP</td>
                <td style="padding:8px 12px; font-size:11px;">SQLi, XSS, CSRF, Path Traversal, Misconfigurations</td>
                <td style="padding:8px 12px; font-size:11px;">Active (payload injection)</td>
            </tr>
            <tr style="background:#FAFAFA; border-bottom:1px solid #ECF0F1;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">Nuclei</td>
                <td style="padding:8px 12px; font-size:11px;">Known CVEs, exposed files, default credentials</td>
                <td style="padding:8px 12px; font-size:11px;">Template-based</td>
            </tr>
            <tr style="border-bottom:1px solid #ECF0F1;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">Header Scanner</td>
                <td style="padding:8px 12px; font-size:11px;">Missing security headers (CSP, HSTS, X-Frame-Options)</td>
                <td style="padding:8px 12px; font-size:11px;">Passive</td>
            </tr>
            <tr style="background:#FAFAFA; border-bottom:1px solid #ECF0F1;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">SSL/TLS Scanner</td>
                <td style="padding:8px 12px; font-size:11px;">Certificate validity, protocol versions, cipher suites</td>
                <td style="padding:8px 12px; font-size:11px;">Passive</td>
            </tr>
            <tr style="border-bottom:1px solid #ECF0F1;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">Tech Fingerprinter</td>
                <td style="padding:8px 12px; font-size:11px;">Web server, CMS, framework, JS library detection</td>
                <td style="padding:8px 12px; font-size:11px;">Passive</td>
            </tr>
            <tr style="background:#FAFAFA;">
                <td style="padding:8px 12px; font-size:11px; font-weight:600;">NVD CVE Lookup</td>
                <td style="padding:8px 12px; font-size:11px;">Cross-reference detected versions against NVD database</td>
                <td style="padding:8px 12px; font-size:11px;">Intelligence</td>
            </tr>
        </tbody>
    </table>

    <table style="width:100%; border-collapse:collapse; border:1px solid #ECF0F1;">
        <thead>
            <tr style="background:#ECF0F1;">
                <th colspan="2" style="padding:8px 12px; text-align:left; font-size:11px; font-weight:700;">Severity Classification (CVSS v3.1)</th>
            </tr>
        </thead>
        <tbody>
            <tr style="border-bottom:1px solid #ECF0F1;">
                <td style="padding:6px 12px;"><span style="background:#FFE5E5; color:#7B0000; padding:2px 8px; font-weight:700; font-size:10px;">CRITICAL</span></td>
                <td style="padding:6px 12px; font-size:11px;">CVSS 9.0–10.0 — Requires immediate remediation</td>
            </tr>
            <tr style="background:#FAFAFA; border-bottom:1px solid #ECF0F1;">
                <td style="padding:6px 12px;"><span style="background:#FDECEA; color:#C0392B; padding:2px 8px; font-weight:700; font-size:10px;">HIGH</span></td>
                <td style="padding:6px 12px; font-size:11px;">CVSS 7.0–8.9 — Address within 30 days</td>
            </tr>
            <tr style="border-bottom:1px solid #ECF0F1;">
                <td style="padding:6px 12px;"><span style="background:#FEF3E2; color:#E67E22; padding:2px 8px; font-weight:700; font-size:10px;">MEDIUM</span></td>
                <td style="padding:6px 12px; font-size:11px;">CVSS 4.0–6.9 — Address within 90 days</td>
            </tr>
            <tr style="background:#FAFAFA;">
                <td style="padding:6px 12px;"><span style="background:#EBF5FB; color:#2980B9; padding:2px 8px; font-weight:700; font-size:10px;">LOW</span></td>
                <td style="padding:6px 12px; font-size:11px;">CVSS 0.1–3.9 — Address during regular maintenance</td>
            </tr>
        </tbody>
    </table>

    <p style="font-size:10px; color:#999; margin-top:20px; text-align:center; border-top:1px solid #ECF0F1; padding-top:12px;">
        AI-Powered Vulnerability Assessment Tool &nbsp;|&nbsp; Powered by OWASP ZAP + Nuclei + Groq AI (Llama 3.3 70B) &nbsp;|&nbsp; Generated: {date_str}
        <br/>Scan ID: {scan_id}
    </p>
</div>

</body>
</html>"""
        return html

    def generate(self, scan_data: dict, output_filename: str = None) -> str:
        try:
            from xhtml2pdf import pisa
        except ImportError:
            raise ImportError("xhtml2pdf not installed. Run: pip install xhtml2pdf")

        # Patch missing fields
        if not scan_data.get("scan_id") and scan_data.get("findings"):
            scan_data["scan_id"] = scan_data["findings"][0].get("scan_id", "unknown")
        if not scan_data.get("url") and scan_data.get("target"):
            scan_data["url"] = scan_data["target"]
        if "summary" not in scan_data:
            findings = scan_data.get("findings", [])
            summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f.get("severity", "Low").lower()
                if sev in summary:
                    summary[sev] += 1
            scan_data["summary"] = summary

        scan_id = scan_data.get("scan_id", "unknown")
        if output_filename is None:
            output_filename = f"report_{scan_id}.pdf"

        output_path = self.output_dir / output_filename
        logger.info(f"Generating Tenable-style PDF for scan {scan_id}")

        html_content = self._build_html(scan_data)

        with open(str(output_path), "wb") as pdf_file:
            pisa.CreatePDF(html_content, dest=pdf_file)

        logger.info(f"PDF saved to: {output_path}")
        return str(output_path)


# ── Quick test ──────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    for fname in ["scan_result_enriched.json", "scan_result.json"]:
        if os.path.exists(fname):
            with open(fname) as f:
                raw = json.load(f)
            print(f"Loaded from {fname}")
            break
    else:
        print("No scan data found.")
        sys.exit(1)

    gen = PDFGenerator(output_dir="reports/output")
    path = gen.generate(raw)
    print(f"\nPDF generated: {path}")