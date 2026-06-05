#!/usr/bin/env python3
"""
reporter.py - Generates HTML and JSON scan reports with full evidence.
Styled to match professional Nessus-style output.
"""

import os
import json
from datetime import datetime, timezone


class ReportGenerator:
    """Generate HTML/JSON reports from scan results."""

    def __init__(self, scan_dir, target):
        self.scan_dir = scan_dir
        self.target = target

    def generate_json(self, results):
        """Generate machine-readable JSON report."""
        findings = [r for r in results if r.get("found")]
        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "target": self.target,
            "summary": self._build_summary(findings),
            "findings": findings
        }
        path = os.path.join(self.scan_dir, "report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return path

    def generate_html(self, results):
        """Generate styled HTML report with evidence."""
        findings = [r for r in results if r.get("found")]
        summary = self._build_summary(findings)

        # Sort findings: critical → high → medium → low → info
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(
            f.get("severity", f.get("plugin_severity", "info")), 5))

        html = self._render_html(findings, summary)
        path = os.path.join(self.scan_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _build_summary(self, findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", f.get("plugin_severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
        return {
            "total": len(findings),
            "by_severity": counts,
            "target": self.target
        }

    def _render_html(self, findings, summary):
        severity_colors = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"
        }
        confidence_colors = {
            "high": "#16a34a", "medium": "#d97706", "low": "#6b7280"
        }

        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", f.get("plugin_severity", "info")).lower()
            conf = f.get("confidence", "low").lower()
            sev_color = severity_colors.get(sev, "#6b7280")
            conf_color = confidence_colors.get(conf, "#6b7280")

            plugin_output = ""
            for line in f.get("plugin_output", []):
                plugin_output += f"<div class='output-line'>{_esc(str(line))}</div>"

            cve_html = ""
            for cve in f.get("cve_refs", []):
                cve_html += f"<a href='https://nvd.nist.gov/vuln/detail/{cve}' target='_blank' class='cve-link'>{_esc(cve)}</a> "

            request_html = f"<pre class='evidence-block'>{_esc(f.get('request', 'N/A'))}</pre>" if f.get("request") else ""
            response_html = f"<pre class='evidence-block'>{_esc(f.get('response', 'N/A'))}</pre>" if f.get("response") else ""

            remediation = f.get("remediation", "")
            rem_html = f"<div class='remediation'><strong>Remediation:</strong> {_esc(remediation)}</div>" if remediation else ""

            findings_html += f"""
            <div class="finding" id="finding-{i}">
                <div class="finding-header">
                    <span class="severity-badge" style="background:{sev_color}">{sev.upper()}</span>
                    <span class="finding-title">{_esc(f.get('title', f.get('plugin_name', 'Unknown')))}</span>
                    <span class="confidence-badge" style="background:{conf_color}">Confidence: {conf.upper()}</span>
                </div>
                <div class="finding-meta">
                    <span>Plugin: {_esc(f.get('plugin_name', ''))}</span>
                    <span>Family: {_esc(f.get('plugin_family', ''))}</span>
                    <span>Time: {f.get('execution_time', 0)}s</span>
                </div>
                <div class="finding-body">
                    <div class="evidence-section">
                        <strong>Evidence:</strong>
                        <div class="evidence-text">{_esc(f.get('evidence', 'N/A'))}</div>
                    </div>
                    {f'<div class="plugin-output"><strong>Plugin Output:</strong>{plugin_output}</div>' if plugin_output else ''}
                    {f'<div class="evidence-section"><strong>Request:</strong>{request_html}</div>' if request_html else ''}
                    {f'<div class="evidence-section"><strong>Response:</strong>{response_html}</div>' if response_html else ''}
                    {f'<div class="cve-section"><strong>CVEs:</strong> {cve_html}</div>' if cve_html else ''}
                    {rem_html}
                </div>
            </div>"""

        counts = summary["by_severity"]
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scan Report — {_esc(self.target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#1e293b,#334155);border-radius:12px;padding:30px;margin-bottom:24px;border:1px solid #475569}}
.header h1{{font-size:24px;color:#f8fafc;margin-bottom:8px}}
.header .target{{color:#38bdf8;font-size:16px}}
.header .meta{{color:#94a3b8;font-size:13px;margin-top:8px}}
.summary{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.summary-card{{flex:1;min-width:100px;background:#1e293b;border-radius:10px;padding:16px;text-align:center;border:1px solid #334155}}
.summary-card .count{{font-size:28px;font-weight:700}}
.summary-card .label{{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.finding{{background:#1e293b;border-radius:10px;margin-bottom:16px;border:1px solid #334155;overflow:hidden}}
.finding-header{{padding:16px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid #334155;flex-wrap:wrap}}
.severity-badge,.confidence-badge{{padding:4px 12px;border-radius:6px;font-size:11px;font-weight:700;color:#fff;letter-spacing:0.5px}}
.finding-title{{font-size:16px;font-weight:600;color:#f1f5f9;flex:1}}
.finding-meta{{padding:8px 20px;display:flex;gap:16px;font-size:12px;color:#64748b;border-bottom:1px solid #1e293b}}
.finding-body{{padding:16px 20px}}
.evidence-section,.plugin-output,.cve-section,.remediation{{margin-top:12px}}
.evidence-text{{background:#0f172a;padding:10px 14px;border-radius:6px;margin-top:6px;font-family:'Cascadia Code',monospace;font-size:13px;color:#38bdf8}}
.evidence-block{{background:#0f172a;padding:10px 14px;border-radius:6px;margin-top:6px;font-size:12px;color:#cbd5e1;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:300px}}
.output-line{{padding:2px 0;font-family:monospace;font-size:13px;color:#a5b4fc}}
.cve-link{{color:#f472b6;text-decoration:none;margin-right:8px;font-weight:600}}
.cve-link:hover{{text-decoration:underline}}
.remediation{{background:#1a2e1a;border:1px solid #22c55e40;border-radius:6px;padding:12px;color:#86efac}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Vulnerability Scan Report</h1>
<div class="target">Target: {_esc(self.target)}</div>
<div class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
</div>
<div class="summary">
<div class="summary-card"><div class="count" style="color:#dc2626">{counts.get('critical',0)}</div><div class="label">Critical</div></div>
<div class="summary-card"><div class="count" style="color:#ea580c">{counts.get('high',0)}</div><div class="label">High</div></div>
<div class="summary-card"><div class="count" style="color:#d97706">{counts.get('medium',0)}</div><div class="label">Medium</div></div>
<div class="summary-card"><div class="count" style="color:#2563eb">{counts.get('low',0)}</div><div class="label">Low</div></div>
<div class="summary-card"><div class="count" style="color:#6b7280">{counts.get('info',0)}</div><div class="label">Info</div></div>
<div class="summary-card"><div class="count" style="color:#f8fafc">{summary['total']}</div><div class="label">Total</div></div>
</div>
{findings_html}
</div>
</body>
</html>"""


def _esc(text):
    """HTML-escape a string."""
    if not isinstance(text, str):
        text = str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
