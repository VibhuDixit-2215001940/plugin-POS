#!/usr/bin/env python3
"""
missing_csp.py — Checks for missing Content-Security-Policy header.
"""

import requests
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector

requests.packages.urllib3.disable_warnings()


class MissingCSP(PluginBase):
    name = "Missing Content-Security-Policy"
    family = "http_headers"
    severity = "high"
    description = "Checks for missing CSP header"
    depends_on = []
    references = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]

    def detect(self, target, kb):
        try:
            r = requests.get(target, timeout=10, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")

        csp = r.headers.get("Content-Security-Policy", "")
        csp_ro = r.headers.get("Content-Security-Policy-Report-Only", "")
        req = EvidenceCollector.format_http_request("GET", target)
        resp = EvidenceCollector.format_http_response(r.status_code, dict(r.headers))

        if not csp and not csp_ro:
            return PluginResult(
                found=True, title="Missing Content-Security-Policy", severity="high",
                confidence="high", evidence="CSP header not found",
                request=req, response=resp,
                plugin_output=["Content-Security-Policy header is MISSING.",
                               "Application is vulnerable to XSS and data injection attacks."],
                remediation="Implement a Content-Security-Policy header with restrictive directives."
            )

        # Check for unsafe directives
        issues = []
        if "'unsafe-inline'" in csp:
            issues.append("CSP allows 'unsafe-inline' — XSS protection weakened")
        if "'unsafe-eval'" in csp:
            issues.append("CSP allows 'unsafe-eval' — code injection possible")
        if "* " in csp or csp.strip().endswith("*"):
            issues.append("CSP uses wildcard (*) — too permissive")

        if issues:
            return PluginResult(
                found=True, title="Weak Content-Security-Policy", severity="medium",
                confidence="high", evidence=f"CSP: {csp[:200]}",
                request=req, response=resp, plugin_output=issues,
                remediation="Remove unsafe-inline and unsafe-eval from CSP directives."
            )

        return PluginResult(found=False, evidence=f"CSP present: {csp[:100]}")
