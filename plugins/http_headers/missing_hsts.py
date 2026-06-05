#!/usr/bin/env python3
"""
missing_hsts.py — Checks for missing Strict-Transport-Security header.
"""

import requests
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector

requests.packages.urllib3.disable_warnings()


class MissingHSTS(PluginBase):
    name = "Missing HSTS Header"
    family = "http_headers"
    severity = "medium"
    description = "Checks for missing or misconfigured HSTS header"
    depends_on = []
    references = ["https://tools.ietf.org/html/rfc6797"]

    def detect(self, target, kb):
        try:
            r = requests.get(target, timeout=10, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")

        hsts = r.headers.get("Strict-Transport-Security", "")
        req = EvidenceCollector.format_http_request("GET", target)
        resp = EvidenceCollector.format_http_response(r.status_code, dict(r.headers))
        output = []

        if not hsts:
            output = [
                "Strict-Transport-Security header is MISSING.",
                "Clients may connect over insecure HTTP.",
                f"URL: {r.url}"
            ]
            return PluginResult(
                found=True, title="Missing HSTS Header", severity="medium",
                confidence="high", evidence="Strict-Transport-Security header not found",
                request=req, response=resp, plugin_output=output,
                remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
            )

        # Check for weak max-age
        if "max-age=0" in hsts:
            output = [f"HSTS present but disabled: {hsts}"]
            return PluginResult(
                found=True, title="HSTS Disabled (max-age=0)", severity="medium",
                confidence="high", evidence=f"HSTS: {hsts}", request=req, response=resp,
                plugin_output=output, remediation="Set max-age to at least 31536000."
            )

        return PluginResult(found=False, evidence=f"HSTS present: {hsts}")
