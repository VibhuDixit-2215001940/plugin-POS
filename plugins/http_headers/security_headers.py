#!/usr/bin/env python3
"""
missing_xframe.py — X-Frame-Options check.
missing_xcontent.py — X-Content-Type-Options check.
missing_referrer.py — Referrer-Policy check.
dangerous_methods.py — HTTP dangerous methods check.

Combined into one file for efficiency — each is a separate plugin class.
"""

import requests
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0"}


def _fetch(target):
    return requests.get(target, timeout=10, verify=False, allow_redirects=True, headers=UA)


class MissingXFrameOptions(PluginBase):
    name = "Missing X-Frame-Options"
    family = "http_headers"
    severity = "medium"
    description = "Checks for missing X-Frame-Options (clickjacking protection)"
    depends_on = []

    def detect(self, target, kb):
        try:
            r = _fetch(target)
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")
        val = r.headers.get("X-Frame-Options", "")
        req = EvidenceCollector.format_http_request("GET", target)
        resp = EvidenceCollector.format_http_response(r.status_code, dict(r.headers))
        if not val:
            return PluginResult(
                found=True, title="Missing X-Frame-Options", severity="medium",
                confidence="high", evidence="X-Frame-Options not set",
                request=req, response=resp,
                plugin_output=["X-Frame-Options header is MISSING.", "Site may be vulnerable to clickjacking."],
                remediation="Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
            )
        return PluginResult(found=False, evidence=f"X-Frame-Options: {val}")


class MissingXContentType(PluginBase):
    name = "Missing X-Content-Type-Options"
    family = "http_headers"
    severity = "low"
    description = "Checks for missing X-Content-Type-Options: nosniff"
    depends_on = []

    def detect(self, target, kb):
        try:
            r = _fetch(target)
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")
        val = r.headers.get("X-Content-Type-Options", "")
        req = EvidenceCollector.format_http_request("GET", target)
        resp = EvidenceCollector.format_http_response(r.status_code, dict(r.headers))
        if not val:
            return PluginResult(
                found=True, title="Missing X-Content-Type-Options", severity="low",
                confidence="high", evidence="X-Content-Type-Options not set",
                request=req, response=resp,
                plugin_output=["X-Content-Type-Options header is MISSING.",
                               "Browser may MIME-sniff responses, enabling XSS."],
                remediation="Add 'X-Content-Type-Options: nosniff' header."
            )
        return PluginResult(found=False, evidence=f"X-Content-Type-Options: {val}")


class MissingReferrerPolicy(PluginBase):
    name = "Missing Referrer-Policy"
    family = "http_headers"
    severity = "low"
    description = "Checks for missing Referrer-Policy header"
    depends_on = []

    def detect(self, target, kb):
        try:
            r = _fetch(target)
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")
        val = r.headers.get("Referrer-Policy", "")
        req = EvidenceCollector.format_http_request("GET", target)
        resp = EvidenceCollector.format_http_response(r.status_code, dict(r.headers))
        if not val:
            return PluginResult(
                found=True, title="Missing Referrer-Policy", severity="low",
                confidence="high", evidence="Referrer-Policy not set",
                request=req, response=resp,
                plugin_output=["Referrer-Policy header is MISSING.",
                               "Full URL may leak to third parties via Referer header."],
                remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
            )
        return PluginResult(found=False, evidence=f"Referrer-Policy: {val}")


class DangerousHTTPMethods(PluginBase):
    name = "Dangerous HTTP Methods Enabled"
    family = "http_headers"
    severity = "medium"
    description = "Checks for dangerous HTTP methods (PUT, DELETE, TRACE)"
    depends_on = []

    def detect(self, target, kb):
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
        found_methods = []
        output = []

        try:
            r = requests.options(target, timeout=10, verify=False, headers=UA)
            allow = r.headers.get("Allow", "")
            if allow:
                for method in dangerous:
                    if method in allow.upper():
                        found_methods.append(method)
                output.append(f"Allow header: {allow}")
        except Exception:
            pass

        # Test TRACE explicitly
        try:
            r = requests.request("TRACE", target, timeout=5, verify=False, headers=UA)
            if r.status_code == 200:
                if "TRACE" not in found_methods:
                    found_methods.append("TRACE")
                output.append(f"TRACE method returned {r.status_code}")
        except Exception:
            pass

        if found_methods:
            return PluginResult(
                found=True, title="Dangerous HTTP Methods Enabled", severity="medium",
                confidence="high", evidence=f"Methods enabled: {', '.join(found_methods)}",
                plugin_output=output,
                remediation=f"Disable dangerous HTTP methods: {', '.join(found_methods)}"
            )
        return PluginResult(found=False, evidence="No dangerous methods detected")
