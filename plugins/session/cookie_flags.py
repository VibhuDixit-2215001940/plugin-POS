#!/usr/bin/env python3
"""
cookie_flags.py — Cookie Security Audit Plugin
Checks Set-Cookie headers for missing security flags.
"""

import re
import requests
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector

requests.packages.urllib3.disable_warnings()

SENSITIVE_PATTERNS = [
    r"sess(ion)?", r"auth", r"token", r"jwt", r"access",
    r"refresh", r"user", r"uid", r"csrf", r"xsrf",
    r"login", r"admin", r"key", r"secret"
]


class CookieSecurityAudit(PluginBase):
    name = "Insecure Cookie Flags"
    family = "session"
    severity = "medium"
    description = "Checks cookies for missing HttpOnly, Secure, SameSite flags"
    depends_on = []

    def detect(self, target, kb):
        try:
            r = requests.get(target, timeout=10, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
        except Exception as e:
            return PluginResult(found=False, evidence=f"Error: {e}")

        # Get raw Set-Cookie headers
        try:
            raw_cookies = r.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw_cookies = []
        if not raw_cookies:
            sc = r.headers.get("Set-Cookie", "")
            raw_cookies = [sc] if sc else []

        if not raw_cookies:
            return PluginResult(found=False, evidence="No Set-Cookie headers found")

        issues = []
        output = []
        is_https = target.startswith("https://")

        for raw in raw_cookies:
            parts = [p.strip() for p in raw.split(";")]
            if not parts:
                continue
            name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
            attrs_lower = [p.lower() for p in parts[1:]]
            sensitive = any(re.search(p, name.lower()) for p in SENSITIVE_PATTERNS)

            if not any("httponly" in a for a in attrs_lower):
                sev = "high" if sensitive else "medium"
                issues.append(f"Cookie '{name}' missing HttpOnly ({sev})")
            if not any("secure" in a for a in attrs_lower):
                sev = "high" if (sensitive and is_https) else "medium"
                issues.append(f"Cookie '{name}' missing Secure flag ({sev})")
            if not any("samesite" in a for a in attrs_lower):
                issues.append(f"Cookie '{name}' missing SameSite attribute")

            output.append(f"Cookie: {name} | Raw: {raw[:100]}")

        if issues:
            worst = "high" if any("high" in i for i in issues) else "medium"
            return PluginResult(
                found=True, title="Insecure Cookie Flags", severity=worst,
                confidence="high", evidence=f"{len(issues)} cookie issues found",
                plugin_output=issues + output,
                request=EvidenceCollector.format_http_request("GET", target),
                response=EvidenceCollector.format_http_response(r.status_code, dict(r.headers)),
                remediation="Set HttpOnly, Secure, and SameSite flags on all sensitive cookies."
            )

        return PluginResult(found=False, evidence="All cookies have proper security flags")
