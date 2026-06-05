#!/usr/bin/env python3
"""
lfi_check.py — Local File Inclusion Detection Plugin
Payloads and success patterns from external data/payloads.yaml.
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import get_payloads

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0"}


class LFICheck(PluginBase):
    name = "Local File Inclusion (LFI)"
    family = "injection"
    severity = "critical"
    description = "Tests for local file inclusion using external payloads"
    depends_on = []

    def detect(self, target, kb):
        payloads_data = get_payloads()
        lfi_payloads = payloads_data.get("lfi", {}).get("unix", [])
        lfi_payloads += payloads_data.get("lfi", {}).get("windows", [])
        success_patterns = payloads_data.get("lfi_success_patterns", {})

        unix_patterns = success_patterns.get("unix", [])
        win_patterns = success_patterns.get("windows", [])
        all_success = [(p, "unix") for p in unix_patterns] + [(p, "windows") for p in win_patterns]

        if not lfi_payloads:
            return PluginResult(found=False, evidence="No LFI payloads loaded")

        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        test_params = list(params.keys()) if params else ["file", "page", "path", "include", "doc", "template", "view"]

        for param in test_params:
            for payload in lfi_payloads:
                if params:
                    test_p = dict(params)
                    test_p[param] = [payload]
                else:
                    test_p = {param: [payload]}

                query = urlencode(test_p, doseq=True)
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = requests.get(test_url, headers=UA, timeout=8, verify=False)
                    body = r.text

                    for pattern, os_type in all_success:
                        if pattern in body:
                            req = EvidenceCollector.format_http_request("GET", test_url, UA)
                            resp = EvidenceCollector.format_http_response(
                                r.status_code, dict(r.headers), body
                            )
                            return PluginResult(
                                found=True, title=f"Local File Inclusion ({os_type.upper()})",
                                severity="critical", confidence="high",
                                evidence=f"LFI success pattern found: {pattern}",
                                request=req, response=resp,
                                plugin_output=[
                                    f"Parameter: {param}", f"Payload: {payload}",
                                    f"OS: {os_type}", f"Pattern matched: {pattern}",
                                    f"URL: {test_url}"
                                ],
                                remediation="Never use user input in file paths. Use a whitelist of allowed files."
                            )
                except Exception:
                    continue

        return PluginResult(found=False, evidence="No LFI detected")


class OpenRedirectCheck(PluginBase):
    name = "Open Redirect"
    family = "injection"
    severity = "medium"
    description = "Tests for open redirect vulnerabilities using external payloads"
    depends_on = []

    def detect(self, target, kb):
        payloads_data = get_payloads()
        redirect_payloads = payloads_data.get("open_redirect", {}).get("payloads", [])
        redirect_params = payloads_data.get("open_redirect", {}).get("parameter_names", [])

        if not redirect_payloads or not redirect_params:
            return PluginResult(found=False, evidence="No redirect payloads loaded")

        for param in redirect_params:
            for payload in redirect_payloads[:3]:
                test_url = f"{target}{'&' if '?' in target else '?'}{param}={payload}"

                try:
                    r = requests.get(test_url, headers=UA, timeout=8, verify=False,
                                     allow_redirects=False)

                    location = r.headers.get("Location", "")
                    if location and ("evil.com" in location):
                        return PluginResult(
                            found=True, title="Open Redirect",
                            severity="medium", confidence="high",
                            evidence=f"Redirects to attacker-controlled URL: {location}",
                            plugin_output=[f"Param: {param}", f"Payload: {payload}",
                                           f"Location: {location}", f"URL: {test_url}"],
                            remediation="Validate redirect destinations against a whitelist."
                        )
                except Exception:
                    continue

        return PluginResult(found=False, evidence="No open redirect detected")
