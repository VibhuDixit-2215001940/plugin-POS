#!/usr/bin/env python3
"""
xss_reflected.py — Reflected XSS Detection Plugin
Payloads loaded from external data/payloads.yaml.
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import get_payloads

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0"}


class ReflectedXSS(PluginBase):
    name = "Reflected Cross-Site Scripting (XSS)"
    family = "injection"
    severity = "high"
    description = "Tests URL parameters for reflected XSS using external payloads"
    depends_on = []

    def detect(self, target, kb):
        payloads_data = get_payloads()
        xss_payloads = payloads_data.get("xss", {}).get("reflected", [])

        if not xss_payloads:
            return PluginResult(found=False, evidence="No XSS payloads loaded")

        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        # If no params in URL, try common ones
        test_params = list(params.keys()) if params else ["q", "search", "s", "query", "name", "id", "page"]

        for param in test_params:
            for payload in xss_payloads[:4]:
                if params:
                    test_p = dict(params)
                    test_p[param] = [payload]
                else:
                    test_p = {param: [payload]}

                query = urlencode(test_p, doseq=True)
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = requests.get(test_url, headers=UA, timeout=8, verify=False)

                    # Check if payload is reflected unencoded
                    if payload in r.text:
                        req = EvidenceCollector.format_http_request("GET", test_url, UA)
                        resp = EvidenceCollector.format_http_response(
                            r.status_code, dict(r.headers), r.text
                        )
                        return PluginResult(
                            found=True,
                            title="Reflected XSS",
                            severity="high",
                            confidence="high",
                            evidence=f"XSS payload reflected unencoded in response",
                            request=req, response=resp,
                            plugin_output=[
                                f"Parameter: {param}",
                                f"Payload: {payload}",
                                f"URL: {test_url}",
                                "Payload was reflected WITHOUT encoding in the response body."
                            ],
                            remediation="Encode all user input before rendering. Implement CSP."
                        )
                except Exception:
                    continue

        return PluginResult(found=False, evidence="No reflected XSS detected")
