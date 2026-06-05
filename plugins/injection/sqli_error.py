#!/usr/bin/env python3
"""
sqli_error.py — Error-Based SQL Injection Detection Plugin

Injects payloads from external data/payloads.yaml into discovered parameters
and checks for SQL error signatures from data/signatures.yaml.
Fully data-driven — no hardcoded payloads or signatures.
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import get_payloads, get_signatures

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0"}


class SQLInjectionErrorBased(PluginBase):
    name = "SQL Injection (Error-Based)"
    family = "injection"
    severity = "critical"
    description = "Tests URL parameters for error-based SQL injection using external payloads"
    depends_on = []

    def detect(self, target, kb):
        payloads_data = get_payloads()
        sigs_data = get_signatures()

        sqli_payloads = payloads_data.get("sqli", {}).get("error_based", [])
        sql_sigs = sigs_data.get("sql_error_signatures", {})

        if not sqli_payloads:
            return PluginResult(found=False, evidence="No SQLi payloads loaded")

        # Flatten all SQL error patterns
        all_patterns = []
        for db_type, patterns in sql_sigs.items():
            for p in patterns:
                all_patterns.append((db_type, p.lower()))

        # Discover parameters from the target URL
        parsed = urlparse(target)
        params = parse_qs(parsed.query)

        # Also try common parameter names if URL has no params
        if not params:
            common_params = ["id", "page", "q", "search", "user", "name", "item", "cat", "category"]
            for param in common_params:
                test_url = f"{target}{'&' if '?' in target else '?'}{param}=1"
                result = self._test_url(test_url, param, sqli_payloads, all_patterns)
                if result:
                    return result
            return PluginResult(found=False, evidence="No parameters to test and no injection points found")

        # Test each existing parameter
        for param_name in params:
            for payload in sqli_payloads[:5]:  # Limit payloads per param for speed
                test_params = dict(params)
                test_params[param_name] = [payload]

                query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = requests.get(test_url, headers=UA, timeout=10, verify=False)
                    body_lower = r.text.lower()

                    for db_type, pattern in all_patterns:
                        if pattern in body_lower:
                            req = EvidenceCollector.format_http_request("GET", test_url, UA)
                            resp = EvidenceCollector.format_http_response(
                                r.status_code, dict(r.headers), r.text
                            )
                            return PluginResult(
                                found=True,
                                title=f"SQL Injection (Error-Based) — {db_type}",
                                severity="critical",
                                confidence="high",
                                evidence=f"SQL error signature detected ({db_type}): {pattern}",
                                request=req, response=resp,
                                plugin_output=[
                                    f"Parameter: {param_name}",
                                    f"Payload: {payload}",
                                    f"Database: {db_type}",
                                    f"Error Pattern: {pattern}",
                                    f"URL: {test_url}"
                                ],
                                remediation="Use parameterized queries / prepared statements."
                            )
                except Exception:
                    continue

        return PluginResult(found=False, evidence="No SQL injection detected in tested parameters")

    def _test_url(self, url, param, payloads, patterns):
        """Test a specific URL+param combo."""
        for payload in payloads[:3]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))

            try:
                r = requests.get(test_url, headers=UA, timeout=8, verify=False)
                body_lower = r.text.lower()
                for db_type, pattern in patterns:
                    if pattern in body_lower:
                        return PluginResult(
                            found=True,
                            title=f"SQL Injection (Error-Based) — {db_type}",
                            severity="critical", confidence="high",
                            evidence=f"SQL error: {pattern}",
                            plugin_output=[f"Param: {param}", f"Payload: {payload}", f"DB: {db_type}"],
                            remediation="Use parameterized queries."
                        )
            except Exception:
                continue
        return None
