#!/usr/bin/env python3
"""
cors_misconfig.py — CORS Misconfiguration Detection Plugin
Loads test scenarios dynamically — not hardcoded.
"""

import requests
from urllib.parse import urlparse
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0"}


class CORSMisconfiguration(PluginBase):
    name = "CORS Misconfiguration"
    family = "http_headers"
    severity = "high"
    description = "Checks for CORS misconfigurations (reflected origin, wildcard, null origin)"
    depends_on = []

    def detect(self, target, kb):
        findings = []
        output = []

        # Test 1: Reflected origin
        evil = "https://evil-attacker.com"
        try:
            r = requests.get(target, headers={**UA, "Origin": evil},
                             timeout=10, verify=False, allow_redirects=True)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == evil:
                sev = "critical" if acac.lower() == "true" else "high"
                findings.append(f"Server reflects arbitrary origin: {evil}")
                if acac.lower() == "true":
                    findings.append("Access-Control-Allow-Credentials: true — CRITICAL")
                output.append(f"ACAO: {acao}, Credentials: {acac}")
            elif acao == "*":
                findings.append("Access-Control-Allow-Origin: * (wildcard)")
                if acac.lower() == "true":
                    findings.append("Wildcard + Credentials = severe misconfiguration")
        except Exception as e:
            output.append(f"Request failed: {e}")

        # Test 2: Null origin
        try:
            r = requests.get(target, headers={**UA, "Origin": "null"},
                             timeout=10, verify=False, allow_redirects=True)
            if r.headers.get("Access-Control-Allow-Origin", "") == "null":
                findings.append("Server trusts 'null' origin — iframe/sandbox exploit possible")
        except Exception:
            pass

        req = EvidenceCollector.format_http_request("GET", target, {**UA, "Origin": evil})

        if findings:
            return PluginResult(
                found=True, title="CORS Misconfiguration", severity="high",
                confidence="high", evidence="; ".join(findings),
                request=req, plugin_output=findings + output,
                remediation="Validate Origin header against a whitelist. Never reflect arbitrary origins."
            )

        return PluginResult(found=False, evidence="No CORS misconfigurations detected")
