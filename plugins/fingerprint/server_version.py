#!/usr/bin/env python3
"""
server_version.py — Server Version Fingerprint Plugin

Detects web server type and version from HTTP headers.
Stores results in KB for downstream plugins to use.
Loads detection patterns from data/signatures.yaml (not hardcoded).

This is the MOST IMPORTANT plugin — it runs first and
populates the KB that all other plugins depend on.
"""

import re
import requests

from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import get_signatures

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0 Safari/537.36"
    )
}


class ServerVersionDetection(PluginBase):

    name = "Server Version Detection"
    family = "fingerprint"
    severity = "info"
    description = "Detects web server type and version from HTTP response headers"
    depends_on = []  # No dependencies — runs first
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]

    def detect(self, target, kb):
        signatures = get_signatures()
        server_sigs = signatures.get("server_headers", {})

        try:
            response = requests.get(
                target, headers=HEADERS, timeout=10,
                verify=False, allow_redirects=True
            )
        except Exception as e:
            return PluginResult(found=False, evidence=f"Connection failed: {e}")

        server_header = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        via_header = response.headers.get("Via", "")
        aspnet_ver = response.headers.get("X-AspNet-Version", "")

        # Build request/response evidence
        req_text = EvidenceCollector.format_http_request("GET", target, HEADERS)
        resp_text = EvidenceCollector.format_http_response(
            response.status_code, dict(response.headers), response.text
        )

        # Detect server type and version from external signatures
        detected_server = ""
        detected_version = ""
        output_lines = []

        for server_name, sig_data in server_sigs.items():
            patterns = sig_data.get("patterns", [])
            version_regex = sig_data.get("version_regex")

            for pattern in patterns:
                if pattern.lower() in server_header.lower():
                    detected_server = server_name
                    output_lines.append(f"Server Type: {server_name}")
                    output_lines.append(f"Server Header: {server_header}")

                    # Extract version
                    if version_regex and server_header:
                        match = re.search(version_regex, server_header)
                        if match:
                            detected_version = match.group(1)
                            output_lines.append(f"Version: {detected_version}")
                    break
            if detected_server:
                break

        # Store in KB for downstream plugins
        if detected_server:
            kb.set("server", detected_server)
        if detected_version:
            kb.set("server_version", detected_version)
        if server_header:
            kb.set("server_header", server_header)
        if powered_by:
            kb.set("powered_by", powered_by)
            output_lines.append(f"X-Powered-By: {powered_by}")

            # Check if PHP version
            php_match = re.search(r"PHP/([0-9.]+)", powered_by)
            if php_match:
                kb.set("php_version", php_match.group(1))
                output_lines.append(f"PHP Version: {php_match.group(1)}")

        if aspnet_ver:
            kb.set("aspnet_version", aspnet_ver)
            output_lines.append(f"ASP.NET Version: {aspnet_ver}")

        if via_header:
            kb.set("via_header", via_header)

        # Store all response headers in KB
        kb.set("response_headers", dict(response.headers))
        kb.set("status_code", response.status_code)
        kb.set("final_url", response.url)

        found = bool(server_header or powered_by)
        evidence = server_header or powered_by or "No server information disclosed"

        if not output_lines:
            output_lines = [
                "Server header not disclosed or unrecognized.",
                f"Raw Server header: {server_header or 'Not present'}"
            ]

        return PluginResult(
            found=found,
            title="Server Version Detection",
            severity="info",
            confidence="high" if detected_version else "medium",
            evidence=evidence,
            request=req_text,
            response=resp_text,
            plugin_output=output_lines,
            cve_refs=[],
            remediation="Configure the web server to suppress version information in HTTP headers."
        )
