#!/usr/bin/env python3
"""
technology_detect.py — Technology Detection Plugin

Detects CMS, frameworks, and libraries from HTML content and headers.
Loads patterns from data/signatures.yaml (not hardcoded).
"""

import re
import requests

from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import get_signatures

requests.packages.urllib3.disable_warnings()


class TechnologyDetection(PluginBase):

    name = "Technology Detection"
    family = "fingerprint"
    severity = "info"
    description = "Detects CMS, frameworks, and client-side libraries"
    depends_on = []

    def detect(self, target, kb):
        signatures = get_signatures()
        tech_sigs = signatures.get("technology_patterns", {})

        try:
            response = requests.get(
                target, timeout=10, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
        except Exception as e:
            return PluginResult(found=False, evidence=f"Connection failed: {e}")

        html = response.text.lower()
        headers_str = str(response.headers).lower()
        detected = []
        output_lines = []

        for tech_name, sig_data in tech_sigs.items():
            found_tech = False

            # Check HTML patterns
            for pattern in sig_data.get("html_patterns", []):
                if pattern.lower() in html:
                    found_tech = True
                    break

            # Check header patterns
            if not found_tech:
                for pattern in sig_data.get("header_patterns", []):
                    if pattern.lower() in headers_str:
                        found_tech = True
                        break

            if found_tech:
                detected.append(tech_name)
                version = ""
                version_regex = sig_data.get("version_regex")
                if version_regex:
                    # Search in HTML and headers
                    match = re.search(version_regex, response.text, re.IGNORECASE)
                    if not match:
                        match = re.search(version_regex, str(response.headers), re.IGNORECASE)
                    if match:
                        version = match.group(1)

                if version:
                    output_lines.append(f"Detected: {tech_name} v{version}")
                    kb.set(f"tech.{tech_name}", version)
                else:
                    output_lines.append(f"Detected: {tech_name}")
                    kb.set(f"tech.{tech_name}", "detected")

                # Set CMS-specific KB keys
                if tech_name in ("wordpress", "drupal", "joomla"):
                    kb.set("cms", tech_name)
                    if version:
                        kb.set("cms_version", version)

        if not detected:
            output_lines = ["No specific technologies identified from HTML/headers."]

        # Store full tech list in KB
        kb.set("technologies", detected)

        req_text = EvidenceCollector.format_http_request("GET", target)
        resp_text = EvidenceCollector.format_http_response(
            response.status_code, dict(response.headers), response.text
        )

        return PluginResult(
            found=bool(detected),
            title="Technology Detection",
            severity="info",
            confidence="medium",
            evidence=f"Technologies detected: {', '.join(detected)}" if detected else "None",
            request=req_text,
            response=resp_text,
            plugin_output=output_lines,
            remediation="Remove unnecessary version information from HTML source and headers."
        )
