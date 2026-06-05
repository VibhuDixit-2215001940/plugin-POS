#!/usr/bin/env python3

"""
evidence.py — Evidence Collector for scan findings.

Every plugin finding is saved with full proof:
    - Raw HTTP request sent
    - Raw HTTP response received
    - Server headers snapshot
    - Screenshot (if applicable)
    - Plugin output text
    - Timestamp

This is what makes reports Nessus-grade instead of
simple "version → CVE" correlation reports.

Directory structure per scan:

    findings/<target>_<timestamp>/
        ├── kb.json
        ├── results.json
        ├── evidence/
        │   ├── missing_hsts/
        │   │   ├── request.txt
        │   │   ├── response.txt
        │   │   ├── evidence.json
        │   │   └── screenshot.png
        │   ├── apache_version/
        │   │   ├── request.txt
        │   │   ├── response.txt
        │   │   └── evidence.json
        │   └── ...
        └── screenshots/
"""

import os
import json
from datetime import datetime, timezone


class EvidenceCollector:
    """
    Saves structured evidence for every plugin finding.

    Args:
        scan_dir (str): Root directory for this scan's evidence.
    """

    def __init__(self, scan_dir):
        self.scan_dir = scan_dir
        self.evidence_dir = os.path.join(scan_dir, "evidence")
        self.screenshots_dir = os.path.join(scan_dir, "screenshots")

        os.makedirs(self.evidence_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def save_finding(self, plugin_name, result_dict):
        """
        Save all evidence for a single plugin finding.

        Args:
            plugin_name (str): Plugin name (used as directory name).
            result_dict (dict): PluginResult.to_dict() output.

        Returns:
            str: Path to the evidence directory for this finding.
        """
        # Sanitize plugin name for filesystem
        safe_name = self._sanitize_name(plugin_name)
        finding_dir = os.path.join(self.evidence_dir, safe_name)
        os.makedirs(finding_dir, exist_ok=True)

        # Save raw request
        if result_dict.get("request"):
            request_path = os.path.join(finding_dir, "request.txt")
            with open(request_path, "w", encoding="utf-8") as f:
                f.write(result_dict["request"])

        # Save raw response
        if result_dict.get("response"):
            response_path = os.path.join(finding_dir, "response.txt")
            with open(response_path, "w", encoding="utf-8") as f:
                f.write(result_dict["response"])

        # Save structured evidence JSON
        evidence_data = {
            "plugin_name": plugin_name,
            "found": result_dict.get("found", False),
            "title": result_dict.get("title", ""),
            "severity": result_dict.get("severity", "info"),
            "confidence": result_dict.get("confidence", "low"),
            "evidence": result_dict.get("evidence", ""),
            "plugin_output": result_dict.get("plugin_output", []),
            "cve_refs": result_dict.get("cve_refs", []),
            "remediation": result_dict.get("remediation", ""),
            "screenshot": result_dict.get("screenshot"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        evidence_path = os.path.join(finding_dir, "evidence.json")
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence_data, f, indent=2, default=str)

        return finding_dir

    def save_scan_results(self, results, target):
        """
        Save the complete scan results to a master JSON file.

        Args:
            results (list[dict]): All plugin results.
            target (str): Target URL.
        """
        output = {
            "target": target,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_findings": len([r for r in results if r.get("found")]),
            "total_plugins_run": len(results),
            "findings": results
        }

        results_path = os.path.join(self.scan_dir, "results.json")

        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        return results_path

    @staticmethod
    def _sanitize_name(name):
        """Convert plugin name to a safe directory name."""
        safe = name.lower()
        safe = safe.replace(" ", "_")
        safe = safe.replace("/", "_")
        safe = safe.replace("\\", "_")
        safe = safe.replace(":", "_")
        safe = "".join(c for c in safe if c.isalnum() or c in ("_", "-"))
        return safe[:80]

    @staticmethod
    def format_http_request(method, url, headers=None, body=None):
        """
        Build a human-readable HTTP request string for evidence.

        Args:
            method (str): HTTP method.
            url (str): Request URL.
            headers (dict): Request headers.
            body (str): Request body.

        Returns:
            str: Formatted HTTP request.
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)

        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")

        if headers:
            for key, value in headers.items():
                if key.lower() != "host":
                    lines.append(f"{key}: {value}")

        lines.append("")

        if body:
            lines.append(body)

        return "\n".join(lines)

    @staticmethod
    def format_http_response(status_code, headers, body=None, max_body=2000):
        """
        Build a human-readable HTTP response string for evidence.

        Args:
            status_code (int): HTTP status code.
            headers (dict): Response headers.
            body (str): Response body (truncated).
            max_body (int): Max body characters to include.

        Returns:
            str: Formatted HTTP response.
        """
        lines = [f"HTTP/1.1 {status_code}"]

        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        lines.append("")

        if body:
            truncated = body[:max_body]
            if len(body) > max_body:
                truncated += f"\n\n[... truncated, {len(body)} total bytes ...]"
            lines.append(truncated)

        return "\n".join(lines)
