#!/usr/bin/env python3
"""
default_files.py — Dangerous Files & Panels Discovery Plugin
Loads wordlist from external file data/wordlists/common_paths.txt.
Loads content signatures from data/signatures.yaml.
"""

import requests
import concurrent.futures
import re
import threading
from urllib.parse import urljoin
from core.plugin_base import PluginBase, PluginResult
from core.evidence import EvidenceCollector
from core.data_loader import load_wordlist, get_signatures

requests.packages.urllib3.disable_warnings()
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


class DefaultFileDiscovery(PluginBase):
    name = "Dangerous Files & Panels Discovery"
    family = "discovery"
    severity = "medium"
    description = "Discovers exposed admin panels, config files, backups, and sensitive endpoints"
    depends_on = []

    def detect(self, target, kb):
        # Load wordlist from external file
        wordlist = load_wordlist("common_paths.txt")
        if not wordlist:
            return PluginResult(found=False, evidence="Wordlist not found or empty")

        # Load signatures for content validation
        sigs = get_signatures()
        info_sigs = sigs.get("info_disclosure_signatures", {})

        findings = []
        lock = threading.Lock()

        def check_path(path):
            url = urljoin(target + "/", path.lstrip("/"))
            try:
                r = requests.get(url, headers=UA, timeout=8, verify=False, allow_redirects=True)
                if r.status_code not in [200, 401, 403]:
                    return

                score = 0
                matched_sigs = []

                # Score based on status
                if r.status_code == 200:
                    score += 40
                elif r.status_code in [401, 403]:
                    score += 20

                # Score based on path sensitivity
                critical_paths = [".env", ".git", "backup", "phpinfo", "server-status",
                                  "id_rsa", "credentials", "secret", "actuator", "debug"]
                for keyword in critical_paths:
                    if keyword in path.lower():
                        score += 30

                # Score based on content signatures
                body_lower = r.text.lower()
                for sig_name, sig_data in info_sigs.items():
                    for pattern in sig_data.get("patterns", []):
                        if pattern.lower() in body_lower:
                            score += 20
                            matched_sigs.append(f"{sig_name}: {pattern}")

                if r.status_code == 200 and len(r.text) > 100:
                    score += 10

                if score >= 50:
                    severity = "critical" if score >= 90 else "high" if score >= 70 else "medium"
                    with lock:
                        findings.append({
                            "path": path,
                            "url": url,
                            "status": r.status_code,
                            "score": score,
                            "severity": severity,
                            "content_length": len(r.text),
                            "signatures": matched_sigs
                        })

            except Exception:
                pass

        # Run discovery with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(check_path, wordlist)

        if not findings:
            return PluginResult(found=False, evidence="No sensitive files or panels discovered")

        # Sort by score
        findings.sort(key=lambda x: x["score"], reverse=True)
        worst_severity = findings[0]["severity"]

        output = []
        for f in findings:
            line = f"[{f['status']}] {f['path']} (score: {f['score']}, severity: {f['severity']})"
            output.append(line)
            for sig in f.get("signatures", []):
                output.append(f"  Signature match: {sig}")

        # Store discovered paths in KB
        kb.set("discovered_paths", [f["path"] for f in findings])
        kb.set("discovered_urls", [f["url"] for f in findings])

        return PluginResult(
            found=True,
            title="Dangerous Files & Panels Discovery",
            severity=worst_severity,
            confidence="high",
            evidence=f"{len(findings)} sensitive paths discovered",
            plugin_output=output,
            remediation="Remove or restrict access to exposed files, admin panels, and debug endpoints."
        )
