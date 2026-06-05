#!/usr/bin/env python3
"""
version_cve_check.py — Generic CVE Correlation Plugin

Maps detected server/software version to known CVEs.
Loads CVE data from external data/cve_database.json.
NOT hardcoded — add new CVEs by editing the JSON file.

This plugin depends on the fingerprint phase having run first.
"""

from core.plugin_base import PluginBase, PluginResult
from core.cve_mapper import CVEMapper


class VersionCVECheck(PluginBase):
    name = "Version-Based CVE Correlation"
    family = "cve"
    severity = "high"
    description = "Maps detected software versions to known CVEs from external database"
    depends_on = ["server"]  # Needs server fingerprint in KB

    def detect(self, target, kb):
        mapper = CVEMapper()
        all_cves = []
        output = []

        # Check server version
        server = kb.get("server", "")
        version = kb.get("server_version", "")

        if server and version:
            cves = mapper.lookup(server, version)
            for cve in cves:
                all_cves.append(cve)
                output.append(
                    f"[{cve['severity'].upper()}] {cve['cve']}: "
                    f"{cve['description']} (affects {server} {version})"
                )

        # Check PHP version
        php_ver = kb.get("php_version", "")
        if php_ver:
            cves = mapper.lookup("php", php_ver)
            for cve in cves:
                all_cves.append(cve)
                output.append(f"[{cve['severity'].upper()}] {cve['cve']}: {cve['description']}")

        # Check CMS version
        cms = kb.get("cms", "")
        cms_ver = kb.get("cms_version", "")
        if cms and cms_ver:
            cves = mapper.lookup(cms, cms_ver)
            for cve in cves:
                all_cves.append(cve)
                output.append(f"[{cve['severity'].upper()}] {cve['cve']}: {cve['description']}")

        if not all_cves:
            output.append(f"No CVEs found for {server} {version}")
            return PluginResult(
                found=False,
                evidence=f"No matching CVEs for detected versions"
            )

        # Determine worst severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        worst = min(all_cves, key=lambda c: sev_order.get(c["severity"], 5))

        cve_ids = [c["cve"] for c in all_cves]
        refs = []
        for c in all_cves:
            refs.extend(c.get("references", []))

        output.insert(0, f"Detection Method: Version Fingerprinting")
        output.insert(1, f"Confidence: Low (version correlation only — not validated)")
        output.insert(2, f"Server: {server} {version}")
        output.insert(3, "")

        server_header = kb.get("server_header", "")

        return PluginResult(
            found=True,
            title=f"Known CVEs for {server} {version}",
            severity=worst["severity"],
            confidence="low",  # Version correlation = low confidence
            evidence=f"{len(all_cves)} CVEs found for {server} {version}: {', '.join(cve_ids)}",
            plugin_output=output,
            cve_refs=cve_ids,
            remediation=f"Upgrade {server} to the latest stable version."
        )
