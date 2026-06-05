#!/usr/bin/env python3
"""
cve_mapper.py - Maps detected software versions to known CVEs.
Loads CVE data from external JSON file (data/cve_database.json).
NOT hardcoded — add new CVEs by editing the JSON file.
"""

import os
import re
import json
from packaging.version import Version, InvalidVersion


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFAULT_CVE_DB = os.path.join(DATA_DIR, "cve_database.json")


class CVEMapper:
    """
    Maps software name + version to known CVEs from an external database.

    The CVE database (data/cve_database.json) has the structure:
    {
        "apache": [
            {
                "cve": "CVE-2021-41773",
                "affected_versions": {"min": "2.4.49", "max": "2.4.49"},
                "severity": "critical",
                "description": "Path traversal in Apache 2.4.49",
                "references": ["https://..."]
            }
        ]
    }
    """

    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_CVE_DB
        self.database = {}
        self._load_database()

    def _load_database(self):
        """Load CVE database from JSON file."""
        if not os.path.exists(self.db_path):
            print(f"[!] CVE database not found: {self.db_path}")
            return

        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                self.database = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load CVE database: {e}")

    def lookup(self, software, version_str):
        """
        Find CVEs affecting the given software version.

        Args:
            software (str): Software name (e.g. "apache", "nginx").
            version_str (str): Version string (e.g. "2.4.49").

        Returns:
            list[dict]: Matching CVE entries.
        """
        software_key = software.lower().strip()
        entries = self.database.get(software_key, [])

        if not entries:
            # Try partial match
            for key in self.database:
                if software_key in key or key in software_key:
                    entries = self.database[key]
                    break

        if not entries:
            return []

        matches = []
        for entry in entries:
            if self._version_in_range(version_str, entry.get("affected_versions", {})):
                matches.append(entry)

        return matches

    def _version_in_range(self, version_str, affected):
        """Check if version falls within the affected range."""
        if not affected:
            return False

        min_ver = affected.get("min", "0")
        max_ver = affected.get("max", "999.999.999")

        try:
            v = self._parse_version(version_str)
            v_min = self._parse_version(min_ver)
            v_max = self._parse_version(max_ver)
            return v_min <= v <= v_max
        except Exception:
            # Fallback to string comparison
            return version_str == min_ver or version_str == max_ver

    @staticmethod
    def _parse_version(ver_str):
        """Parse version string, handling non-standard formats."""
        # Strip common prefixes
        ver_str = re.sub(r'^[vV]', '', ver_str.strip())
        # Keep only version-like chars
        ver_str = re.split(r'[^0-9.]', ver_str)[0]
        if not ver_str:
            ver_str = "0"
        try:
            return Version(ver_str)
        except InvalidVersion:
            # Split into numeric tuple for comparison
            parts = []
            for p in ver_str.split("."):
                try:
                    parts.append(int(p))
                except ValueError:
                    parts.append(0)
            return tuple(parts)

    def get_all_software(self):
        """Return list of all software names in the database."""
        return list(self.database.keys())

    def get_cve_count(self):
        """Return total number of CVE entries."""
        return sum(len(v) for v in self.database.values())
