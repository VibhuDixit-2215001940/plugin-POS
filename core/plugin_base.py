#!/usr/bin/env python3

"""
plugin_base.py — Base class for all scanner plugins.

Every plugin inherits from PluginBase and overrides detect().
The engine auto-discovers plugin classes and executes them
based on dependency resolution against the Knowledge Base.

Plugins are NOT hardcoded — the engine scans the plugins/
directory tree, imports every module, and collects all
PluginBase subclasses automatically.
"""

from abc import ABC, abstractmethod


class PluginResult:
    """
    Standardized result object returned by every plugin.

    Attributes:
        found (bool):
            Whether the vulnerability/issue was detected.
        title (str):
            Human-readable finding title.
        severity (str):
            critical / high / medium / low / info
        confidence (str):
            high   = active validation succeeded (e.g. got /etc/passwd back)
            medium = strong fingerprint evidence (header, behavior match)
            low    = version correlation only (Nmap version → CVE)
        evidence (str):
            Primary evidence string (e.g. "Server: Apache/2.4.49")
        request (str):
            Raw HTTP request sent.
        response (str):
            Raw HTTP response received (headers + partial body).
        plugin_output (list[str]):
            Nessus-style plugin output lines for the report.
        screenshot (str or None):
            Path to screenshot file, if captured.
        cve_refs (list[str]):
            Associated CVE IDs (e.g. ["CVE-2021-41773"]).
        remediation (str):
            Suggested fix.
    """

    def __init__(
        self,
        found=False,
        title="",
        severity="info",
        confidence="low",
        evidence="",
        request="",
        response="",
        plugin_output=None,
        screenshot=None,
        cve_refs=None,
        remediation=""
    ):
        self.found = found
        self.title = title
        self.severity = severity
        self.confidence = confidence
        self.evidence = evidence
        self.request = request
        self.response = response
        self.plugin_output = plugin_output or []
        self.screenshot = screenshot
        self.cve_refs = cve_refs or []
        self.remediation = remediation

    def to_dict(self):
        return {
            "found": self.found,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "plugin_output": self.plugin_output,
            "screenshot": self.screenshot,
            "cve_refs": self.cve_refs,
            "remediation": self.remediation
        }


class PluginBase(ABC):
    """
    Abstract base class for all scanner plugins.

    Class Attributes:
        name (str):
            Unique human-readable plugin name.
            Example: "Missing HSTS Header"

        family (str):
            Plugin family / category for grouping.
            Example: "http_headers", "injection", "fingerprint", "cve", "session"

        severity (str):
            Default severity: critical / high / medium / low / info

        description (str):
            One-line description of what this plugin checks.

        depends_on (list[str]):
            KB keys that must exist before this plugin runs.
            Example: ["server"] means the KB must have a "server" key.
            Empty list = runs on all targets (no dependencies).

        cve_ids (list[str]):
            CVE IDs this plugin specifically checks for.
            Empty for generic checks (e.g. missing headers).

        risk_factor (str):
            Nessus-style risk factor string.

        references (list[str]):
            URLs to relevant documentation, RFCs, advisories.
    """

    name = ""
    family = ""
    severity = "info"
    description = ""
    depends_on = []
    cve_ids = []
    risk_factor = ""
    references = []

    def should_run(self, kb):
        """
        Override for custom skip logic beyond depends_on.

        The engine calls this AFTER checking depends_on keys.
        Use this for fine-grained conditions, e.g.:

            def should_run(self, kb):
                server = kb.get("server", "")
                return "apache" in server.lower()

        Args:
            kb: KnowledgeBase instance.

        Returns:
            bool: True if this plugin should execute.
        """
        return True

    @abstractmethod
    def detect(self, target, kb):
        """
        Execute the plugin's detection logic.

        Args:
            target (str): Full URL of the target (e.g. "https://example.com").
            kb: KnowledgeBase instance with data from prior plugins.

        Returns:
            PluginResult: Standardized result with evidence.
        """
        raise NotImplementedError

    def __repr__(self):
        return f"<Plugin: {self.name} [{self.family}] severity={self.severity}>"
