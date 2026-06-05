"""
Core engine for the Nessus-style plugin-based vulnerability scanner.

Modules:
    plugin_base     - Base class all plugins inherit from
    knowledge_base  - Central KB populated by fingerprint plugins, queried by all
    evidence        - Saves raw request/response/screenshots per finding
    engine          - Auto-discovers plugins, resolves dependencies, runs in parallel
    cve_mapper      - Maps detected versions to CVEs from external JSON database
    reporter        - Generates HTML/JSON reports with evidence
"""
