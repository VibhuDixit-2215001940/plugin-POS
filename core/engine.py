#!/usr/bin/env python3
import sys, io
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
"""
engine.py - Scan Engine: auto-discovery, dependency resolution, parallel execution.
Nothing hardcoded. Plugins are auto-loaded from plugins/ directory tree.
"""

import os
import sys
import importlib
import inspect
import traceback
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from core.plugin_base import PluginBase, PluginResult
from core.knowledge_base import KnowledgeBase
from core.evidence import EvidenceCollector


class ScanEngine:
    def __init__(self, target, plugins_dir="plugins", output_dir="findings",
                 max_workers=20, families=None):
        self.target = self._normalize_target(target)
        self.plugins_dir = os.path.abspath(plugins_dir)
        self.max_workers = max_workers
        self.families_filter = families
        self.kb = KnowledgeBase()
        self.all_plugins = []
        self.results = []

        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_dir = os.path.join(os.path.abspath(output_dir),
                                     f"{safe_target}_{timestamp}")
        self.evidence = EvidenceCollector(self.scan_dir)

    def discover_plugins(self):
        """Recursively scan plugins/ dir and import all PluginBase subclasses."""
        discovered = []
        if not os.path.isdir(self.plugins_dir):
            print(f"[!] Plugins directory not found: {self.plugins_dir}")
            return discovered

        project_root = os.path.dirname(self.plugins_dir)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)

        for root, dirs, files in os.walk(self.plugins_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for filename in files:
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, project_root)
                module_name = rel_path.replace(os.sep, ".")
                if module_name.endswith(".py"):
                    module_name = module_name[:-3]
                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (inspect.isclass(attr) and issubclass(attr, PluginBase)
                                and attr is not PluginBase and attr.name):
                            discovered.append(attr())
                except Exception as e:
                    print(f"[!] Failed to load {module_name}: {e}")

        self.all_plugins = discovered
        return discovered

    def resolve_dependencies(self, plugins):
        """Filter plugins whose KB dependencies are not met."""
        runnable, skipped = [], []
        for plugin in plugins:
            if self.families_filter and plugin.family not in self.families_filter:
                skipped.append((plugin, "family filtered"))
                continue
            missing = [d for d in plugin.depends_on if not self.kb.has(d)]
            if missing:
                skipped.append((plugin, f"missing KB: {missing}"))
                continue
            try:
                if not plugin.should_run(self.kb):
                    skipped.append((plugin, "should_run=False"))
                    continue
            except Exception as e:
                skipped.append((plugin, f"should_run error: {e}"))
                continue
            runnable.append(plugin)
        return runnable, skipped

    def _execute_plugin(self, plugin):
        """Execute a single plugin with error handling."""
        start = time.time()
        try:
            result = plugin.detect(self.target, self.kb)
            if isinstance(result, PluginResult):
                rd = result.to_dict()
            elif isinstance(result, dict):
                rd = result
            else:
                rd = {"found": False, "evidence": "Invalid result type"}
        except Exception as e:
            rd = {"found": False, "evidence": f"Error: {e}",
                  "plugin_output": [str(e), traceback.format_exc()]}

        rd["plugin_name"] = plugin.name
        rd["plugin_family"] = plugin.family
        rd["plugin_severity"] = plugin.severity
        rd["plugin_description"] = plugin.description
        rd["plugin_cve_ids"] = plugin.cve_ids
        rd["plugin_references"] = plugin.references
        rd["execution_time"] = round(time.time() - start, 3)
        if rd.get("found") and not rd.get("title"):
            rd["title"] = plugin.name
        if rd.get("found"):
            self.evidence.save_finding(plugin.name, rd)
        return rd

    def run(self):
        """Full scan pipeline: discover → fingerprint → resolve → parallel execute → report."""
        scan_start = time.time()
        print("=" * 70)
        print("  NESSUS-STYLE PLUGIN SCANNER")
        print("=" * 70)
        print(f"  Target  : {self.target}")
        print(f"  Workers : {self.max_workers}")
        print("=" * 70)

        # Step 1: Discover
        print("\n[Phase 1] Discovering plugins...")
        plugins = self.discover_plugins()
        print(f"  Found {len(plugins)} plugins")
        if not plugins:
            print("[!] No plugins found.")
            return []

        families = {}
        for p in plugins:
            families.setdefault(p.family, []).append(p)
        for fam, members in sorted(families.items()):
            print(f"  [{fam}] {', '.join(m.name for m in members)}")

        # Step 2: Run fingerprint plugins first
        fp_plugins = [p for p in plugins if p.family == "fingerprint"]
        other = [p for p in plugins if p.family != "fingerprint"]
        print(f"\n[Phase 2] Running {len(fp_plugins)} fingerprint plugins...")
        for plugin in fp_plugins:
            print(f"  Running: {plugin.name}...")
            result = self._execute_plugin(plugin)
            self.results.append(result)
            status = "✓" if result.get("found") else "·"
            print(f"    {status} {result.get('evidence', '')[:80]}")

        # Step 3: Resolve dependencies
        print(f"\n[Phase 3] Resolving deps for {len(other)} plugins...")
        runnable, skipped = self.resolve_dependencies(other)
        print(f"  Runnable: {len(runnable)} | Skipped: {len(skipped)}")
        for p, reason in skipped:
            print(f"    SKIP: {p.name} — {reason}")

        # Step 4: Parallel execution
        print(f"\n[Phase 4] Executing {len(runnable)} plugins...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._execute_plugin, p): p for p in runnable}
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    if result.get("found"):
                        sev = result.get("severity", result.get("plugin_severity", "info"))
                        print(f"  ✓ [{sev.upper()}] {plugin.name}")
                    else:
                        print(f"  · {plugin.name}")
                except Exception as e:
                    print(f"  ✗ {plugin.name}: {e}")

        # Step 5: Save
        elapsed = round(time.time() - scan_start, 2)
        self.kb.set("scan.target", self.target)
        self.kb.set("scan.duration", elapsed)
        self.kb.save(os.path.join(self.scan_dir, "kb.json"))
        results_path = self.evidence.save_scan_results(self.results, self.target)

        findings = [r for r in self.results if r.get("found")]
        print("\n" + "=" * 70)
        print(f"  SCAN COMPLETE | {elapsed}s | {len(findings)} findings")
        print(f"  Results: {results_path}")
        print("=" * 70)
        return self.results

    @staticmethod
    def _normalize_target(target):
        target = target.strip().rstrip("/")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target
