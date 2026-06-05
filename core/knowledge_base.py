#!/usr/bin/env python3

"""
knowledge_base.py — Central Knowledge Base for the scan engine.

The KB is populated by fingerprint plugins (Phase 2 of the scan)
and queried by all subsequent plugins to decide whether to run
and to access cached scan data.

This is how Nessus avoids redundant requests:
    Plugin 1 → detects Apache/2.4.49 → stores in KB
    Plugin 2 → queries KB["server"] → skips if not Apache
    Plugin 3 → queries KB["server"] → runs Apache-specific CVE check

The KB is persisted to JSON after each scan for evidence/audit trail.
"""

import json
import os
import threading
from datetime import datetime, timezone


class KnowledgeBase:
    """
    Thread-safe in-memory key-value store for scan data.

    Populated incrementally by plugins during the scan.
    Supports nested keys via dot notation: kb.set("tls.version", "1.3")
    """

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()
        self._history = []  # audit trail of all set() calls

    def set(self, key, value):
        """
        Store a value in the KB.

        Args:
            key (str): Dot-separated key (e.g. "server", "tls.version").
            value: Any JSON-serializable value.
        """
        with self._lock:
            keys = key.split(".")

            target = self._store

            for k in keys[:-1]:
                if k not in target or not isinstance(target[k], dict):
                    target[k] = {}
                target = target[k]

            target[keys[-1]] = value

            self._history.append({
                "action": "set",
                "key": key,
                "value": str(value)[:200],
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    def get(self, key, default=None):
        """
        Retrieve a value from the KB.

        Args:
            key (str): Dot-separated key.
            default: Value to return if key doesn't exist.

        Returns:
            The stored value, or default.
        """
        with self._lock:
            keys = key.split(".")
            target = self._store

            for k in keys:
                if isinstance(target, dict) and k in target:
                    target = target[k]
                else:
                    return default

            return target

    def has(self, key):
        """
        Check if a key exists in the KB.

        Args:
            key (str): Dot-separated key.

        Returns:
            bool
        """
        return self.get(key, _SENTINEL) is not _SENTINEL

    def append(self, key, value):
        """
        Append a value to a list stored at key.
        Creates the list if it doesn't exist.

        Args:
            key (str): KB key.
            value: Value to append.
        """
        with self._lock:
            keys = key.split(".")
            target = self._store

            for k in keys[:-1]:
                if k not in target or not isinstance(target[k], dict):
                    target[k] = {}
                target = target[k]

            final_key = keys[-1]

            if final_key not in target:
                target[final_key] = []

            if isinstance(target[final_key], list):
                target[final_key].append(value)

    def dump(self):
        """Return a deep copy of the entire KB as a dict."""
        with self._lock:
            return json.loads(json.dumps(self._store, default=str))

    def save(self, filepath):
        """
        Persist the KB to a JSON file.

        Args:
            filepath (str): Output file path.
        """
        data = {
            "kb": self.dump(),
            "history": self._history,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }

        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def load(self, filepath):
        """
        Load KB data from a previously saved JSON file.

        Args:
            filepath (str): Input file path.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        with self._lock:
            self._store = data.get("kb", {})
            self._history = data.get("history", [])

    def __repr__(self):
        return f"<KnowledgeBase keys={list(self._store.keys())}>"


# Sentinel object for has() checks
_SENTINEL = object()
