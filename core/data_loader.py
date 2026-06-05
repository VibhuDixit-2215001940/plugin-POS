#!/usr/bin/env python3
"""
data_loader.py - Loads external YAML/JSON data files for plugins.
Central utility so plugins never hardcode signatures, payloads, or CVE data.
"""

import os
import json

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# Try to import yaml, fall back to a simple parser
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def load_yaml(filename):
    """Load a YAML file from the data/ directory."""
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        print(f"[!] Data file not found: {filepath}")
        return {}
    with open(filepath, "r", encoding="utf-8") as f:
        if HAS_YAML:
            return yaml.safe_load(f) or {}
        else:
            # Minimal fallback: try JSON
            try:
                return json.load(f)
            except Exception:
                print(f"[!] PyYAML not installed and {filename} is not JSON. pip install pyyaml")
                return {}


def load_json(filename):
    """Load a JSON file from the data/ directory."""
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        print(f"[!] Data file not found: {filepath}")
        return {}
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_wordlist(filename):
    """Load a text wordlist from the data/wordlists/ directory."""
    filepath = os.path.join(DATA_DIR, "wordlists", filename)
    if not os.path.exists(filepath):
        print(f"[!] Wordlist not found: {filepath}")
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def get_signatures():
    """Load all signatures from signatures.yaml."""
    return load_yaml("signatures.yaml")


def get_payloads():
    """Load all payloads from payloads.yaml."""
    return load_yaml("payloads.yaml")


def get_cve_database():
    """Load CVE database from cve_database.json."""
    return load_json("cve_database.json")
