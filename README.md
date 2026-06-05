<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Security-Scanner-EF4444?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Security"/>
  <img src="https://img.shields.io/badge/Architecture-Plugin--Based-0052CC?style=for-the-badge&logo=architecture" alt="Architecture"/>
  <img src="https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🛡️ Nessus-Style Plugin Vulnerability Scanner</h1>

<p align="center">
  <b>A modular, dependency-driven web vulnerability scanner architecture featuring an dynamic plugin auto-loader, centralized knowledge base (KB), standardized evidence collector, and version-to-CVE mapper.</b>
</p>

<p align="center">
  <i>Identify. Validate. Collect Proof. Report.</i>
</p>

---

## 📖 Overview

This repository hosts a **Nessus-Style Plugin-Based Vulnerability Scanner**. Moving away from hardcoded security checking scripts, this framework implements a modern security tool pipeline:
1. **Dynamic Plugin Auto-Discovery:** Scans and imports all plugins on launch. Adding a new check is as simple as dropping a `.py` file into the `plugins/` folder.
2. **Centralized Knowledge Base (KB):** Caches information gathered by reconnaissance and fingerprinting plugins to avoid sending redundant HTTP requests.
3. **Nessus-Style Dependency Resolution:** Checks KB requirements and skips plugins target-incompatible with the active system, ensuring high-speed scanning (e.g. skipping Apache-specific CVE checks on a IIS target).
4. **Standardized Evidence Collection Layer:** Saves raw HTTP requests, response headers, and partial response bodies as proof of vulnerabilities for audit reporting.
5. **Data-Driven Signatures & Payloads:** Detection patterns, SQL error signatures, XSS/LFI/Command injection payloads, and target paths are loaded from external configuration files (`.yaml`, `.json`, `.txt`) rather than being hardcoded in code.

---

## 🏗️ Project Architecture

```
HEADERS/
│
├── 🧠 core/                    # Core Scanning Engine
│   ├── plugin_base.py          # Base plugin interface and PluginResult structures
│   ├── knowledge_base.py       # Thread-safe in-memory key-value store & history log
│   ├── engine.py               # Orchestrator (auto-discovery, dependencies, parallel worker pool)
│   ├── evidence.py             # File-based evidence saver (request/response/metadata logger)
│   ├── cve_mapper.py           # Software version parser and CVE matching engine
│   ├── reporter.py             # Dark-mode styled HTML & structured JSON report generator
│   └── data_loader.py          # Loader helper for external assets (YAML/JSON/wordlists)
│
├── 🛡️ plugins/                 # Auto-Discovered Scanner Plugins
│   ├── fingerprint/            # Reconnaissance & technology classifiers
│   │   ├── server_version.py   # Web server banner detection & version extractor
│   │   └── technology_detect.py# CMS (WordPress, Drupal, etc.) & framework detection
│   ├── http_headers/           # HTTP Header auditing plugins
│   │   ├── missing_hsts.py     # HSTS implementation checker
│   │   ├── missing_csp.py      # Content-Security-Policy structural evaluator
│   │   ├── security_headers.py # XFO, X-Content-Type, Referrer-Policy, and OPTIONS method checker
│   │   └── cors_misconfig.py   # CORS reflected origin & null origin vulnerability tester
│   ├── session/                # Cookie flag & session verification
│   │   └── cookie_flags.py     # HttpOnly, Secure, & SameSite cookie audit tool
│   ├── discovery/              # File and panel path scanner
│   │   └── default_files.py    # Multi-threaded URL path finder using scoring algorithms
│   ├── injection/              # Active vulnerability validation
│   │   ├── sqli_error.py       # Error-based SQL injection vulnerability scanner
│   │   ├── xss_reflected.py    # Reflected XSS auditor
│   │   └── lfi_check.py        # Local File Inclusion & Open Redirect validator
│   └── cve/                    # Version correlation plugins
│       └── version_cve_check.py# Software version mapping to NVD CVE entries
│
├── 📊 data/                    # External Database & Payload Files
│   ├── cve_database.json       # Version correlation CVE definitions
│   ├── signatures.yaml         # Server header patterns & tech signatures
│   ├── payloads.yaml           # SQLi, XSS, LFI, CMDi, and Redirect payloads
│   └── wordlists/
│       └── common_paths.txt    # Directory discovery wordlist (150+ paths)
│
├── 📊 findings/                # Scan Output Artifacts (generated per scan)
│   └── <target>_<timestamp>/
│       ├── kb.json             # Serialized knowledge base configuration
│       ├── results.json        # Compiled results output
│       ├── report.html         # Rich dark-mode HTML report
│       ├── report.json         # Master findings list
│       └── evidence/           # Subfolders containing raw request.txt and response.txt per finding
│
├── 🚀 main_scanner.py          # CLI entry point
└── 📄 README.md                # System documentation
```

---

## 🚀 How to Run the Scanner (Scanner Run Guide)

### 1. Installation & Prerequisites

This project uses Python 3.x. Install the required Python packages first:

```bash
# Clone or navigate to the directory
cd HEADERS

# Install python dependencies
pip install requests pyyaml packaging
```

### 2. Basic Scan

To run a scan against a target, execute `main_scanner.py`. If no target is specified, it will interactively prompt you for one:

```bash
# Run interactively
python main_scanner.py

# Or specify target directly via CLI
python main_scanner.py -t example.com
```

### 3. Advanced CLI Configuration

The CLI supports filtering plugins by family, configuring parallel execution speed, and targeting custom output locations:

```bash
# Run ONLY fingerprinting and HTTP header checks
python main_scanner.py -t example.com -f fingerprint,http_headers

# Adjust speed using thread workers (default is 20)
python main_scanner.py -t example.com -w 40

# Force standard CLI output styling on Windows console encodings
python -X utf8 main_scanner.py -t example.com
```

### 4. Viewing Results & Reports

Once a scan finishes, a target-specific directory is created in the `findings/` folder:

- **Interactive HTML Report:** Open the generated `report.html` in your web browser. It displays findings sorted by severity (Critical, High, Medium, Low, Info) featuring confidence scores and remediation.
- **Evidence Files:** Under `findings/<target>_<timestamp>/evidence/<plugin_name>/` you will find:
  - `request.txt`: The exact raw HTTP request sent.
  - `response.txt`: The exact raw HTTP response headers and body payload returned.
  - `evidence.json`: Contextual finding parameters.
- **Knowledge Base (KB):** Inspect `kb.json` to view the variables and version history populated during discovery.

---

## 🛠️ Adding New Checks (No Code Changes Required)

Since the scanner separates plugin logic from vulnerability payloads and signatures, you don't need to rewrite code to update the detection databases:

### Adding New Vulnerability Payloads
Open `data/payloads.yaml` and add your payloads under the appropriate category:
```yaml
sqli:
  error_based:
    - "'"
    - "'; SELECT pg_sleep(5)--"
```

### Adding New Web Technologies & Server Headers
Open `data/signatures.yaml` to include new regexes or html identification keywords:
```yaml
technology_patterns:
  wordpress:
    html_patterns:
      - "wp-content"
    version_regex: "WordPress ([0-9.]+)"
```

### Adding New CVE Definitions
Open `data/cve_database.json` and append CVE objects specifying target software and range bounds:
```json
"nginx": [
  {
    "cve": "CVE-2022-41741",
    "affected_versions": {"min": "1.1.3", "max": "1.23.1"},
    "severity": "high",
    "description": "Memory corruption in nginx mp4 module"
  }
]
```

### Writing a Custom Python Plugin
To write a new plugin, simply create a new `.py` file inside `plugins/<family>/`. Inherit from `PluginBase` and override `detect`:

```python
from core.plugin_base import PluginBase, PluginResult

class MyCustomCheck(PluginBase):
    name = "My Custom Header Check"
    family = "http_headers"
    severity = "medium"
    description = "Checks for my custom header"
    depends_on = [] # Declare KB dependencies if any (e.g. ['server'])

    def detect(self, target, kb):
        # Access cached headers from KB instead of making redundant requests!
        headers = kb.get("response_headers", {})
        
        if "My-Header" not in headers:
            return PluginResult(
                found=True,
                title="Missing My-Header",
                severity="medium",
                confidence="high",
                evidence="My-Header not present in response"
            )
        return PluginResult(found=False)
```

The scan engine will automatically register, resolve dependencies for, and execute your new check on the next scan!

---

## ⚖️ Legal Disclaimer

> **⚠️ This scanner is intended for authorized security testing and educational purposes only.**
>
> Unauthorized access or scanning of computer networks is illegal. Always obtain written authorization before scanning target endpoints. The authors are not responsible for any misuse of this tool suite.
