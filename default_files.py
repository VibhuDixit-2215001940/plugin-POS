#!/usr/bin/env python3

"""
ADVANCED DEFAULT FILE / PANEL DISCOVERY
--------------------------------------

Features:
- Large built-in wordlist
- Scoring engine
- Severity detection
- Signature analysis
- Multithreaded scanning
- Smart filtering
- No file saving
- JSON console output only

Requirements:
pip install requests colorama

Usage:
python discovery.py
"""

import requests
import concurrent.futures
import json
import re
import time
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36"
    )
}

# ---------------------------------------------------
# LARGE WORDLIST
# ---------------------------------------------------

WORDLIST = [

    # GIT
    "/.git/",
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",

    # ENV
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.production",
    "/.env.backup",

    # CONFIG
    "/config.php",
    "/config.php.bak",
    "/config.json",
    "/config.yml",
    "/settings.py",
    "/settings.json",

    # BACKUPS
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/site.zip",
    "/www.zip",
    "/admin.zip",
    "/backup/",
    "/old/",
    "/temp/",
    "/tmp/",
    "/dump.sql",

    # APACHE
    "/server-status",
    "/server-info",

    # PHP
    "/phpinfo.php",
    "/info.php",
    "/test.php",

    # ADMIN
    "/admin",
    "/admin/",
    "/administrator",
    "/admin/login",
    "/admin/dashboard",
    "/login",
    "/dashboard",
    "/cpanel",
    "/user/login",

    # SWAGGER
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/openapi.json",

    # SPRING
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/metrics",
    "/actuator/mappings",

    # DEBUG
    "/debug",
    "/debug/default/view",
    "/debug/pprof",
    "/_debugbar",

    # CLOUD
    "/.aws/credentials",
    "/credentials",
    "/aws.yml",

    # K8S
    "/k8s",
    "/kubernetes",
    "/.kube/config",

    # DOCKER
    "/docker-compose.yml",
    "/Dockerfile",

    # CI/CD
    "/jenkins",
    "/gitlab",
    "/.gitlab-ci.yml",
    "/.github/workflows",

    # MONITORING
    "/grafana",
    "/prometheus",
    "/kibana",

    # CMS
    "/wp-admin",
    "/wp-login.php",
    "/wp-config.php",
    "/xmlrpc.php",
    "/administrator/index.php",

    # LOGS
    "/logs",
    "/error.log",
    "/access.log",
    "/debug.log",

    # STORAGE
    "/storage",
    "/uploads",
    "/private",
    "/public",

    # API
    "/api",
    "/api/v1",
    "/graphql",
    "/graphiql",

    # COMMON
    "/robots.txt",
    "/crossdomain.xml",
    "/sitemap.xml",

    # FRAMEWORKS
    "/vendor/",
    "/node_modules/",
    "/package.json",
    "/composer.json",
    "/yarn.lock",

    # TEST
    "/test",
    "/testing",
    "/dev",
    "/staging",
    "/beta",

    # DATABASE
    "/phpmyadmin",
    "/mysql",
    "/mongo-express",
    "/adminer",

    # SECRETS
    "/id_rsa",
    "/.ssh/id_rsa",
    "/secret.txt",
    "/secrets.yml",

    # JAVA
    "/jmx-console",
    "/web-console",
    "/manager/html",

    # ELASTIC
    "/_cat",
    "/_cluster/health",

    # MISC
    "/health",
    "/metrics",
    "/status",
    "/version"
]

# ---------------------------------------------------
# SIGNATURES
# ---------------------------------------------------

SIGNATURES = {
    ".git": [
        r"repositoryformatversion",
        r"refs",
        r"git"
    ],

    ".env": [
        r"app_key",
        r"db_password",
        r"aws_secret",
        r"secret_key",
        r"api_key"
    ],

    "phpinfo": [
        r"php version",
        r"zend",
        r"phpinfo"
    ],

    "server-status": [
        r"apache server status",
        r"cpu usage",
        r"server uptime"
    ],

    "swagger": [
        r"swagger-ui",
        r"openapi",
        r"swagger"
    ],

    "actuator": [
        r"spring",
        r"health",
        r"diskspace"
    ]
}

# ---------------------------------------------------
# SCORING ENGINE
# ---------------------------------------------------

def calculate_score(path, status, body):

    score = 0
    severity = "info"

    body_lower = body.lower()

    if status == 200:
        score += 40

    elif status in [401, 403]:
        score += 20

    critical_keywords = [
        ".env",
        ".git",
        "backup",
        "phpinfo",
        "server-status",
        "id_rsa",
        "credentials",
        "secret"
    ]

    for keyword in critical_keywords:

        if keyword in path.lower():
            score += 30

    for _, patterns in SIGNATURES.items():

        for pattern in patterns:

            if re.search(pattern, body_lower):
                score += 20

    if len(body) > 100:
        score += 10

    if score >= 90:
        severity = "critical"

    elif score >= 70:
        severity = "high"

    elif score >= 50:
        severity = "medium"

    elif score >= 20:
        severity = "low"

    return score, severity

# ---------------------------------------------------
# DISCOVERY CLASS
# ---------------------------------------------------

class DefaultFileDiscovery:

    def __init__(self, target):

        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        self.target = target.rstrip("/")
        self.results = []

    def scan_path(self, path):

        url = urljoin(self.target, path)

        try:

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=8,
                verify=False,
                allow_redirects=True
            )

            score, severity = calculate_score(
                path,
                response.status_code,
                response.text
            )

            if response.status_code in [200, 401, 403]:

                result = {
                    "path": path,
                    "match_status": response.status_code,
                    "severity": severity,
                    "score": score,
                    "content_length": len(response.text)
                }

                self.results.append(result)

                color = Fore.GREEN

                if severity == "critical":
                    color = Fore.RED

                elif severity == "high":
                    color = Fore.MAGENTA

                elif severity == "medium":
                    color = Fore.YELLOW

                print(
                    color +
                    f"[{response.status_code}] "
                    f"{path:<35} "
                    f"Severity: {severity.upper():<10} "
                    f"Score: {score}"
                )

        except Exception:
            pass

    def run(self):

        print("=" * 75)
        print("ADVANCED DEFAULT FILE / PANEL DISCOVERY")
        print("=" * 75)
        print(f"Target : {self.target}")
        print(f"Paths  : {len(WORDLIST)}")
        print("=" * 75)

        start = time.time()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=40
        ) as executor:

            executor.map(self.scan_path, WORDLIST)

        end = time.time()

        print("\n" + "=" * 75)
        print("SCAN COMPLETE")
        print("=" * 75)

        print(f"Interesting Findings : {len(self.results)}")
        print(f"Scan Time            : {round(end - start, 2)}s")

        print("\nJSON RESULTS:\n")

        print(json.dumps(self.results, indent=4))


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------

def main():

    target = input(
        "Enter domain or URL: "
    ).strip()

    scanner = DefaultFileDiscovery(target)
    scanner.run()


if __name__ == "__main__":
    main()