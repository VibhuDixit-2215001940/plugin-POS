#!/usr/bin/env python3

"""
Advanced Server Fingerprinting Script
------------------------------------

Features:
- HTTP Header Fingerprinting
- TLS Information Extraction
- HTTP Behavior Analysis
- favicon.ico MurmurHash3 Fingerprinting
- HTML Technology Detection
- Error Page Analysis
- JA3-like TLS Data Collection
- JARM Fingerprinting (basic implementation)
- Wappalyzer-style Detection
- Response Timing Analysis
- ETag Analysis

Requirements:
pip install requests beautifulsoup4 mmh3 pyopenssl tldextract

Usage:
python fingerprint.py https://example.com
"""

import requests
import socket
import ssl
import hashlib
import mmh3
import base64
import re
import sys
import time
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from OpenSSL import SSL
import tldextract

requests.packages.urllib3.disable_warnings()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0 Safari/537.36"
    )
}

TECH_PATTERNS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wordpress"
    ],
    "Drupal": [
        r"drupal",
        r"sites/default"
    ],
    "Joomla": [
        r"joomla",
        r"/components/"
    ],
    "Cloudflare": [
        r"cloudflare"
    ],
    "Apache": [
        r"apache"
    ],
    "Nginx": [
        r"nginx"
    ],
    "IIS": [
        r"iis"
    ],
    "PHP": [
        r"php"
    ],
    "ASP.NET": [
        r"asp.net",
        r"__viewstate"
    ],
    "React": [
        r"react",
        r"_next"
    ],
    "Vue": [
        r"vue"
    ],
    "Bootstrap": [
        r"bootstrap"
    ]
}


class ServerFingerprint:

    def __init__(self, target):
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        self.target = target
        self.parsed = urlparse(target)
        self.host = self.parsed.hostname
        self.port = self.parsed.port or (
            443 if self.parsed.scheme == "https" else 80
        )

        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def banner(self):
        print("=" * 70)
        print("ADVANCED SERVER FINGERPRINTING")
        print("=" * 70)
        print(f"Target : {self.target}")
        print(f"Host   : {self.host}")
        print(f"Port   : {self.port}")
        print("=" * 70)

    def get_response(self):
        try:
            start = time.time()

            response = self.session.get(
                self.target,
                verify=False,
                timeout=10,
                allow_redirects=True
            )

            end = time.time()

            response.elapsed_total = round(end - start, 4)

            return response

        except Exception as error:
            print(f"[ERROR] Request failed: {error}")
            return None

    def analyze_headers(self, response):
        print("\n[+] HEADER ANALYSIS")
        print("-" * 50)

        important_headers = [
            "Server",
            "X-Powered-By",
            "Via",
            "X-AspNet-Version",
            "X-Generator",
            "CF-RAY",
            "Set-Cookie",
            "Strict-Transport-Security"
        ]

        for header in important_headers:
            value = response.headers.get(header)
            if value:
                print(f"{header}: {value}")

    def tls_info(self):
        print("\n[+] TLS INFORMATION")
        print("-" * 50)

        try:
            context = ssl.create_default_context()

            with socket.create_connection((self.host, 443), timeout=10) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=self.host
                ) as ssock:

                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    print(f"TLS Version : {version}")
                    print(f"Cipher      : {cipher[0]}")
                    print(f"Issuer      : {cert.get('issuer')}")
                    print(f"Subject     : {cert.get('subject')}")

        except Exception as error:
            print(f"[ERROR] TLS analysis failed: {error}")

    def favicon_hash(self):
        print("\n[+] FAVICON HASH")
        print("-" * 50)

        favicon_url = f"{self.target.rstrip('/')}/favicon.ico"

        try:
            response = self.session.get(
                favicon_url,
                verify=False,
                timeout=10
            )

            if response.status_code == 200:

                favicon_base64 = base64.encodebytes(
                    response.content
                )

                favicon_hash = mmh3.hash(
                    favicon_base64.decode("utf-8")
                )

                md5_hash = hashlib.md5(
                    response.content
                ).hexdigest()

                print(f"Favicon URL     : {favicon_url}")
                print(f"MurmurHash3     : {favicon_hash}")
                print(f"MD5             : {md5_hash}")

            else:
                print("favicon.ico not found")

        except Exception as error:
            print(f"[ERROR] favicon analysis failed: {error}")

    def html_analysis(self, response):
        print("\n[+] HTML PATTERN ANALYSIS")
        print("-" * 50)

        html = response.text.lower()

        detected = set()

        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, html):
                    detected.add(tech)

        if detected:
            for tech in sorted(detected):
                print(f"Detected : {tech}")
        else:
            print("No technologies identified")

    def etag_analysis(self, response):
        print("\n[+] ETAG ANALYSIS")
        print("-" * 50)

        etag = response.headers.get("ETag")

        if etag:
            print(f"ETag : {etag}")

            if "-" in etag:
                print("Possible Apache-style inode/size/time ETag")

            if re.match(r'^"[a-f0-9]+"$', etag):
                print("Likely hash-based ETag")

        else:
            print("ETag header missing")

    def timing_analysis(self):
        print("\n[+] RESPONSE TIMING ANALYSIS")
        print("-" * 50)

        timings = []

        for _ in range(5):

            try:
                start = time.time()

                self.session.get(
                    self.target,
                    verify=False,
                    timeout=10
                )

                end = time.time()

                timings.append(end - start)

            except Exception:
                pass

        if timings:
            avg = sum(timings) / len(timings)

            print(f"Average Response Time : {avg:.4f}s")
            print(f"Min Response Time     : {min(timings):.4f}s")
            print(f"Max Response Time     : {max(timings):.4f}s")

    def http_behavior(self):
        print("\n[+] HTTP BEHAVIOR")
        print("-" * 50)

        methods = ["GET", "POST", "OPTIONS", "TRACE", "PUT"]

        for method in methods:

            try:
                response = self.session.request(
                    method,
                    self.target,
                    verify=False,
                    timeout=10
                )

                print(f"{method:<10} -> {response.status_code}")

            except Exception:
                print(f"{method:<10} -> FAILED")

    def error_page_analysis(self):
        print("\n[+] ERROR PAGE ANALYSIS")
        print("-" * 50)

        random_path = (
            self.target.rstrip("/") +
            "/this_should_not_exist_123456"
        )

        try:
            response = self.session.get(
                random_path,
                verify=False,
                timeout=10
            )

            title = ""

            soup = BeautifulSoup(response.text, "html.parser")

            if soup.title:
                title = soup.title.text.strip()

            print(f"Status Code : {response.status_code}")
            print(f"Page Title  : {title}")

            signatures = [
                "apache",
                "nginx",
                "iis",
                "cloudflare",
                "tomcat"
            ]

            body = response.text.lower()

            for signature in signatures:
                if signature in body:
                    print(f"Error Signature Detected : {signature}")

        except Exception as error:
            print(f"[ERROR] Error page analysis failed: {error}")

    def ja3_like_data(self):
        print("\n[+] JA3-LIKE TLS DATA")
        print("-" * 50)

        try:
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, 443))

            connection = SSL.Connection(context, sock)
            connection.set_tlsext_host_name(
                self.host.encode()
            )

            connection.set_connect_state()
            connection.do_handshake()

            cipher = connection.get_cipher_name()
            version = connection.get_protocol_version_name()

            print(f"TLS Version : {version}")
            print(f"Cipher      : {cipher}")

            connection.close()
            sock.close()

        except Exception as error:
            print(f"[ERROR] JA3 collection failed: {error}")

    def basic_jarm(self):
        """
        Simplified JARM-style fingerprint.
        Real JARM requires crafted TLS probes.
        """

        print("\n[+] BASIC JARM FINGERPRINT")
        print("-" * 50)

        try:
            context = ssl.create_default_context()

            with socket.create_connection((self.host, 443)) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=self.host
                ) as ssock:

                    data = (
                        ssock.version() +
                        ssock.cipher()[0]
                    )

                    jarm_hash = hashlib.sha256(
                        data.encode()
                    ).hexdigest()

                    print(f"JARM-like Hash : {jarm_hash}")

        except Exception as error:
            print(f"[ERROR] JARM failed: {error}")

    def run(self):

        self.banner()

        response = self.get_response()

        if not response:
            return

        print(f"\n[+] FINAL URL : {response.url}")
        print(f"[+] STATUS    : {response.status_code}")
        print(f"[+] TIME      : {response.elapsed_total}s")

        self.analyze_headers(response)
        self.tls_info()
        self.http_behavior()
        self.favicon_hash()
        self.html_analysis(response)
        self.error_page_analysis()
        self.timing_analysis()
        self.etag_analysis(response)
        self.ja3_like_data()
        self.basic_jarm()

        print("\n" + "=" * 70)
        print("FINGERPRINTING COMPLETE")
        print("=" * 70)


def get_target():
    target = input("Enter domain or URL: ").strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return target


def main():

    target = get_target()

    scanner = ServerFingerprint(target)
    scanner.run()


if __name__ == "__main__":
    main()