#!/usr/bin/env python3
"""
cors.py — CORS Misconfiguration Checker
WebSec Headers Toolkit | Plugin #1

Checks for:
  - Wildcard Access-Control-Allow-Origin: *
  - Reflected Origin without validation
  - Credentials allowed with wildcard or reflected origin
  - Dangerous HTTP methods exposed via CORS
  - Missing Vary: Origin header
"""

import requests
import sys
import json
from urllib.parse import urlparse

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
RED    = "\033[91m"
ORANGE = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════╗
║         🌐  CORS Misconfiguration Checker        ║
║              WebSec Headers Toolkit              ║
╚══════════════════════════════════════════════════╝{RESET}
"""

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_origin_from_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def make_request(url: str, headers: dict, timeout: int = 10):
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return response
    except requests.exceptions.SSLError:
        # Retry with HTTP
        url = url.replace("https://", "http://")
        try:
            return requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(f"{RED}[ERROR] Request failed: {e}{RESET}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"{RED}[ERROR] Could not connect to target. Check if the domain is correct.{RESET}")
        return None
    except requests.exceptions.Timeout:
        print(f"{RED}[ERROR] Request timed out.{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[ERROR] Unexpected error: {e}{RESET}")
        return None


# ─────────────────────────────────────────────
# CORS Test Cases
# ─────────────────────────────────────────────

def test_wildcard_origin(url: str) -> dict:
    """Test 1: Check if ACAO header is set to wildcard *"""
    result = {
        "test": "Wildcard Origin (Access-Control-Allow-Origin: *)",
        "risk": "MEDIUM",
        "status": "PASS",
        "detail": ""
    }
    headers = {"Origin": "https://evil-attacker.com"}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        if acac.lower() == "true":
            result["risk"] = "HIGH"
            result["status"] = "FAIL"
            result["detail"] = (
                f"ACAO: * AND Access-Control-Allow-Credentials: true — "
                f"Browsers block this combo but misconfigurations here signal poor CORS policy."
            )
        else:
            result["status"] = "WARN"
            result["detail"] = (
                f"ACAO is wildcard (*). Any origin can read responses. "
                f"Acceptable for public APIs, risky for authenticated endpoints."
            )
    else:
        result["detail"] = f"ACAO is not wildcard. Value: '{acao if acao else 'Not Present'}'"
    return result


def test_reflected_origin(url: str) -> dict:
    """Test 2: Check if the server blindly reflects the Origin header"""
    result = {
        "test": "Reflected Origin (Origin header echoed back without validation)",
        "risk": "HIGH",
        "status": "PASS",
        "detail": ""
    }
    evil_origin = "https://evil-attacker.com"
    headers = {"Origin": evil_origin}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == evil_origin:
        if acac.lower() == "true":
            result["status"] = "FAIL"
            result["detail"] = (
                f"Server reflects arbitrary origin AND allows credentials. "
                f"CRITICAL: Attacker can make authenticated cross-origin requests. "
                f"ACAO: {acao} | Credentials: {acac}"
            )
            result["risk"] = "CRITICAL"
        else:
            result["status"] = "FAIL"
            result["detail"] = (
                f"Server reflects arbitrary origin back. "
                f"Any site can read responses from this endpoint. "
                f"ACAO: {acao}"
            )
    else:
        result["detail"] = f"Origin not reflected. ACAO: '{acao if acao else 'Not Present'}'"
    return result


def test_null_origin(url: str) -> dict:
    """Test 3: Check if null origin is trusted"""
    result = {
        "test": "Null Origin Trust (Origin: null accepted)",
        "risk": "HIGH",
        "status": "PASS",
        "detail": ""
    }
    headers = {"Origin": "null"}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "null":
        result["status"] = "FAIL"
        result["detail"] = (
            f"Server trusts 'null' origin. Sandboxed iframes and local file:// "
            f"pages send null origin — attacker can exploit this. "
            f"Credentials: {acac if acac else 'Not set'}"
        )
    else:
        result["detail"] = f"Null origin not trusted. ACAO: '{acao if acao else 'Not Present'}'"
    return result


def test_subdomain_origin(url: str) -> dict:
    """Test 4: Check if a crafted subdomain of the target is trusted"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")
    # Strip port if present
    domain = domain.split(":")[0]
    crafted_origin = f"https://evil.{domain}"

    result = {
        "test": f"Subdomain Trust Check (crafted: {crafted_origin})",
        "risk": "MEDIUM",
        "status": "PASS",
        "detail": ""
    }
    headers = {"Origin": crafted_origin}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    if acao == crafted_origin:
        result["status"] = "FAIL"
        result["detail"] = (
            f"Server trusts crafted subdomain '{crafted_origin}'. "
            f"If an attacker can control a subdomain (via takeover), they can read responses. "
            f"Credentials: {acac if acac else 'Not set'}"
        )
    else:
        result["detail"] = f"Crafted subdomain not trusted. ACAO: '{acao if acao else 'Not Present'}'"
    return result


def test_http_origin_on_https(url: str) -> dict:
    """Test 5: Check if HTTP origin is trusted by HTTPS endpoint"""
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").split(":")[0]
    http_origin = f"http://{domain}"

    result = {
        "test": f"HTTP Origin on HTTPS Endpoint ({http_origin})",
        "risk": "MEDIUM",
        "status": "PASS",
        "detail": ""
    }
    headers = {"Origin": http_origin}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")

    if acao == http_origin:
        result["status"] = "FAIL"
        result["detail"] = (
            f"HTTPS endpoint trusts HTTP origin '{http_origin}'. "
            f"Downgrade attacks possible — MitM attacker on HTTP can read HTTPS responses."
        )
    else:
        result["detail"] = f"HTTP origin not trusted. ACAO: '{acao if acao else 'Not Present'}'"
    return result


def test_vary_header(url: str) -> dict:
    """Test 6: Check if Vary: Origin is present (required for correct caching)"""
    result = {
        "test": "Vary: Origin Header (Cache Poisoning Prevention)",
        "risk": "LOW",
        "status": "PASS",
        "detail": ""
    }
    headers = {"Origin": get_origin_from_url(url)}
    resp = make_request(url, headers)
    if resp is None:
        result["status"] = "ERROR"
        result["detail"] = "Request failed"
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    vary = resp.headers.get("Vary", "")

    # Only relevant if CORS is active
    if acao and acao != "*":
        if "origin" not in vary.lower():
            result["status"] = "WARN"
            result["detail"] = (
                f"CORS is active (ACAO: {acao}) but Vary: Origin is missing. "
                f"Caches may serve wrong CORS responses to different origins."
            )
        else:
            result["detail"] = f"Vary header includes Origin. Value: '{vary}'"
    else:
        result["detail"] = "Not applicable — CORS not active or wildcard used."
    return result


def test_preflight_methods(url: str) -> dict:
    """Test 7: Check what methods are exposed via CORS preflight (OPTIONS)"""
    result = {
        "test": "Preflight Allowed Methods (OPTIONS request)",
        "risk": "INFO",
        "status": "INFO",
        "detail": ""
    }
    headers = {
        "Origin": "https://evil-attacker.com",
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "Authorization"
    }
    try:
        resp = requests.options(url, headers=headers, timeout=10, allow_redirects=True)
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        acao = resp.headers.get("Access-Control-Allow-Origin", "")

        dangerous = [m for m in ["DELETE", "PUT", "PATCH"] if m in acam.upper()]

        if dangerous and acao:
            result["risk"] = "MEDIUM"
            result["status"] = "WARN"
            result["detail"] = (
                f"Preflight exposes dangerous methods: {', '.join(dangerous)}. "
                f"ACAO: {acao} | Allowed Methods: {acam} | Allowed Headers: {acah if acah else 'Not set'}"
            )
        elif acam:
            result["detail"] = f"Allowed Methods: {acam} | Allowed Headers: {acah if acah else 'Not set'}"
        else:
            result["detail"] = "No CORS preflight response or no Access-Control-Allow-Methods header."
    except Exception as e:
        result["status"] = "ERROR"
        result["detail"] = f"Preflight request failed: {e}"
    return result


# ─────────────────────────────────────────────
# Risk color mapper
# ─────────────────────────────────────────────

def risk_color(risk: str) -> str:
    return {
        "CRITICAL": f"{RED}{BOLD}",
        "HIGH":     RED,
        "MEDIUM":   ORANGE,
        "LOW":      CYAN,
        "INFO":     BLUE,
    }.get(risk.upper(), RESET)


def status_icon(status: str) -> str:
    return {
        "PASS":  f"{GREEN}✔ PASS{RESET}",
        "FAIL":  f"{RED}✘ FAIL{RESET}",
        "WARN":  f"{ORANGE}⚠ WARN{RESET}",
        "INFO":  f"{BLUE}ℹ INFO{RESET}",
        "ERROR": f"{RED}⚡ ERROR{RESET}",
    }.get(status.upper(), status)


# ─────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────

def run_all_tests(url: str):
    print(BANNER)
    print(f"{BOLD}[*] Target  : {CYAN}{url}{RESET}")
    print(f"{BOLD}[*] Running : 7 CORS misconfiguration checks...{RESET}")
    print("─" * 60)

    tests = [
        test_wildcard_origin,
        test_reflected_origin,
        test_null_origin,
        test_subdomain_origin,
        test_http_origin_on_https,
        test_vary_header,
        test_preflight_methods,
    ]

    results = []
    fail_count = 0
    warn_count = 0

    for i, test_fn in enumerate(tests, 1):
        print(f"\n{BOLD}[TEST {i}/7] {test_fn.__doc__.strip().splitlines()[0]}{RESET}")
        result = test_fn(url)
        results.append(result)

        rc = risk_color(result["risk"])
        print(f"  Status : {status_icon(result['status'])}")
        print(f"  Risk   : {rc}{result['risk']}{RESET}")
        print(f"  Detail : {result['detail']}")

        if result["status"] == "FAIL":
            fail_count += 1
        elif result["status"] == "WARN":
            warn_count += 1

    # ── Summary ──
    print("\n" + "═" * 60)
    print(f"{BOLD}📊 CORS SCAN SUMMARY{RESET}")
    print("═" * 60)
    print(f"  Target       : {url}")
    print(f"  Tests Run    : {len(tests)}")
    print(f"  {RED}Failures  : {fail_count}{RESET}")
    print(f"  {ORANGE}Warnings  : {warn_count}{RESET}")
    print(f"  {GREEN}Passed    : {len(tests) - fail_count - warn_count}{RESET}")

    if fail_count == 0 and warn_count == 0:
        print(f"\n  {GREEN}{BOLD}✔ No critical CORS misconfigurations detected.{RESET}")
    elif fail_count > 0:
        print(f"\n  {RED}{BOLD}✘ CORS misconfigurations found! Review FAIL items above.{RESET}")
    else:
        print(f"\n  {ORANGE}{BOLD}⚠ Minor CORS issues found. Review WARN items above.{RESET}")

    print("═" * 60)

    # ── JSON export option ──
    export = input(f"\n{CYAN}[?] Export results to JSON? (y/n): {RESET}").strip().lower()
    if export == "y":
        filename = f"cors_results_{urlparse(url).netloc.replace(':', '_')}.json"
        with open(filename, "w") as f:
            json.dump({"target": url, "results": results}, f, indent=2)
        print(f"{GREEN}[+] Results saved to: {filename}{RESET}")


def main():
    print(BANNER)
    if len(sys.argv) > 1:
        raw_url = sys.argv[1]
    else:
        raw_url = input(f"{CYAN}Enter target domain or URL: {RESET}").strip()

    if not raw_url:
        print(f"{RED}[ERROR] No target provided.{RESET}")
        sys.exit(1)

    url = normalize_url(raw_url)
    run_all_tests(url)


if __name__ == "__main__":
    main()