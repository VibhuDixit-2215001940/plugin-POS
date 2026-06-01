#!/usr/bin/env python3
"""
cookie.py — Cookie Security Auditor
WebSec Headers Toolkit | Plugin #2

Checks every Set-Cookie header for:
  - Missing HttpOnly flag
  - Missing Secure flag
  - Missing SameSite attribute (None / Lax / Strict)
  - SameSite=None without Secure flag
  - Overly broad Domain scope
  - Missing or overly long Expires/Max-Age
  - Sensitive cookie names transmitted insecurely
  - Cookie Prefixes (__Secure- / __Host-) misuse
"""

import requests
import sys
import json
import re
from urllib.parse import urlparse
from http.cookiejar import CookieJar
from datetime import datetime, timezone

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
║           🍪  Cookie Security Auditor            ║
║              WebSec Headers Toolkit              ║
╚══════════════════════════════════════════════════╝{RESET}
"""

# Sensitive cookie name patterns (session, auth, token cookies)
SENSITIVE_PATTERNS = [
    r"sess(ion)?", r"auth", r"token", r"jwt", r"access",
    r"refresh", r"user", r"uid", r"account", r"login",
    r"csrf", r"xsrf", r"secret", r"key", r"credential",
    r"id", r"remember", r"admin"
]

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_sensitive_cookie(name: str) -> bool:
    name_lower = name.lower()
    return any(re.search(p, name_lower) for p in SENSITIVE_PATTERNS)


def parse_set_cookie_headers(raw_headers) -> list:
    """
    Manually parse all Set-Cookie headers (requests merges duplicates,
    so we use the raw response headers list).
    """
    cookies = []
    # requests stores multiple Set-Cookie in response.headers as comma-joined
    # Use raw header list via response.raw.headers.getlist if available
    raw_cookies = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []

    if not raw_cookies:
        # Fallback: parse from the single merged value (less accurate but usable)
        merged = raw_headers.get("Set-Cookie", "")
        if merged:
            raw_cookies = [merged]

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue

        name_value = parts[0]
        name = name_value.split("=")[0].strip() if "=" in name_value else name_value.strip()
        value = name_value.split("=", 1)[1].strip() if "=" in name_value else ""

        attrs = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.strip().lower()] = True

        cookies.append({
            "name": name,
            "value": value[:20] + "..." if len(value) > 20 else value,
            "raw": raw,
            "attrs": attrs,
            "flags": {
                "httponly": "httponly" in attrs,
                "secure": "secure" in attrs,
                "samesite": attrs.get("samesite", None),
                "domain": attrs.get("domain", None),
                "path": attrs.get("path", "/"),
                "expires": attrs.get("expires", None),
                "max_age": attrs.get("max-age", None),
            }
        })
    return cookies


def make_request(url: str, timeout: int = 10):
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return resp
    except requests.exceptions.SSLError:
        try:
            url = url.replace("https://", "http://")
            return requests.get(url, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(f"{RED}[ERROR] {e}{RESET}")
            return None
    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")
        return None


# ─────────────────────────────────────────────
# Per-cookie checks
# ─────────────────────────────────────────────

def audit_cookie(cookie: dict, is_https: bool) -> list:
    findings = []
    flags = cookie["flags"]
    name = cookie["name"]
    sensitive = is_sensitive_cookie(name)

    # ── 1. HttpOnly ──
    if not flags["httponly"]:
        risk = "HIGH" if sensitive else "MEDIUM"
        findings.append({
            "check": "Missing HttpOnly",
            "risk": risk,
            "detail": (
                f"Cookie '{name}' lacks HttpOnly. "
                f"{'Sensitive cookie — ' if sensitive else ''}"
                f"JavaScript can read this via document.cookie (XSS escalation risk)."
            )
        })

    # ── 2. Secure flag ──
    if not flags["secure"]:
        risk = "HIGH" if (sensitive and is_https) else "MEDIUM"
        findings.append({
            "check": "Missing Secure Flag",
            "risk": risk,
            "detail": (
                f"Cookie '{name}' lacks Secure flag. "
                f"Transmitted over HTTP — vulnerable to network interception (MitM)."
            )
        })

    # ── 3. SameSite ──
    samesite = flags["samesite"]
    if samesite is None:
        findings.append({
            "check": "Missing SameSite Attribute",
            "risk": "MEDIUM",
            "detail": (
                f"Cookie '{name}' has no SameSite attribute. "
                f"Modern browsers default to Lax, but explicit setting is required. "
                f"Missing SameSite can enable CSRF attacks on older browsers."
            )
        })
    elif samesite.lower() == "none":
        if not flags["secure"]:
            findings.append({
                "check": "SameSite=None Without Secure",
                "risk": "HIGH",
                "detail": (
                    f"Cookie '{name}' has SameSite=None but is missing Secure flag. "
                    f"Browsers will reject this cookie entirely (Chrome 80+). "
                    f"Also exposes cookie on HTTP connections."
                )
            })
        else:
            findings.append({
                "check": "SameSite=None (Cross-site cookie)",
                "risk": "LOW",
                "detail": (
                    f"Cookie '{name}' is explicitly cross-site (SameSite=None; Secure). "
                    f"Verify this is intentional — third-party/embed use case only."
                )
            })

    # ── 4. Domain scope ──
    domain = flags["domain"]
    if domain and domain.startswith("."):
        findings.append({
            "check": "Overly Broad Domain Scope",
            "risk": "LOW",
            "detail": (
                f"Cookie '{name}' has Domain='{domain}' (leading dot). "
                f"Cookie is sent to all subdomains. If a subdomain is compromised, "
                f"attacker can read/set this cookie."
            )
        })

    # ── 5. Cookie Prefix misuse ──
    if name.startswith("__Secure-"):
        if not flags["secure"]:
            findings.append({
                "check": "__Secure- Prefix Misuse",
                "risk": "MEDIUM",
                "detail": (
                    f"Cookie '{name}' uses __Secure- prefix but lacks Secure flag. "
                    f"Browser will reject this cookie."
                )
            })
    if name.startswith("__Host-"):
        issues = []
        if not flags["secure"]:
            issues.append("missing Secure flag")
        if domain:
            issues.append(f"has Domain attribute ('{domain}')")
        if flags["path"] != "/":
            issues.append(f"Path is not '/' (got '{flags['path']}')")
        if issues:
            findings.append({
                "check": "__Host- Prefix Misuse",
                "risk": "MEDIUM",
                "detail": (
                    f"Cookie '{name}' uses __Host- prefix but: {', '.join(issues)}. "
                    f"Browser will reject this cookie."
                )
            })

    # ── 6. No expiry (session cookie) — just info ──
    if not flags["expires"] and not flags["max_age"]:
        findings.append({
            "check": "Session Cookie (No Expiry)",
            "risk": "INFO",
            "detail": (
                f"Cookie '{name}' has no Expires/Max-Age — it's a session cookie. "
                f"Deleted when browser closes. Acceptable for auth cookies; "
                f"risky if user keeps browser open indefinitely."
            )
        })

    # ── 7. Very long Max-Age ──
    max_age = flags["max_age"]
    if max_age and str(max_age).lstrip("-").isdigit():
        age_seconds = int(max_age)
        if age_seconds > 86400 * 365:  # > 1 year
            findings.append({
                "check": "Excessive Max-Age (> 1 year)",
                "risk": "LOW",
                "detail": (
                    f"Cookie '{name}' has Max-Age={max_age} seconds "
                    f"({age_seconds // 86400} days). "
                    f"Long-lived cookies increase session hijacking window."
                )
            })

    return findings


# ─────────────────────────────────────────────
# Risk color / status
# ─────────────────────────────────────────────

def risk_color(risk: str) -> str:
    return {
        "CRITICAL": f"{RED}{BOLD}",
        "HIGH":     RED,
        "MEDIUM":   ORANGE,
        "LOW":      CYAN,
        "INFO":     BLUE,
    }.get(risk.upper(), RESET)


def risk_icon(risk: str) -> str:
    return {
        "CRITICAL": f"{RED}{BOLD}🔴 CRITICAL{RESET}",
        "HIGH":     f"{RED}🔴 HIGH{RESET}",
        "MEDIUM":   f"{ORANGE}🟠 MEDIUM{RESET}",
        "LOW":      f"{CYAN}🟡 LOW{RESET}",
        "INFO":     f"{BLUE}🔵 INFO{RESET}",
    }.get(risk.upper(), risk)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

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
    is_https = url.startswith("https://")

    print(f"\n{BOLD}[*] Target  : {CYAN}{url}{RESET}")
    print(f"{BOLD}[*] Fetching cookies...{RESET}\n")

    resp = make_request(url)
    if resp is None:
        print(f"{RED}[ERROR] Could not reach target.{RESET}")
        sys.exit(1)

    print(f"  {GREEN}[+] HTTP Status   : {resp.status_code}{RESET}")
    print(f"  {GREEN}[+] Final URL     : {resp.url}{RESET}")

    # Parse Set-Cookie headers from urllib3 raw response
    try:
        raw_cookies_list = resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookies_list = []

    # Fallback: use requests built-in cookies
    if not raw_cookies_list:
        # Build synthetic raw strings from requests cookie jar
        raw_cookies_list = []
        for c in resp.cookies:
            parts = [f"{c.name}={c.value}"]
            if c.path:     parts.append(f"Path={c.path}")
            if c.domain:   parts.append(f"Domain={c.domain}")
            if c.expires:  parts.append(f"Expires={c.expires}")
            raw_cookies_list.append("; ".join(parts))

    if not raw_cookies_list:
        print(f"\n{ORANGE}[!] No Set-Cookie headers found in the response.{RESET}")
        print(f"  This could mean:")
        print(f"  • The target uses JavaScript-set cookies (not visible in initial response)")
        print(f"  • Authentication is required before cookies are issued")
        print(f"  • No cookies are used by this endpoint")
        sys.exit(0)

    print(f"  {GREEN}[+] Cookies Found : {len(raw_cookies_list)}{RESET}")
    print("─" * 60)

    # Parse and audit each cookie
    all_findings = []
    total_issues = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for i, raw_cookie in enumerate(raw_cookies_list, 1):
        # Parse the raw Set-Cookie string manually
        parts = [p.strip() for p in raw_cookie.split(";")]
        name_val = parts[0]
        name = name_val.split("=")[0].strip() if "=" in name_val else name_val.strip()
        value = name_val.split("=", 1)[1].strip() if "=" in name_val else ""

        attrs = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[part.strip().lower()] = True

        cookie = {
            "name": name,
            "value": value[:20] + "..." if len(value) > 20 else value,
            "raw": raw_cookie,
            "attrs": attrs,
            "flags": {
                "httponly": "httponly" in attrs,
                "secure": "secure" in attrs,
                "samesite": attrs.get("samesite", None),
                "domain": attrs.get("domain", None),
                "path": attrs.get("path", "/"),
                "expires": attrs.get("expires", None),
                "max_age": attrs.get("max-age", None),
            }
        }

        sensitive = is_sensitive_cookie(name)

        print(f"\n{BOLD}{'═'*60}{RESET}")
        print(f"{BOLD}[Cookie {i}] {CYAN}{name}{RESET} {'🔑 (Sensitive)' if sensitive else ''}")
        print(f"{'═'*60}{RESET}")
        print(f"  Value     : {cookie['value']}")
        print(f"  HttpOnly  : {'✔' if cookie['flags']['httponly'] else f'{RED}✘{RESET}'}")
        print(f"  Secure    : {'✔' if cookie['flags']['secure'] else f'{RED}✘{RESET}'}")
        print(f"  SameSite  : {cookie['flags']['samesite'] if cookie['flags']['samesite'] else f'{ORANGE}Not set{RESET}'}")
        print(f"  Domain    : {cookie['flags']['domain'] if cookie['flags']['domain'] else 'Not set (host-only)'}")
        print(f"  Path      : {cookie['flags']['path']}")
        print(f"  Expires   : {cookie['flags']['expires'] if cookie['flags']['expires'] else 'Session cookie'}")

        findings = audit_cookie(cookie, is_https)

        if findings:
            print(f"\n  {BOLD}Findings:{RESET}")
            for f in findings:
                print(f"  ├─ {risk_icon(f['risk'])} — {BOLD}{f['check']}{RESET}")
                print(f"  │   {f['detail']}")
                total_issues[f["risk"]] = total_issues.get(f["risk"], 0) + 1
            all_findings.append({"cookie": name, "findings": findings})
        else:
            print(f"\n  {GREEN}✔ No security issues found for this cookie.{RESET}")

    # ── Summary ──
    print(f"\n\n{'═'*60}")
    print(f"{BOLD}📊 COOKIE AUDIT SUMMARY{RESET}")
    print(f"{'═'*60}")
    print(f"  Target         : {url}")
    print(f"  Cookies Audited: {len(raw_cookies_list)}")
    print(f"  {RED}Critical      : {total_issues.get('CRITICAL', 0)}{RESET}")
    print(f"  {RED}High          : {total_issues.get('HIGH', 0)}{RESET}")
    print(f"  {ORANGE}Medium        : {total_issues.get('MEDIUM', 0)}{RESET}")
    print(f"  {CYAN}Low           : {total_issues.get('LOW', 0)}{RESET}")
    print(f"  {BLUE}Info          : {total_issues.get('INFO', 0)}{RESET}")

    high_total = total_issues.get("CRITICAL", 0) + total_issues.get("HIGH", 0)
    if high_total == 0:
        print(f"\n  {GREEN}{BOLD}✔ No critical/high cookie security issues detected.{RESET}")
    else:
        print(f"\n  {RED}{BOLD}✘ {high_total} critical/high issue(s) found. Review above.{RESET}")
    print(f"{'═'*60}")

    # ── JSON export ──
    export = input(f"\n{CYAN}[?] Export results to JSON? (y/n): {RESET}").strip().lower()
    if export == "y":
        parsed = urlparse(url)
        filename = f"cookie_audit_{parsed.netloc.replace(':', '_')}.json"
        with open(filename, "w") as f:
            json.dump({
                "target": url,
                "cookies_audited": len(raw_cookies_list),
                "summary": total_issues,
                "findings": all_findings
            }, f, indent=2)
        print(f"{GREEN}[+] Results saved to: {filename}{RESET}")


if __name__ == "__main__":
    main()