#!/usr/bin/env python3
"""
ssl_tls.py — SSL/TLS Security Analyzer
WebSec Headers Toolkit | Plugin #3

Checks:
  - Supported TLS versions (TLS 1.0 / 1.1 deprecated, 1.2 / 1.3 preferred)
  - Certificate validity & expiry (days remaining)
  - Self-signed certificate detection
  - Certificate CN / SAN hostname match
  - Weak cipher suite detection
  - HSTS presence (bonus check)
  - Certificate chain (issuer info)
"""

import ssl
import socket
import sys
import json
import datetime
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
║           🔐  SSL / TLS Security Analyzer        ║
║              WebSec Headers Toolkit              ║
╚══════════════════════════════════════════════════╝{RESET}
"""

# TLS version constants
TLS_VERSIONS = {
    "TLSv1":   (ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None),
    "TLSv1.1": (ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
    "TLSv1.2": (ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_2),
    "TLSv1.3": (ssl.PROTOCOL_TLS_CLIENT, ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
}

WEAK_CIPHERS_KEYWORDS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL",
    "ANON", "aNULL", "eNULL", "ADH", "AECDH", "PSK",
    "SRP", "SEED", "IDEA", "CAMELLIA128"
]

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def normalize_host(target: str) -> tuple:
    """Returns (host, port) from a domain or URL."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
    else:
        if ":" in target:
            host, port = target.rsplit(":", 1)
            port = int(port)
        else:
            host = target
            port = 443
    return host, port


def get_cert_info(host: str, port: int = 443) -> dict:
    """Retrieve certificate via ssl.get_server_certificate + SSLSocket."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "tls_version": tls_version,
                    "error": None
                }
    except ssl.SSLCertVerificationError as e:
        # Try again without verification to still get cert data
        ctx_nocheck = ssl.create_default_context()
        ctx_nocheck.check_hostname = False
        ctx_nocheck.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx_nocheck.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "tls_version": tls_version,
                        "error": f"SSL Verification Error: {e}"
                    }
        except Exception as e2:
            return {"cert": None, "cipher": None, "tls_version": None, "error": str(e2)}
    except Exception as e:
        return {"cert": None, "cipher": None, "tls_version": None, "error": str(e)}


def probe_tls_version(host: str, port: int, version_name: str, tls_enum) -> str:
    """
    Try connecting with a specific max/min TLS version.
    Returns 'supported', 'rejected', or 'unknown'.
    """
    if tls_enum is None:
        return "unknown"

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_enum
        ctx.maximum_version = tls_enum

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "supported"
    except ssl.SSLError:
        return "rejected"
    except OSError:
        return "rejected"
    except Exception:
        return "unknown"


def parse_cert_dates(cert: dict):
    """Returns (not_before, not_after) as datetime objects."""
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.datetime.strptime(cert.get("notBefore", ""), fmt).replace(tzinfo=datetime.timezone.utc)
        not_after  = datetime.datetime.strptime(cert.get("notAfter",  ""), fmt).replace(tzinfo=datetime.timezone.utc)
        return not_before, not_after
    except Exception:
        return None, None


def get_san_list(cert: dict) -> list:
    """Extract Subject Alternative Names from cert."""
    san_list = []
    for ext in cert.get("subjectAltName", []):
        if ext[0].lower() == "dns":
            san_list.append(ext[1])
    return san_list


def get_subject_field(cert: dict, field: str) -> str:
    for entry in cert.get("subject", []):
        for k, v in entry:
            if k == field:
                return v
    return ""


def get_issuer_field(cert: dict, field: str) -> str:
    for entry in cert.get("issuer", []):
        for k, v in entry:
            if k == field:
                return v
    return ""


def is_self_signed(cert: dict) -> bool:
    subject_cn = get_subject_field(cert, "commonName")
    issuer_cn  = get_issuer_field(cert, "commonName")
    subject_o  = get_subject_field(cert, "organizationName")
    issuer_o   = get_issuer_field(cert, "organizationName")
    return (subject_cn == issuer_cn) and (subject_o == issuer_o)


def hostname_matches_cert(host: str, cert: dict) -> bool:
    """Check if hostname matches CN or SAN."""
    san_list = get_san_list(cert)
    cn = get_subject_field(cert, "commonName")

    all_names = san_list if san_list else [cn]
    host_lower = host.lower()

    for name in all_names:
        name = name.lower()
        if name == host_lower:
            return True
        if name.startswith("*."):
            # Wildcard: *.example.com matches sub.example.com
            suffix = name[2:]
            if host_lower.endswith(f".{suffix}") and "." not in host_lower[:-len(suffix)-1]:
                return True
    return False


def check_weak_cipher(cipher_name: str) -> bool:
    cipher_upper = cipher_name.upper()
    return any(weak in cipher_upper for weak in WEAK_CIPHERS_KEYWORDS)


# ─────────────────────────────────────────────
# Risk display
# ─────────────────────────────────────────────

def risk_icon(risk: str) -> str:
    return {
        "CRITICAL": f"{RED}{BOLD}🔴 CRITICAL{RESET}",
        "HIGH":     f"{RED}🔴 HIGH{RESET}",
        "MEDIUM":   f"{ORANGE}🟠 MEDIUM{RESET}",
        "LOW":      f"{CYAN}🟡 LOW{RESET}",
        "INFO":     f"{BLUE}🔵 INFO{RESET}",
        "PASS":     f"{GREEN}✔  PASS{RESET}",
    }.get(risk.upper(), risk)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    if len(sys.argv) > 1:
        raw_target = sys.argv[1]
    else:
        raw_target = input(f"{CYAN}Enter target domain or URL (HTTPS): {RESET}").strip()

    if not raw_target:
        print(f"{RED}[ERROR] No target provided.{RESET}")
        sys.exit(1)

    host, port = normalize_host(raw_target)

    print(f"\n{BOLD}[*] Target  : {CYAN}{host}:{port}{RESET}")
    print(f"{BOLD}[*] Running SSL/TLS analysis...{RESET}\n")
    print("─" * 60)

    findings = []
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def record(risk, check, detail, status="ISSUE"):
        findings.append({"risk": risk, "check": check, "detail": detail, "status": status})
        if risk in summary:
            summary[risk] += 1

    # ══════════════════════════════════════════
    # SECTION 1: Certificate Info
    # ══════════════════════════════════════════
    print(f"\n{BOLD}[1/4] 📜 Certificate Information{RESET}")
    print("─" * 60)

    info = get_cert_info(host, port)

    if info["error"] and not info["cert"]:
        print(f"  {RED}[ERROR] Could not retrieve certificate: {info['error']}{RESET}")
        sys.exit(1)

    if info["error"]:
        print(f"  {ORANGE}[!] Warning during cert retrieval: {info['error']}{RESET}")

    cert = info["cert"]
    if cert:
        cn      = get_subject_field(cert, "commonName")
        org     = get_subject_field(cert, "organizationName")
        issuer  = get_issuer_field(cert, "organizationName")
        issuer_cn = get_issuer_field(cert, "commonName")
        san_list = get_san_list(cert)

        print(f"  Subject CN    : {cn}")
        print(f"  Organization  : {org if org else 'Not set'}")
        print(f"  Issuer        : {issuer if issuer else issuer_cn}")
        print(f"  SAN Entries   : {', '.join(san_list) if san_list else 'None (using CN only)'}")

        # ── Expiry ──
        not_before, not_after = parse_cert_dates(cert)
        now = datetime.datetime.now(datetime.timezone.utc)

        if not_before and not_after:
            days_remaining = (not_after - now).days
            print(f"  Valid From    : {not_before.strftime('%Y-%m-%d %H:%M UTC')}")
            print(f"  Valid Until   : {not_after.strftime('%Y-%m-%d %H:%M UTC')}")

            if days_remaining < 0:
                print(f"  {RED}  ✘ Certificate EXPIRED {abs(days_remaining)} days ago!{RESET}")
                record("CRITICAL", "Certificate Expired",
                       f"Certificate expired {abs(days_remaining)} days ago on {not_after.strftime('%Y-%m-%d')}.")
            elif days_remaining <= 14:
                print(f"  {RED}  ⚠ Expires in {days_remaining} days (CRITICAL){RESET}")
                record("HIGH", "Certificate Expiring Soon",
                       f"Certificate expires in {days_remaining} days. Renew immediately.")
            elif days_remaining <= 30:
                print(f"  {ORANGE}  ⚠ Expires in {days_remaining} days{RESET}")
                record("MEDIUM", "Certificate Expiring Soon",
                       f"Certificate expires in {days_remaining} days.")
            else:
                print(f"  {GREEN}  ✔ Valid for {days_remaining} more days{RESET}")

        # ── Self-signed ──
        if is_self_signed(cert):
            print(f"  {RED}  ✘ Self-signed certificate detected!{RESET}")
            record("HIGH", "Self-Signed Certificate",
                   "Certificate is self-signed. Browsers will show untrusted warnings. "
                   "Replace with a CA-signed certificate.")
        else:
            print(f"  {GREEN}  ✔ Certificate is CA-signed{RESET}")

        # ── Hostname match ──
        if not hostname_matches_cert(host, cert):
            print(f"  {RED}  ✘ Hostname mismatch! '{host}' not in cert CN/SAN{RESET}")
            record("HIGH", "Hostname Mismatch",
                   f"Host '{host}' does not match certificate CN '{cn}' or SAN list.")
        else:
            print(f"  {GREEN}  ✔ Hostname matches certificate{RESET}")

    # ══════════════════════════════════════════
    # SECTION 2: TLS Version Support
    # ══════════════════════════════════════════
    print(f"\n{BOLD}[2/4] 🔑 TLS Version Support{RESET}")
    print("─" * 60)

    tls_results = {}
    for vname, (proto, venum) in TLS_VERSIONS.items():
        status = probe_tls_version(host, port, vname, venum)
        tls_results[vname] = status

        if status == "supported":
            if vname in ("TLSv1", "TLSv1.1"):
                print(f"  {RED}  ✘ {vname} : SUPPORTED (Deprecated — should be disabled){RESET}")
                record("HIGH", f"Deprecated TLS Version Supported ({vname})",
                       f"{vname} is deprecated (RFC 8996). Vulnerable to BEAST, POODLE attacks. Disable immediately.")
            elif vname == "TLSv1.2":
                print(f"  {GREEN}  ✔ TLSv1.2 : Supported (Acceptable){RESET}")
            elif vname == "TLSv1.3":
                print(f"  {GREEN}  ✔ TLSv1.3 : Supported (Best){RESET}")
        elif status == "rejected":
            if vname in ("TLSv1", "TLSv1.1"):
                print(f"  {GREEN}  ✔ {vname} : Rejected (Good — disabled){RESET}")
            else:
                print(f"  {ORANGE}  ⚠ {vname} : Not supported{RESET}")
        else:
            print(f"  {BLUE}  ℹ {vname} : Could not determine{RESET}")

    if not tls_results.get("TLSv1.2") == "supported" and not tls_results.get("TLSv1.3") == "supported":
        record("CRITICAL", "No Modern TLS Version Supported",
               "Neither TLSv1.2 nor TLSv1.3 is supported. Connections may fail on modern clients.")

    # ══════════════════════════════════════════
    # SECTION 3: Cipher Suite
    # ══════════════════════════════════════════
    print(f"\n{BOLD}[3/4] 🔒 Active Cipher Suite{RESET}")
    print("─" * 60)

    if info["cipher"]:
        cipher_name, tls_ver, bits = info["cipher"]
        print(f"  Cipher        : {cipher_name}")
        print(f"  TLS Version   : {tls_ver}")
        print(f"  Key Bits      : {bits}")

        if check_weak_cipher(cipher_name):
            print(f"  {RED}  ✘ Weak cipher detected!{RESET}")
            record("HIGH", "Weak Cipher Suite",
                   f"Active cipher '{cipher_name}' is considered weak. "
                   f"Configure server to prefer ECDHE/AES-GCM/ChaCha20 suites.")
        else:
            print(f"  {GREEN}  ✔ Cipher appears strong{RESET}")

        if bits and int(bits) < 128:
            print(f"  {RED}  ✘ Key strength {bits} bits is below minimum (128){RESET}")
            record("HIGH", "Insufficient Key Strength",
                   f"Cipher key size {bits} bits. Minimum recommended is 128 bits (prefer 256).")
    else:
        print(f"  {ORANGE}  Could not determine active cipher suite.{RESET}")

    # ══════════════════════════════════════════
    # SECTION 4: Bonus — HSTS Check
    # ══════════════════════════════════════════
    print(f"\n{BOLD}[4/4] 🛡️  HSTS Header Check (Bonus){RESET}")
    print("─" * 60)

    try:
        import requests as req
        resp = req.get(f"https://{host}:{port}", timeout=10, allow_redirects=True, verify=False)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if hsts:
            print(f"  {GREEN}  ✔ HSTS Present: {hsts}{RESET}")
            if "max-age=0" in hsts:
                record("MEDIUM", "HSTS max-age=0 (Disabled)",
                       "HSTS header is present but max-age=0 effectively disables it.")
        else:
            print(f"  {RED}  ✘ HSTS header missing{RESET}")
            record("MEDIUM", "Missing HSTS Header",
                   "Strict-Transport-Security header not found. Clients may connect over HTTP.")
    except Exception as e:
        print(f"  {ORANGE}  ⚠ Could not check HSTS: {e}{RESET}")

    # ══════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════
    print(f"\n\n{'═'*60}")
    print(f"{BOLD}📊 SSL/TLS SCAN SUMMARY{RESET}")
    print(f"{'═'*60}")
    print(f"  Target         : {host}:{port}")
    print(f"  {RED}Critical      : {summary.get('CRITICAL', 0)}{RESET}")
    print(f"  {RED}High          : {summary.get('HIGH', 0)}{RESET}")
    print(f"  {ORANGE}Medium        : {summary.get('MEDIUM', 0)}{RESET}")
    print(f"  {CYAN}Low           : {summary.get('LOW', 0)}{RESET}")
    print(f"  {BLUE}Info          : {summary.get('INFO', 0)}{RESET}")

    if findings:
        print(f"\n  {BOLD}Issues Detected:{RESET}")
        for f in findings:
            print(f"  ├─ {risk_icon(f['risk'])} {f['check']}")
            print(f"  │   {f['detail']}")
    else:
        print(f"\n  {GREEN}{BOLD}✔ No SSL/TLS issues detected.{RESET}")

    print(f"{'═'*60}")

    export = input(f"\n{CYAN}[?] Export results to JSON? (y/n): {RESET}").strip().lower()
    if export == "y":
        filename = f"ssl_tls_{host.replace('.', '_')}.json"
        with open(filename, "w") as out:
            json.dump({
                "target": f"{host}:{port}",
                "tls_versions": tls_results,
                "cipher": list(info["cipher"]) if info["cipher"] else None,
                "summary": summary,
                "findings": findings
            }, out, indent=2)
        print(f"{GREEN}[+] Results saved to: {filename}{RESET}")


if __name__ == "__main__":
    main()