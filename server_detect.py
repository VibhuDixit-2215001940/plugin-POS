#!/usr/bin/env python3

import socket
import ssl
import sys
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[-] requests module not found")
    print("[*] Install using: pip install requests")
    sys.exit(1)


BANNER = """
HTTP Server Type and Version Detector
=====================================
"""


def normalize_target(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target


def get_server_header(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        final_url = response.url
        server = response.headers.get("Server", "Not Disclosed")
        powered_by = response.headers.get("X-Powered-By", "Not Found")

        print(f"\n[+] Final URL      : {final_url}")
        print(f"[+] HTTP Status    : {response.status_code}")
        print(f"[+] Server Header  : {server}")
        print(f"[+] X-Powered-By   : {powered_by}")

        return final_url

    except requests.exceptions.SSLError:
        print("[-] SSL Error")
    except requests.exceptions.ConnectionError:
        print("[-] Connection Failed")
    except requests.exceptions.Timeout:
        print("[-] Request Timed Out")
    except Exception as e:
        print(f"[-] Error: {e}")

    return None


def raw_banner_grab(host, port=80, use_ssl=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        if use_ssl:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        sock.send(request.encode())

        response = sock.recv(4096).decode(errors="ignore")

        print("\n[+] Raw HTTP Response:")
        print("-" * 60)

        lines = response.splitlines()

        for line in lines:
            if (
                "Server:" in line
                or "X-Powered-By:" in line
                or "Via:" in line
            ):
                print(line)

        print("-" * 60)

        sock.close()

    except Exception as e:
        print(f"[-] Raw Banner Grab Failed: {e}")


def main():
    print(BANNER)

    target = input("Enter Domain or URL: ").strip()

    url = normalize_target(target)

    parsed = urlparse(url)

    host = parsed.hostname
    scheme = parsed.scheme

    print(f"\n[+] Target Host : {host}")
    print(f"[+] Scheme      : {scheme}")

    final_url = get_server_header(url)

    if final_url:
        parsed_final = urlparse(final_url)

        use_ssl = parsed_final.scheme == "https"
        port = 443 if use_ssl else 80

        raw_banner_grab(parsed_final.hostname, port, use_ssl)


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()