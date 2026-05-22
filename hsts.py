import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("142960 - HSTS Missing From HTTPS Server (RFC 6797)")
print("=" * 60)

domain = input("Enter domain or URL: ").strip()

if not domain.startswith("http://") and not domain.startswith("https://"):
    target = "https://" + domain
else:
    target = domain

try:

    response = requests.get(
        target,
        verify=False,
        allow_redirects=True,
        timeout=10
    )

    print(f"\nOriginal Target : {target}")
    print(f"Final URL       : {response.url}")
    print(f"Status Code     : {response.status_code}")

    print("\n--- RESPONSE HEADERS ---")

    for header, value in response.headers.items():
        print(f"{header}: {value}")

    print("\n--- ANALYSIS ---")

    # DETECT INTERCEPTION
    if "192.168." in response.url or "block" in response.url.lower():

        print("[!] TRAFFIC INTERCEPTION DETECTED")
        print("Your request is being filtered or redirected")
        print("by a local firewall/proxy/security product.")

    # HSTS CHECK
    if "Strict-Transport-Security" in response.headers:

        print("\n[+] HSTS HEADER FOUND")
        print(
            f'Strict-Transport-Security: '
            f'{response.headers["Strict-Transport-Security"]}'
        )

        print("\nRisk Factor : INFO / LOW")

    else:

        print("\n[-] HSTS HEADER MISSING")
        print(
            'The remote HTTPS server does not send the '
            '"Strict-Transport-Security" header.'
        )

        print("\nRisk Factor : MEDIUM")

except requests.exceptions.RequestException as e:
    print(f"\nConnection Error : {e}")