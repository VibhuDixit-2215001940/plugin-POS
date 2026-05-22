import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("Content-Security-Policy Header Check")
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

    print("\n--- ANALYSIS ---")

    if "Content-Security-Policy" in response.headers:

        print("\n[+] CSP HEADER FOUND")
        print(
            f'Content-Security-Policy: '
            f'{response.headers["Content-Security-Policy"]}'
        )

        print("\nRisk Factor : INFO / LOW")

    else:

        print("\n[-] CSP HEADER MISSING")
        print(
            'The remote server does not send the '
            '"Content-Security-Policy" header.'
        )

        print("\nRisk Factor : HIGH")

except requests.exceptions.RequestException as e:
    print(f"\nConnection Error : {e}")