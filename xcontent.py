import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("X-Content-Type-Options Header Check")
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

    if "X-Content-Type-Options" in response.headers:

        print("\n[+] X-Content-Type-Options HEADER FOUND")
        print(
            f'X-Content-Type-Options: '
            f'{response.headers["X-Content-Type-Options"]}'
        )

        print("\nRisk Factor : INFO / LOW")

    else:

        print("\n[-] X-Content-Type-Options HEADER MISSING")
        print(
            'The remote server does not send the '
            '"X-Content-Type-Options" header.'
        )

        print("\nRisk Factor : LOW")

except requests.exceptions.RequestException as e:
    print(f"\nConnection Error : {e}")