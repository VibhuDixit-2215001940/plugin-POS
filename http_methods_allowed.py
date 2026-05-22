import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("HTTP Methods Allowed (OPTIONS)")
print("=" * 60)

domain = input("Enter domain or URL: ").strip()

if not domain.startswith("http://") and not domain.startswith("https://"):
    target = "https://" + domain
else:
    target = domain

try:

    response = requests.options(
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

    if "Allow" in response.headers or "Access-Control-Allow-Methods" in response.headers:
        allowed_methods = response.headers.get("Allow", "")
        cors_methods = response.headers.get("Access-Control-Allow-Methods", "")
        
        methods = allowed_methods if allowed_methods else cors_methods
        
        print("\n[+] HTTP METHODS EXPOSED")
        print(f"Allowed Methods: {methods}")
        
        # Check for dangerous methods
        dangerous = ["PUT", "DELETE", "TRACE", "TRACK", "CONNECT"]
        found_dangerous = [m for m in dangerous if m in methods]
        
        if found_dangerous:
            print(f"\n[!] WARNING: Potentially dangerous methods found: {', '.join(found_dangerous)}")
            print("\nRisk Factor : MEDIUM")
        else:
            print("\nRisk Factor : INFO / LOW")
    else:
        print("\n[-] NO EXPLICIT ALLOWED METHODS FOUND (No 'Allow' header)")
        print("\nRisk Factor : INFO")

except requests.exceptions.RequestException as e:
    print(f"\nConnection Error : {e}")
