# pip install tldextract 
import tldextract
from urllib.parse import urlparse

def check_domain_type(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return "Invalid URL"

    extracted = tldextract.extract(host)

    full_domain = f"{extracted.domain}.{extracted.suffix}"

    if extracted.subdomain:
        return f"{host} -> Subdomain"
    else:
        return f"{host} -> Main Domain"

url = input("Enter URL: ").strip() #Input laadle
print(check_domain_type(url)) #Output laadle