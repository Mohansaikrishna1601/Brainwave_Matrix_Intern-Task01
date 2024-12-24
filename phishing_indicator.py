import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
from OpenSSL import crypto
from publicsuffix2 import get_sld

# List of common phishing indicators in URLs
phishing_indicators = [
    'login', 'verify', 'update', 'secure', 'account', 'banking',
    'signin', 'reels', 'tinyurl', 'clck', 'cloudflare', 'ngrok'
]

# List of urgency phrases
urgency_phrases = [
    'immediately', 'urgent', 'asap', 'now', 'today', 'act fast',
    'important notice', 'warning'
]

# Phishing phrases in page content
phishing_phrases = [
    'verify your account', 'update your account', 'login to your account',
    'security alert', 'account suspended', 'click here to login'
]

def clean_url(url):
    """ Ensures the URL has a scheme (http/https). """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Default to https
    return url

def extract_root_domain(url):
    """ Extracts the root domain using publicsuffix2. """
    parsed_url = urlparse(url)
    domain = get_sld(parsed_url.netloc)  # Get the registered domain (root domain)
    return domain

def validate_ssl(domain):
    """ Validate the SSL certificate of a domain. """
    try:
        print(f"[SSL] Validating SSL for: {domain}")
        cert = ssl.get_server_certificate((domain, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        if x509.has_expired():
            print(f"[SSL] Certificate for {domain} has expired.")
            return False
        return True
    except Exception as e:
        print(f"[SSL] Could not validate SSL for {domain}: {e}")
        return False

def is_phishing_url(url):
    """ Checks if the given URL is a phishing link. """
    try:
        # Clean and parse the URL
        url = clean_url(url)
        parsed_url = urlparse(url)
        domain = extract_root_domain(url)

        if not domain:
            print("[Error] Could not extract a valid domain.")
            return "Invalid"  # Invalid URL

        print(f"[Domain] Extracted domain: {domain}")

        # 1. Check for phishing indicators in the URL
        if any(indicator in url.lower() for indicator in phishing_indicators):
            print(f"[Phishing Indicator] Suspicious keyword found in URL: {url}")
            return "Phishing"

        # 2. Check for suspicious subdomains
        subdomains = parsed_url.netloc.split('.')
        if any(indicator in subdomains for indicator in phishing_indicators):
            print(f"[Phishing Indicator] Suspicious subdomain found in URL: {url}")
            return "Phishing"

        # 3. Validate SSL Certificate
        if not validate_ssl(domain):
            print(f"[SSL] Invalid or expired SSL certificate for domain: {domain}")
            return "Invalid"

        # 4. Fetch and analyze page content
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                print(f"[HTTP] Failed to fetch content: {response.status_code}")
                return "Invalid"  # Treat inaccessible URLs with caution
            content = response.content
        except requests.RequestException:
            print(f"[HTTP] Unable to fetch content for {url}")
            return "Invalid"

        # Parse page content
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text().lower()

        # Check for phishing phrases
        if any(phrase in text for phrase in phishing_phrases):
            print(f"[Content] Phishing phrases detected in page content.")
            return "Phishing"

        # Check for urgency phrases
        if any(phrase in text for phrase in urgency_phrases):
            print(f"[Content] Urgency phrases detected in page content.")
            return "Phishing"

    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
        return "Invalid"  # Default to invalid if there's an error

    return "Safe"

# Get URLs from user input
urls = input("Enter URLs separated by a comma: ").split(',')

for url in urls:
    url = url.strip()  # Remove any leading/trailing whitespace
    print(f"\nChecking URL: {url}")
    result = is_phishing_url(url)
    if result == "Invalid":
        print(f"❌ The URL {url} is invalid.")
    elif result == "Phishing":
        print(f"⚠️ The URL {url} is likely a phishing link.")
    elif result == "Safe":
        print(f"✅ The URL {url} seems safe.")
    else:
        print(f"❓ The URL {url} could not be validated.")
