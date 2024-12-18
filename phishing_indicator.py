import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
from OpenSSL import crypto
from publicsuffix2 import get_sld

# List of known legitimate domains (include base domains only)
legitimate_domains = [
    'instagram.com', 'facebook.com', 'twitter.com', 'paypal.com',
    'microsoft.com', 'google.com', 'youtube.com', 'amazon.com'
]

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
            return True

        print(f"[Domain] Extracted domain: {domain}")

        # 1. Check if the domain is legitimate
        if domain in legitimate_domains:
            return False  # Legitimate domain, not phishing

        # 2. Check for phishing indicators in the URL
        if any(indicator in url.lower() for indicator in phishing_indicators):
            print(f"[Phishing Indicator] Suspicious keyword found in URL: {url}")
            return True

        # 3. Validate SSL Certificate
        if not validate_ssl(domain):
            print(f"[SSL] Invalid or expired SSL certificate for domain: {domain}")
            return True

        # 4. Fetch and analyze page content
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                print(f"[HTTP] Failed to fetch content: {response.status_code}")
                return True  # Treat inaccessible URLs with caution
            content = response.content
        except requests.RequestException:
            print(f"[HTTP] Unable to fetch content for {url}")
            return False  # Skip inaccessible URLs for now

        # Parse page content
        soup = BeautifulSoup(content, 'html.parser')
        text = soup.get_text().lower()

        # Check for phishing phrases
        if any(phrase in text for phrase in phishing_phrases):
            print(f"[Content] Phishing phrases detected in page content.")
            return True

        # Check for urgency phrases
        if any(phrase in text for phrase in urgency_phrases):
            print(f"[Content] Urgency phrases detected in page content.")
            return True

    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")
        return True  # Default to phishing if there's an error

    return False  # If all checks pass, URL is safe

# Get URLs from user input
urls = input("Enter URLs separated by a comma: ").split(',')

for url in urls:
    url = url.strip()  # Remove any leading/trailing whitespace
    print(f"\nChecking URL: {url}")
    if is_phishing_url(url):
        print(f"❌ The URL {url} is likely a phishing link.")
    else:
        print(f"✅ The URL {url} seems safe.")
