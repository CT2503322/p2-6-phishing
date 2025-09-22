import re
from urllib.parse import urlparse


WHITELIST_DOMAINS = ['enron.com', 'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']

def extract_urls(body):
    """Extract URLs from body.
    """
    url_pattern = r'http[s]?://[^\s]+|www\.[^\s]+'
    urls = re.findall(url_pattern, body)
    return [urlparse(url) for url in urls]

def anchor_text_domain_mismatch(url):
    """Assume text domain mismatch if url domain is unknown good. 
    """
    KNOWN_DOMAINS = ['paypal.com', 'ebay.com', 'amazon.com', 'apple.com', 'microsoft.com', 'en.wikipedia.org']
    TRUSTED_DOMAINS = WHITELIST_DOMAINS + KNOWN_DOMAINS
    return url.hostname not in TRUSTED_DOMAINS if url.hostname else False

def is_high_risk_tld(host):
    """High risk TLDs.
    """
    high_risk = ['.tk', '.ml', '.ga']
    return any(host.endswith(tld) for tld in high_risk) if host else False

def is_shortener(host):
    """URL shorteners.
    """
    shorteners = ['bit.ly', 'tinyurl.com', 't.co']
    return host in shorteners if host else False

def looks_credential_harvest(path, query):
    """Check for credential harvest.
    """
    combined = (path + '?' + query).lower()
    return 'login' in combined or 'password' in combined

def check_urls(urls):
    """Check URLs and return suspicious ones with reasons.
    Returns list of (url, reasons) for suspicious URLs.
    """
    suspicious = []
    for u in urls:
        reasons = []
        if anchor_text_domain_mismatch(u):
            reasons.append("Domain not in trusted list")
        if is_high_risk_tld(u.hostname):
            reasons.append("High-risk TLD")
        if is_shortener(u.hostname):
            reasons.append("URL shortener")
        if looks_credential_harvest(u.path, u.query):
            reasons.append("Suggests credential harvesting")
        if reasons:
            suspicious.append((u, reasons))
    return suspicious
