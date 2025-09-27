from __future__ import annotations

import re
from urllib.parse import ParseResult, urlparse

from backend.core.helpers import registrable_domain

# Domains considered safe/trusted for senders
WHITELIST_DOMAINS = {
    'enron.com',
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'microsoft.com',
    'apple.com',
    'google.com',
}

# Domains typically used to serve benign content (less risky)
TRUSTED_CONTENT_DOMAINS = {
    'linkedin.com',
    'facebook.com',
    'instagram.com',
    'twitter.com',
    'pinterest.com',
    'github.com',
    'gitlab.com',
    'figma.com',
    'dropbox.com',
    'box.com',
    'salesforce.com',
    'zendesk.com',
    'notion.so',
    'medium.com',
    'slack.com',
}

# Combined set of all trusted base domains
_TRUSTED_BASES = WHITELIST_DOMAINS | TRUSTED_CONTENT_DOMAINS

# TLDs commonly abused in phishing and scam campaigns
_HIGH_RISK_TLDS = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.country')

# Known URL shortener hosts (used to obscure malicious destinations)
_SHORTENER_HOSTS = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'ow.ly',
    'buff.ly',
    'rebrand.ly',
    'goo.gl',
    'rb.gy',
}

# High-value phishing terms, often present in credential theft links
_PRIMARY_CRED_KEYWORDS = ('login', 'signin', 'password', 'credential')

# Supporting terms that signal possible credential harvest attempts
_SECONDARY_CRED_KEYWORDS = ('verify', 'secure', 'update', 'auth', 'token', 'reset', 'confirm')


def extract_urls(body: str) -> list[ParseResult]:
    """Extracts URLs from the email body using regex and parses them.

    Args:
        body: The raw email body text.

    Returns:
        A list of parsed URLs as ParseResult objects.
    """
    if not body:
        return []
    # Regex matches http(s) and www-prefixed links
    url_pattern = r"https?://[^\s]+|www\.[^\s]+"
    urls = re.findall(url_pattern, body)
    return [urlparse(url) for url in urls]


def is_high_risk_tld(host: str | None) -> bool:
    """Checks if the domain ends in a high-risk TLD."""
    if not host:
        return False
    return any(host.endswith(tld) for tld in _HIGH_RISK_TLDS)


def is_shortener(host: str | None) -> bool:
    """Checks if the host is a known URL shortener."""
    if not host:
        return False
    host_lower = host.lower()
    return host_lower in _SHORTENER_HOSTS


def _credential_harvest_score(path: str | None, query: str | None) -> int:
    """Scores how likely the URL is attempting to harvest credentials.

    Based on the presence of primary and secondary phishing-related terms.

    Returns:
        Integer score between 0 (no risk) and 3 (high risk).
    """
    combined = ' '.join(filter(None, (path, query))).lower()
    if not combined:
        return 0

    # Count number of keyword hits
    primary_hits = sum(1 for kw in _PRIMARY_CRED_KEYWORDS if kw in combined)
    secondary_hits = sum(1 for kw in _SECONDARY_CRED_KEYWORDS if kw in combined)

    if primary_hits == 0:
        return 0

    # Weighted score: base 1, +1 for extra primary, +1 for any secondary
    score = 1 + min(primary_hits - 1, 1) + min(secondary_hits, 1)
    return min(score, 3)


def _domain_risk(host: str | None, sender_domain: str | None) -> tuple[int, str | None]:
    """Evaluates domain similarity to sender and general risk indicators.

    Args:
        host: The hostname from the URL.
        sender_domain: The domain of the sender (From address).

    Returns:
        A tuple of (risk score, reason string if any).
    """
    if not host:
        return 0, None

    host_lower = host.lower()
    base = registrable_domain(host_lower) or host_lower

    # If the base domain is in our known-trusted list, no risk
    if base in _TRUSTED_BASES:
        return 0, None

    sender_base = registrable_domain(sender_domain) if sender_domain else None

    # If it's the sender's domain or a subdomain, assume safe
    if sender_base and (base == sender_base or host_lower.endswith(sender_base)):
        return 0, None

    # Otherwise, check for signs of domain spoofing or obscurity
    suspicious_structure = (
        re.search(r'\d{3,}', host_lower)  # long digit strings
        or host_lower.count('-') >= 2     # multiple hyphens
        or host_lower.startswith('xn--')  # punycode/IDN
        or host_lower.count('.') >= 3     # deeply nested subdomains
    )
    if suspicious_structure:
        return 2, 'Unfamiliar domain structure'

    # If domain differs from sender, mild risk
    if sender_base:
        return 1, 'Domain differs from sender'

    return 0, None


def looks_credential_harvest(path: str | None, query: str | None) -> bool:
    """Convenience wrapper to check if URL components look credential-harvesty."""
    return _credential_harvest_score(path, query) > 0


def check_urls(urls: list[ParseResult], sender_domain: str | None = None) -> list[dict[str, object]]:
    """Checks a list of parsed URLs for suspicious traits.

    Applies several heuristic checks (TLD, shorteners, keywords, etc.)

    Args:
        urls: List of parsed URLs from `extract_urls()`.
        sender_domain: Sender's domain for contextual matching.

    Returns:
        A list of dictionaries per suspicious URL with:
            - url: The ParseResult object
            - reasons: List of human-readable risk reasons
            - score: Integer (1–6), higher = riskier
    """
    findings: list[dict[str, object]] = []
    seen: set[tuple[str | None, str | None, str | None, str | None]] = set()

    for url in urls:
        fingerprint = (url.scheme, url.hostname, url.path, url.query)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        host = url.hostname
        reasons: list[str] = []
        risk = 0

        # Check if domain structure is risky or mismatched
        domain_risk, domain_reason = _domain_risk(host, sender_domain)
        if domain_reason:
            reasons.append(domain_reason)
        risk += domain_risk

        # Add 2 points if domain ends with sketchy TLD
        if is_high_risk_tld(host):
            reasons.append('High-risk TLD')
            risk += 2

        # Add 2 points if the domain is a known shortener
        if is_shortener(host):
            reasons.append('URL shortener')
            risk += 2

        # Add 1–3 points if URL path or query looks like credential harvesting
        cred_score = _credential_harvest_score(url.path, url.query)
        if cred_score:
            reasons.append('Credential-related terms in URL')
            risk += cred_score

        if risk:
            findings.append({
                'url': url,
                'reasons': reasons,
                'score': min(risk, 6),  # Clamp score to a max of 6
            })

    return findings
