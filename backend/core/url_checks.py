from __future__ import annotations

import re
from urllib.parse import ParseResult, urlparse

from backend.core.helpers import registrable_domain

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

_TRUSTED_BASES = WHITELIST_DOMAINS | TRUSTED_CONTENT_DOMAINS
_HIGH_RISK_TLDS = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.country')
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
_PRIMARY_CRED_KEYWORDS = ('login', 'signin', 'password', 'credential')
_SECONDARY_CRED_KEYWORDS = ('verify', 'secure', 'update', 'auth', 'token', 'reset', 'confirm')


def extract_urls(body: str) -> list[ParseResult]:
    """Extract URLs from the email body."""
    if not body:
        return []
    url_pattern = r"https?://[^\s]+|www\.[^\s]+"
    urls = re.findall(url_pattern, body)
    return [urlparse(url) for url in urls]


def is_high_risk_tld(host: str | None) -> bool:
    if not host:
        return False
    return any(host.endswith(tld) for tld in _HIGH_RISK_TLDS)


def is_shortener(host: str | None) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return host_lower in _SHORTENER_HOSTS


def _credential_harvest_score(path: str | None, query: str | None) -> int:
    combined = ' '.join(filter(None, (path, query))).lower()
    if not combined:
        return 0
    primary_hits = sum(1 for kw in _PRIMARY_CRED_KEYWORDS if kw in combined)
    secondary_hits = sum(1 for kw in _SECONDARY_CRED_KEYWORDS if kw in combined)
    if primary_hits == 0:
        return 0
    score = 1 + min(primary_hits - 1, 1) + min(secondary_hits, 1)
    return min(score, 3)


def _domain_risk(host: str | None, sender_domain: str | None) -> tuple[int, str | None]:
    if not host:
        return 0, None
    host_lower = host.lower()
    base = registrable_domain(host_lower) or host_lower
    if base in _TRUSTED_BASES:
        return 0, None
    sender_base = registrable_domain(sender_domain) if sender_domain else None
    if sender_base and (base == sender_base or host_lower.endswith(sender_base)):
        return 0, None
    suspicious_structure = re.search(r'\d{3,}', host_lower) or host_lower.count('-') >= 2 or host_lower.startswith('xn--') or host_lower.count('.') >= 3
    if suspicious_structure:
        return 2, 'Unfamiliar domain structure'
    if sender_base:
        return 1, 'Domain differs from sender'
    return 0, None


def looks_credential_harvest(path: str | None, query: str | None) -> bool:
    return _credential_harvest_score(path, query) > 0


def check_urls(urls: list[ParseResult], sender_domain: str | None = None) -> list[dict[str, object]]:
    """Check URLs and return per-URL findings."""
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

        domain_risk, domain_reason = _domain_risk(host, sender_domain)
        if domain_reason:
            reasons.append(domain_reason)
        risk += domain_risk

        if is_high_risk_tld(host):
            reasons.append('High-risk TLD')
            risk += 2

        if is_shortener(host):
            reasons.append('URL shortener')
            risk += 2

        cred_score = _credential_harvest_score(url.path, url.query)
        if cred_score:
            reasons.append('Credential-related terms in URL')
            risk += cred_score

        if risk:
            findings.append({'url': url, 'reasons': reasons, 'score': min(risk, 6)})
    return findings

