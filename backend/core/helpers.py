from __future__ import annotations

from email.utils import parseaddr
from functools import lru_cache

_PUBLIC_SUFFIX_3 = {
    'ac.uk',
    'co.uk',
    'gov.uk',
    'gov.au',
    'com.au',
    'co.jp',
    'com.br',
    'com.mx',
}


def _strip_port(domain: str) -> str:
    candidate = domain.strip().lower()
    if not candidate:
        return ''
    if candidate.startswith('[') and candidate.endswith(']'):
        return candidate[1:-1]
    if ':' in candidate:
        candidate = candidate.split(':', 1)[0]
    return candidate.strip('.')


@lru_cache(maxsize=None)
def registrable_domain(domain: str | None) -> str | None:
    """Return the registrable portion of a domain (effective second level)."""
    if not domain:
        return None
    host = _strip_port(domain)
    if not host or host.replace('.', '').isdigit():
        return host or None
    labels = host.split('.')
    if len(labels) <= 2:
        return host
    suffix_two = '.'.join(labels[-2:])
    if suffix_two in _PUBLIC_SUFFIX_3 and len(labels) >= 3:
        return '.'.join(labels[-3:])
    return suffix_two


def norm_domain(domain: str | None, *, keep_subdomains: bool = False) -> str | None:
    """Normalize a domain string (case-fold, trim ports)."""
    if not domain:
        return None
    cleaned = _strip_port(domain)
    if not cleaned:
        return None
    return cleaned if keep_subdomains else registrable_domain(cleaned)


def parse_core_addresses(headers) -> tuple[str | None, str | None, str | None]:
    """Parse From, Reply-To, and Return-Path from mapping-like ``headers``."""
    from_addr = parseaddr(headers.get('from', ''))[1]
    reply_to = parseaddr(headers.get('reply-to', ''))[1]
    return_path = parseaddr(headers.get('return-path', ''))[1]
    return from_addr or None, reply_to or None, return_path or None
