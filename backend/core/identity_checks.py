from functools import lru_cache
from pathlib import Path

from backend.core.edit_distance import fuzzy_brand_mentions, fuzzy_domain_matches

_DATA_DIR = Path(__file__).resolve().parents[2] / 'data'
KNOWN_BRANDS_PATH = _DATA_DIR / 'known_brands.txt'

_FALLBACK_BRANDS = (
    ('paypal', 'paypal.com'),
    ('ebay', 'ebay.com'),
    ('amazon', 'amazon.com'),
    ('apple', 'apple.com'),
    ('microsoft', 'microsoft.com'),
    ('bank of america', 'bankofamerica.com'),
    ('chase bank', 'chase.com'),
)


@lru_cache(maxsize=1)
def _load_brand_lists():
    names: list[str] = []
    domains: list[str] = []
    seen_names: set[str] = set()
    seen_domains: set[str] = set()

    def add_record(brand: str, domain: str | None):
        brand = (brand or '').strip().lower()
        if brand and brand not in seen_names:
            names.append(brand)
            seen_names.add(brand)
        if domain:
            clean_domain = domain.strip().lower()
            if clean_domain and clean_domain not in seen_domains:
                domains.append(clean_domain)
                seen_domains.add(clean_domain)

    try:
        with KNOWN_BRANDS_PATH.open('r', encoding='utf-8') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = [part.strip() for part in line.split('|', 1)]
                brand = parts[0]
                domain_part = parts[1] if len(parts) > 1 else ''
                if domain_part:
                    for domain in domain_part.split(','):
                        add_record(brand, domain)
                else:
                    add_record(brand, None)
    except OSError:
        pass

    for fallback_brand, fallback_domain in _FALLBACK_BRANDS:
        add_record(fallback_brand, fallback_domain)

    return tuple(names), tuple(domains)


def _known_brand_names() -> list[str]:
    return list(_load_brand_lists()[0])


def _known_brand_domains() -> list[str]:
    return list(_load_brand_lists()[1])


def is_idn_or_confusable(domain):
    """Check for internationalized domain or confusables.
    Returns the specific issue if found, False otherwise.
    """
    if not domain:
        return False
    if 'xn--' in domain:
        return "xn-- prefix"
    if any(ord(c) > 127 for c in domain):
        return "non-ASCII characters"
    return False


def is_freemx(domain):
    """Check if free mail provider.
    """
    return domain in ['gmail.com', 'yahoo.com', 'hotmail.com']


def mentions_brand(subj, body, max_distance=1):
    """Check if common brands mentioned using fuzzy matching."""
    text = f"{subj or ''} {body or ''}"
    matches = fuzzy_brand_mentions(text, _known_brand_names(), max_distance=max_distance)
    return matches if matches else None


def domain_similar_to_brand(domain, max_distance=1):
    """Return brand domains that are within a small edit distance of ``domain``."""
    matches = fuzzy_domain_matches(domain, _known_brand_domains(), max_distance=max_distance)
    return matches if matches else None
