from backend.core.edit_distance import fuzzy_brand_mentions, fuzzy_domain_matches


KNOWN_BRANDS = [
    'paypal',
    'ebay',
    'amazon',
    'apple',
    'microsoft',
    'bank of america',
    'chase bank',
]

KNOWN_BRAND_DOMAINS = [
    'paypal.com',
    'apple.com',
    'amazon.com',
    'microsoft.com',
    'ebay.com',
    'bankofamerica.com',
    'chase.com',
]


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
    matches = fuzzy_brand_mentions(text, KNOWN_BRANDS, max_distance=max_distance)
    return matches if matches else None


def domain_similar_to_brand(domain, max_distance=1):
    """Return brand domains that are within a small edit distance of ``domain``."""
    matches = fuzzy_domain_matches(domain, KNOWN_BRAND_DOMAINS, max_distance=max_distance)
    return matches if matches else None
