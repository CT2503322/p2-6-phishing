
"""Utilities for fuzzy brand/domain comparisons using simple edit distance."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, Sequence


def _normalize_text(value: str) -> str:
    """Lowercase and collapse non-alphanumeric characters to single spaces."""
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


@lru_cache(maxsize=None)
def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two short strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (ca != cb)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _window_tokens(tokens: Sequence[str], window_size: int) -> Iterable[str]:
    for idx in range(len(tokens) - window_size + 1):
        yield " ".join(tokens[idx: idx + window_size])


def fuzzy_brand_mentions(text: str, brands: Sequence[str], *, max_distance: int = 1) -> list[str]:
    """Return brand names that appear within a small edit distance in ``text``.

    The check is intentionally lightweight and operates over word n-grams.
    """
    if not text or not brands:
        return []
    normalized_text = _normalize_text(text)
    tokens = normalized_text.split()
    if not tokens:
        return []

    matches: set[str] = set()
    for brand in brands:
        if not brand:
            continue
        normalized_brand = _normalize_text(brand)
        if not normalized_brand:
            continue
        if normalized_brand in normalized_text:
            matches.add(brand)
            continue
        brand_tokens = normalized_brand.split()
        if not brand_tokens:
            continue
        window_size = len(brand_tokens)
        for candidate in _window_tokens(tokens, window_size):
            if abs(len(candidate) - len(normalized_brand)) > max_distance + 2:
                continue
            if _levenshtein(candidate, normalized_brand) <= max_distance:
                matches.add(brand)
                break
    return sorted(matches)


def _normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.strip('.')
    return value


def fuzzy_domain_matches(domain: str, known_domains: Sequence[str], *, max_distance: int = 1) -> list[str]:
    """Return brand domains that are within a small edit distance of ``domain``."""
    if not domain or not known_domains:
        return []
    subject = _normalize_domain(domain)
    if not subject:
        return []

    matches: set[str] = set()
    for candidate in known_domains:
        if not candidate:
            continue
        normalized_candidate = _normalize_domain(candidate)
        if not normalized_candidate:
            continue
        if subject == normalized_candidate:
            matches.add(candidate)
            continue
        if _levenshtein(subject, normalized_candidate) <= max_distance:
            matches.add(candidate)
            continue
        # Treat direct subdomain matches as potential typo variants (e.g. login-paypal.com)
        if subject.endswith('.' + normalized_candidate):
            matches.add(candidate)
    return sorted(matches)


__all__ = [
    "fuzzy_brand_mentions",
    "fuzzy_domain_matches",
]
