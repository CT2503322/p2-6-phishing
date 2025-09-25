"""Edit distance utilities for phishing detection heuristics."""

from __future__ import annotations

from typing import List, Sequence

from backend.core.text import normalize_text, tokenize_words


def banded_levenshtein(a: str, b: str, max_distance: int | None = None) -> int | None:
    """Compute Levenshtein distance with optional banded cutoff."""

    if a == b:
        return 0

    if not a:
        distance = len(b)
        return distance if max_distance is None or distance <= max_distance else None
    if not b:
        distance = len(a)
        return distance if max_distance is None or distance <= max_distance else None

    if max_distance is not None:
        if max_distance < 0:
            raise ValueError("max_distance must be non-negative")
        if abs(len(a) - len(b)) > max_distance:
            return None
        band = max_distance
    else:
        band = max(len(a), len(b))

    if len(a) > len(b):
        a, b = b, a

    len_a = len(a)
    len_b = len(b)
    inf = (max_distance if max_distance is not None else len_a + len_b) + 1

    previous = [inf] * (len_b + 1)
    previous[0] = 0
    for j in range(1, min(len_b, band) + 1):
        previous[j] = j

    for i in range(1, len_a + 1):
        current = [inf] * (len_b + 1)
        if i <= band:
            current[0] = i

        start = max(1, i - band)
        end = min(len_b, i + band)
        for j in range(start, end + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            deletion = previous[j] + 1
            insertion = current[j - 1] + 1
            substitution = previous[j - 1] + cost
            current[j] = min(deletion, insertion, substitution)

        previous = current

        if max_distance is not None:
            window_start = max(0, start - 1)
            window_end = end + 1
            if min(previous[window_start:window_end]) > max_distance:
                return None

    distance = previous[len_b]
    if max_distance is not None and distance > max_distance:
        return None
    return distance


def fuzzy_domain_matches(
    domain: str | None,
    candidates: Sequence[str],
    max_distance: int = 1,
) -> List[str]:
    """Return known phishing domains that are within edit distance of ``domain``."""

    domain_norm = normalize_text(domain, lowercase=True, strip_accents=True, collapse_whitespace=True)
    domain_norm = domain_norm.replace(" ", "")
    if not domain_norm:
        return []

    matches: List[str] = []
    for candidate in candidates:
        candidate_norm = normalize_text(candidate, lowercase=True, strip_accents=True, collapse_whitespace=True).replace(" ", "")
        if not candidate_norm:
            continue
        if candidate_norm == domain_norm:
            matches.append(candidate)
            continue
        if banded_levenshtein(domain_norm, candidate_norm, max_distance) is not None:
            matches.append(candidate)
    return matches


def fuzzy_brand_mentions(
    text: str | None,
    brands: Sequence[str],
    max_distance: int = 1,
) -> List[str]:
    """Detect near-miss brand mentions within free-form text."""

    tokens = tokenize_words(text, lowercase=True, min_length=1)
    if not tokens:
        return []

    matches: List[str] = []
    seen = set()

    for brand in brands:
        brand_norm = normalize_text(brand, lowercase=True, strip_accents=True, collapse_whitespace=True)
        if not brand_norm or brand_norm in seen:
            continue

        brand_tokens = brand_norm.split()
        token_count = len(brand_tokens)

        if token_count == 1:
            brand_word = brand_tokens[0]
            for token in tokens:
                if token == brand_word:
                    matches.append(brand)
                    seen.add(brand_norm)
                    break
                if banded_levenshtein(token, brand_word, max_distance) is not None:
                    matches.append(brand)
                    seen.add(brand_norm)
                    break
        else:
            window = token_count
            for idx in range(len(tokens) - window + 1):
                candidate = " ".join(tokens[idx : idx + window])
                if candidate == brand_norm:
                    matches.append(brand)
                    seen.add(brand_norm)
                    break
                if banded_levenshtein(candidate, brand_norm, max_distance) is not None:
                    matches.append(brand)
                    seen.add(brand_norm)
                    break
    return matches
