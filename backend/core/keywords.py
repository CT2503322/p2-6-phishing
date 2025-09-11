import re
from typing import List, Dict, Tuple, Optional

from backend.core.position import (
    find_keywords_with_positions,
    calculate_positioned_score,
)
from backend.utils.models import KeywordHit

# Phishing-related keywords for detection
WORDS = [
    "urgent",
    "action required",
    "verify",
    "password",
    "account",
    "suspended",
    "unusual activity",
    "invoice",
    "payment",
    "security alert",
    "click here",
    "confidential",
    "financial",
    "login",
]

# Keyword weights (higher weights for more suspicious keywords)
KEYWORD_WEIGHTS = {
    "urgent": 1.5,
    "action required": 2.0,
    "verify": 1.2,
    "password": 2.5,
    "account": 1.3,
    "suspended": 1.8,
    "unusual activity": 1.7,
    "invoice": 1.0,
    "payment": 1.0,
    "security alert": 1.8,
    "click here": 2.0,
    "confidential": 1.2,
    "financial": 1.0,
    "login": 1.5,
}

# Pre-compile regex patterns for efficiency (case-insensitive)
WORD_PATTERNS = {word: re.compile(re.escape(word), re.IGNORECASE) for word in WORDS}


def find(text: str) -> List[Dict[str, int]]:
    """
    Legacy function - Find occurrences of phishing keywords in the given text.

    Args:
        text: Input text to search

    Returns:
        List of dicts with keyword and count (deprecated - use find_keywords_with_positions)
    """
    if not text:
        return []

    out = []
    for word, pattern in WORD_PATTERNS.items():
        count = len(pattern.findall(text))
        if count > 0:
            out.append({"keyword": word, "count": count})
    return out


def analyze_keywords(
    subject: str, body_text: str, use_positions: bool = True
) -> Dict[str, any]:
    """
    Analyze keywords in subject and body with optional position weighting.

    Args:
        subject: Email subject line
        body_text: Cleaned email body text
        use_positions: Whether to use position-based weighting

    Returns:
        Dictionary with keyword analysis results
    """
    if use_positions:
        return calculate_positioned_score(subject, body_text, KEYWORD_WEIGHTS)
    else:
        # Legacy simple count-based approach
        subject_hits = find(subject) if subject else []
        body_hits = find(body_text) if body_text else []

        # Convert to new format for consistency
        keyword_hits = []
        total_score = 0.0

        # Process subject hits
        for hit in subject_hits:
            keyword = hit["keyword"]
            count = hit["count"]
            base_weight = KEYWORD_WEIGHTS.get(keyword, 1.0)

            for i in range(count):
                keyword_hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=base_weight,
                        where="subject",
                        pos=0,  # Not tracking positions in legacy mode
                        window="subject",
                    )
                )
                total_score += base_weight

        # Process body hits
        for hit in body_hits:
            keyword = hit["keyword"]
            count = hit["count"]
            base_weight = KEYWORD_WEIGHTS.get(keyword, 1.0)

            for i in range(count):
                keyword_hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=base_weight,
                        where="body",
                        pos=0,  # Not tracking positions in legacy mode
                        window="body",
                    )
                )
                total_score += base_weight

        return {
            "keyword_hits": keyword_hits,
            "term_stats": _build_term_stats(keyword_hits),
            "total_score": total_score,
        }


def _build_term_stats(hits: List[KeywordHit]) -> Dict[str, Dict]:
    """Build term statistics from hits."""
    term_stats = {}
    for hit in hits:
        if hit.term not in term_stats:
            term_stats[hit.term] = {
                "count": 0,
                "total_score": 0.0,
                "positions": [],
                "windows": [],
            }

        term_stats[hit.term]["count"] += 1
        term_stats[hit.term]["total_score"] += hit.weight
        term_stats[hit.term]["positions"].append(hit.pos)
        term_stats[hit.term]["windows"].append(hit.window)

    return term_stats
