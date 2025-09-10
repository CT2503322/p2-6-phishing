"""
Position-based keyword weighting for phishing detection.

This module implements position weighting logic that prioritizes keywords
in email subjects and early body content, providing higher weights for
hits that appear closer to the beginning of important sections.
"""

import re
from typing import List, Dict

from ..ingestion.models import KeywordHit


class PositionScorer:
    """
    Implements position-based weighting for keyword hits.

    Keywords in email subjects and early body text are given higher weights
    as they are more visible and likely to influence user behavior.
    """

    # Weight multipliers for different positions
    SUBJECT_MULTIPLIER = 3.0
    EARLY_BODY_MULTIPLIER_BASE = 2.0

    def __init__(self, early_body_limit: int = 500):
        """
        Initialize position scorer.

        Args:
            early_body_limit: Character limit for early body weighting
        """
        self.early_body_limit = early_body_limit

    def score_hit(self, hit: KeywordHit) -> float:
        """
        Score a keyword hit based on its position.

        Args:
            hit: The keyword hit to score

        Returns:
            Position-weighted score multiplier
        """
        base_weight = hit.weight

        if hit.where == "subject":
            return base_weight * self.SUBJECT_MULTIPLIER

        elif hit.where == "body":
            return self._score_body_position(hit.pos, base_weight)

        return base_weight

    def _score_body_position(self, pos: int, base_weight: float) -> float:
        """Apply early-body decay weighting"""
        if pos >= self.early_body_limit:
            return base_weight  # No early-body boost

        # Linear decay: full boost at position 0, no boost at limit
        position_factor = 1.0 - (pos / self.early_body_limit)
        early_boost = self.EARLY_BODY_MULTIPLIER_BASE * position_factor

        return base_weight * (1.0 + early_boost)


def find_keywords_with_positions(
    subject: str, body_text: str, keywords: Dict[str, float]
) -> List[KeywordHit]:
    """
    Find keywords in both subject and body with position information.

    Args:
        subject: Email subject line
        body_text: Cleaned email body text
        keywords: Dictionary of keyword -> weight mapping

    Returns:
        List of KeywordHit objects with position data
    """
    hits = []

    # Pre-compile keyword patterns (case-insensitive)
    keyword_patterns = {}
    for keyword, weight in keywords.items():
        keyword_patterns[keyword] = re.compile(re.escape(keyword), re.IGNORECASE)

    # Search in subject
    if subject:
        for keyword, pattern in keyword_patterns.items():
            for match in pattern.finditer(subject):
                hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=keywords[keyword],
                        where="subject",
                        pos=match.start(),
                        window="subject",
                    )
                )

    # Search in body sections
    if body_text:
        # Early body window (first N characters)
        early_body = body_text[:500]
        early_window = "body_0_500"

        for keyword, pattern in keyword_patterns.items():
            for match in pattern.finditer(early_body):
                hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=keywords[keyword],
                        where="body",
                        pos=match.start(),
                        window=early_window,
                    )
                )

        # Full body for keywords beyond early window
        for keyword, pattern in keyword_patterns.items():
            offset = len(early_body) if len(body_text) < 500 else 500
            for match in pattern.finditer(body_text[offset:], offset):
                hits.append(
                    KeywordHit(
                        term=keyword,
                        weight=keywords[keyword],
                        where="body",
                        pos=match.start(),
                        window="body",
                    )
                )

    return hits


def calculate_positioned_score(
    subject: str, body_text: str, keywords: Dict[str, float] = None
) -> Dict[str, any]:
    """
    Calculate keyword hits with position weighting.

    Args:
        subject: Email subject line
        body_text: Cleaned email body text
        keywords: Keyword dictionary, defaults to phishing keywords

    Returns:
        Dictionary with hits and scored results
    """
    if keywords is None:
        from .keywords import WORDS

        keywords = {word: 1.0 for word in WORDS}

    # Find all hits
    hits = find_keywords_with_positions(subject, body_text, keywords)

    # Apply position weighting
    scorer = PositionScorer()
    scored_hits = []

    for hit in hits:
        updated_hit = KeywordHit(
            term=hit.term,
            weight=scorer.score_hit(hit),
            where=hit.where,
            pos=hit.pos,
            window=hit.window,
        )
        scored_hits.append(updated_hit)

    # Group by term for summary stats
    term_stats = {}
    for hit in scored_hits:
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

    return {
        "keyword_hits": scored_hits,
        "term_stats": term_stats,
        "total_score": sum(hit.weight for hit in scored_hits),
    }
