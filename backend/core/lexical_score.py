from __future__ import annotations

from typing import Iterable, List

from backend.core.position import KeywordHit, score_keyword_positions

DEFAULT_KEYWORDS: tuple[str, ...] = (
    'urgent',
    'click here',
    'verify',
    'login',
    'password',
    'account',
)


def lexical_score(subject: str | None, body: str | None, keywords: Iterable[str] | None = None) -> tuple[int, List[str], List[KeywordHit]]:
    """Score suspicious keywords with positional weighting.

    Returns total points, matched keyword list, and per-hit breakdown.
    """

    keyword_list = list(keywords or DEFAULT_KEYWORDS)
    total_points, matched, hits = score_keyword_positions(subject, body, keyword_list)
    return total_points, matched, hits

