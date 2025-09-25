from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

EARLY_BODY_WINDOW = 400
BASE_KEYWORD_POINTS = 1
SUBJECT_BONUS = 2
EARLY_BODY_BONUS = 1


@dataclass(frozen=True)
class KeywordHit:
    """Capture where a suspicious keyword was found and how many points it carried."""

    keyword: str
    location: str
    points: int
    offset: int


def _normalize(text: str | None) -> str:
    return (text or "").lower()


def _find_offset(haystack: str, needle: str) -> int:
    try:
        return haystack.index(needle)
    except ValueError:
        return -1


def score_keyword_positions(
    subject: str | None,
    body: str | None,
    keywords: Iterable[str],
    early_body_window: int = EARLY_BODY_WINDOW,
) -> tuple[int, List[str], List[KeywordHit]]:
    """Score suspicious keywords with extra weight for subject/early body.

    Returns the total points awarded, the list of matched keywords (unique, in
    discovery order), and a detailed breakdown for downstream explanations.
    """

    subject_text = subject or ""
    body_text = body or ""

    subject_norm = _normalize(subject_text)
    body_norm = _normalize(body_text)
    early_span = body_norm[:early_body_window]
    late_span = body_norm[early_body_window:]

    hits: List[KeywordHit] = []
    matched: List[str] = []
    total_points = 0

    for keyword in keywords:
        kw_norm = keyword.lower()
        if not kw_norm:
            continue

        if kw_norm in subject_norm:
            offset = _find_offset(subject_norm, kw_norm)
            points = BASE_KEYWORD_POINTS + SUBJECT_BONUS
            hits.append(KeywordHit(keyword, "subject", points, offset))
            matched.append(keyword)
            total_points += points
            continue

        if kw_norm in early_span:
            offset = _find_offset(early_span, kw_norm)
            points = BASE_KEYWORD_POINTS + EARLY_BODY_BONUS
            hits.append(KeywordHit(keyword, "early_body", points, offset))
            matched.append(keyword)
            total_points += points
            continue

        if kw_norm in late_span:
            offset = _find_offset(late_span, kw_norm)
            if offset >= 0:
                offset += early_body_window
            points = BASE_KEYWORD_POINTS
            hits.append(KeywordHit(keyword, "body", points, offset))
            matched.append(keyword)
            total_points += points

    return total_points, matched, hits

