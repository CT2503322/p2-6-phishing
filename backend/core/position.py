from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Set

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
    seen: Set[str] = set()
    total_points = 0

    def record_hit(keyword: str, location: str, points: int, offset: int, signature: str) -> None:
        nonlocal total_points
        hits.append(KeywordHit(keyword, location, points, offset))
        if signature not in seen:
            matched.append(keyword)
            seen.add(signature)
        total_points += points

    for keyword in keywords:
        kw_norm = keyword.lower()
        if not kw_norm:
            continue

        if kw_norm in subject_norm:
            offset = _find_offset(subject_norm, kw_norm)
            record_hit(keyword, "subject", BASE_KEYWORD_POINTS + SUBJECT_BONUS, offset, kw_norm)
            continue

        if kw_norm in early_span:
            offset = _find_offset(early_span, kw_norm)
            record_hit(keyword, "early_body", BASE_KEYWORD_POINTS + EARLY_BODY_BONUS, offset, kw_norm)
            continue

        if kw_norm in late_span:
            offset = _find_offset(late_span, kw_norm)
            if offset >= 0:
                offset += early_body_window
            record_hit(keyword, "body", BASE_KEYWORD_POINTS, offset, kw_norm)

    return total_points, matched, hits
