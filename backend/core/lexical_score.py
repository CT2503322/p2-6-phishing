from __future__ import annotations

import re
from typing import List, Tuple

_KEYWORD_RULES: Tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"\burgent\b", re.IGNORECASE), 2, 'urgent language'),
    (re.compile(r"verify (your|the)?", re.IGNORECASE), 2, 'verification request'),
    (re.compile(r"\bpassword\b", re.IGNORECASE), 2, 'password request'),
    (re.compile(r"\blogin\b", re.IGNORECASE), 1, 'login prompt'),
    (re.compile(r"click (here|below)", re.IGNORECASE), 1, 'click directive'),
    (re.compile(r"confirm (account|details)", re.IGNORECASE), 2, 'account confirmation'),
    (re.compile(r"update (account|billing)", re.IGNORECASE), 1, 'update request'),
)


def lexical_score(subj: str, body: str) -> tuple[int, list[str], list[str]]:
    """Return a heuristic score and matched phrases/descriptions."""
    text = f"{subj or ''} {body or ''}"
    matched_phrases: list[str] = []
    matched_descriptions: list[str] = []
    score = 0
    for pattern, weight, label in _KEYWORD_RULES:
        match = pattern.search(text)
        if match:
            matched_phrases.append(match.group(0))
            matched_descriptions.append(label)
            score += weight
    return min(score, 4), matched_phrases, matched_descriptions
