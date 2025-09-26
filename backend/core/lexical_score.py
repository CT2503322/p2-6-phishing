from __future__ import annotations

import re
from typing import Iterable, Tuple


_KEYWORD_RULES: Tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"\burgent\b", re.IGNORECASE), 2, 'urgent language'),
    (re.compile(r"verify (your|the)?", re.IGNORECASE), 2, 'verification request'),
    (re.compile(r"\bpassword\b", re.IGNORECASE), 2, 'password request'),
    (re.compile(r"\blogin\b", re.IGNORECASE), 1, 'login prompt'),
    (re.compile(r"click (here|below)", re.IGNORECASE), 1, 'click directive'),
    (re.compile(r"confirm (account|details)", re.IGNORECASE), 2, 'account confirmation'),
    (re.compile(r"update (account|billing)", re.IGNORECASE), 1, 'update request'),
)


def lexical_score(subj: str, body: str) -> tuple[int, list[str]]:
    """Return a heuristic score based on risky wording.

    We sum the weights for matched patterns but cap at 4 so a single
    legitimate keyword does not overwhelm the score.
    """
    text = f"{subj or ''} {body or ''}"
    matches: list[str] = []
    score = 0
    for pattern, weight, label in _KEYWORD_RULES:
        if pattern.search(text):
            matches.append(label)
            score += weight
    return min(score, 4), matches
