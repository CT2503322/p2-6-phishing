from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

from backend.core.position import KeywordHit, score_keyword_positions

FALLBACK_KEYWORDS: tuple[str, ...] = (
    'urgent',
    'click here',
    'verify',
    'login',
    'password',
    'account',
)

SUSPICIOUS_TERMS_PATH = Path(__file__).resolve().parents[2] / 'data' / 'suspicious_terms.txt'


def lexical_score(subject: str | None, body: str | None, keywords: Iterable[str] | None = None) -> tuple[int, List[str], List[KeywordHit]]:
    """Score suspicious keywords with positional weighting."""

    keyword_list = list(keywords) if keywords is not None else _default_keywords()
    total_points, matched, hits = score_keyword_positions(subject, body, keyword_list)
    return total_points, matched, hits


@lru_cache(maxsize=1)
def _default_keywords() -> List[str]:
    terms = _load_terms_from_file(SUSPICIOUS_TERMS_PATH)
    return terms if terms else list(FALLBACK_KEYWORDS)


def _load_terms_from_file(path: Path) -> List[str]:
    if not path.exists():
        return []

    loaded: List[str] = []
    try:
        with path.open('r', encoding='utf-8') as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                loaded.append(line.lower())
    except OSError:
        return []

    return loaded
