from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from typing import List, Optional

from backend.core.helpers import norm_domain


@dataclass(frozen=True)
class ReplyToAnalysis:
    """Result of comparing Reply-To and From addresses."""

    score: int
    reasons: List[str]
    from_domain: Optional[str]
    reply_to_domain: Optional[str]


def _extract_domain(address: str | None) -> Optional[str]:
    if not address:
        return None

    real_address = parseaddr(address)[1]
    if '@' not in real_address:
        return None
    domain = real_address.split('@', 1)[1]
    return norm_domain(domain)


def analyze_reply_to(from_address: str | None, reply_to_address: str | None) -> ReplyToAnalysis:
    """Determine if Reply-To routing deviates from the visible sender."""

    from_domain = _extract_domain(from_address)
    reply_domain = _extract_domain(reply_to_address)

    score = 0
    reasons: List[str] = []

    if from_domain and reply_domain and reply_domain != from_domain:
        score += 3
        reasons.append(
            f"+3 points: Reply-to domain differs from From domain ({reply_domain})"
        )

    return ReplyToAnalysis(score=score, reasons=reasons, from_domain=from_domain, reply_to_domain=reply_domain)
