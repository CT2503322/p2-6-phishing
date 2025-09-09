from typing import Dict, Any, List
from .keywords import find
from .whitelist import load_whitelist, is_whitelisted
from urllib.parse import urlparse
import re

THRESHOLD = 1.0
wl = load_whitelist()


def extract_domains(text: str) -> set[str]:
    """Extract domains from URLs in text."""
    urls = re.findall(r"https?://[^\s]+", text)
    domains = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain:
                domains.add(domain.lower())
        except:
            pass
    return domains


def check_keywords(subject: str, body: str) -> Dict[str, Any]:
    kws = find(subject + "\n" + body)
    score = min(1.0, 0.2 * sum(k["count"] for k in kws))
    reasons = ["KEYWORDS"] if score > 0 else []
    return {"score": score, "reasons": reasons, "meta": {"keywords": kws}}


def check_whitelist(subject: str, body: str, html: str) -> Dict[str, Any]:
    domains = extract_domains(subject + "\n" + body + "\n" + html)
    whitelisted = any(is_whitelisted(d, wl) for d in domains)
    return {
        "whitelisted": whitelisted,
        "reasons": ["WHITELISTED"] if whitelisted else [],
    }


def analyze(
    headers: Dict[str, Any], subject: str, body: str, html: str
) -> Dict[str, Any]:
    # Run checks
    kw_res = check_keywords(subject, body)
    wl_res = check_whitelist(subject, body, html)

    # Aggregate score
    score = kw_res["score"]
    if wl_res["whitelisted"]:
        score = min(score, 0.3)

    # Aggregate reasons
    reasons = kw_res["reasons"] + wl_res["reasons"]

    # Determine label
    if score == 0:
        label = "UNSCORED"
    elif score >= THRESHOLD:
        label = "PHISHING"
    else:
        label = "SAFE"

    return {
        "risk": round(score, 2),
        "label": label,
        "reasons": reasons,
        "meta": {**kw_res["meta"], "headers": headers, "subject": subject},
    }
