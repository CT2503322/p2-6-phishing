import re
from typing import List, Dict

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

# Pre-compile regex patterns for efficiency (case-insensitive)
WORD_PATTERNS = {word: re.compile(re.escape(word), re.IGNORECASE) for word in WORDS}


def find(text: str) -> List[Dict[str, int]]:
    """
    Find occurrences of phishing keywords in the given text.

    Args:
        text: Input text to search

    Returns:
        List of dicts with keyword and count
    """
    if not text:
        return []

    out = []
    for word, pattern in WORD_PATTERNS.items():
        count = len(pattern.findall(text))
        if count > 0:
            out.append({"keyword": word, "count": count})
    return out
