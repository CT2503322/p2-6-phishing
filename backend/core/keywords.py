import re
from typing import List, Dict

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


def find(text: str) -> List[Dict[str, int]]:
    t = (text or "").lower()
    out = []
    for w in WORDS:
        c = len(re.findall(re.escape(w), t))
        if c:
            out.append({"keyword": w, "count": c})
    return out
