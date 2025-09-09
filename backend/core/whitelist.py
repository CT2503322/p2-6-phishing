import os
from typing import Set


def normalize_domain(domain: str) -> str:
    """Normalize domain by removing 'www.' prefix and converting to lowercase."""
    domain = domain.lower()
    if domain.startswith("www."):
        return domain[4:]
    return domain


def load_whitelist(path: str = "../data/whitelist.txt") -> Set[str]:
    """Load whitelist from file into a set for O(1) lookups."""
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return {normalize_domain(line.strip()) for line in f if line.strip()}


def is_whitelisted(domain: str, wl: Set[str]) -> bool:
    """Check if domain is in whitelist using O(1) set membership."""
    return normalize_domain(domain) in wl
