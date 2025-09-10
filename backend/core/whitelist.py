import os
from pathlib import Path
from typing import Set


def normalize_domain(domain: str) -> str:
    """
    Normalize domain by:
    - Converting to lowercase
    - Removing 'www.' prefix
    - Stripping trailing dots
    """
    if not domain:
        return ""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    if domain.endswith("."):
        domain = domain[:-1]
    return domain


def load_whitelist(path: str = "backend/data/whitelist.txt") -> Set[str]:
    """
    Load whitelist from file into a set for O(1) lookups.

    Args:
        path: Path to whitelist file (defaults to backend/data/whitelist.txt)

    Returns:
        Set of normalized whitelisted domains
    """
    whitelist_path = Path(path)
    if not whitelist_path.exists():
        return set()

    try:
        with open(whitelist_path, "r", encoding="utf-8") as f:
            return {normalize_domain(line.strip()) for line in f if line.strip()}
    except (OSError, UnicodeDecodeError) as e:
        # Log error and return empty set to avoid crashes
        print(f"Error loading whitelist from {path}: {e}")
        return set()


def is_whitelisted(domain: str, wl: Set[str]) -> bool:
    """
    Check if domain is in whitelist using O(1) set membership.

    Args:
        domain: Domain to check
        wl: Whitelist set

    Returns:
        True if domain is whitelisted
    """
    return normalize_domain(domain) in wl
