import os
from pathlib import Path
from typing import Set, Optional
from backend.utils.models import WhitelistHit


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


def determine_scope(normalized_domain: str, matched_domain: str) -> str:
    """
    Determine the scope of the whitelist match.

    Args:
        normalized_domain: The domain being checked (normalized)
        matched_domain: The whitelisted domain that matched (normalized)

    Returns:
        'exact' | 'apex' | 'subdomain'
    """
    if normalized_domain == matched_domain:
        return "exact"

    norm_parts = normalized_domain.split(".")
    matched_parts = matched_domain.split(".")

    if len(norm_parts) > len(matched_parts):
        return "apex"  # matched is apex for domain
    else:
        return "subdomain"  # matched is subdomain of domain or same


def check_whitelist_hit(
    domain: str, wl: Set[str], reason: str = "manual-whitelist"
) -> Optional[list[WhitelistHit]]:
    """
    Check if domain is whitelisted and return hit details.

    Args:
        domain: Domain to check
        wl: Whitelist set
        reason: Reason for whitelist hit

    Returns:
        WhitelistHit if matched, None otherwise
    """
    normalized = normalize_domain(domain)
    if not normalized:
        return None

    matching = []
    for whitelist_domain in wl:
        if normalized == whitelist_domain:
            scope = determine_scope(normalized, whitelist_domain)
            matching.append(
                WhitelistHit(
                    matched_domain=whitelist_domain, scope=scope, reason=reason
                )
            )
        elif normalized.endswith("." + whitelist_domain):
            scope = determine_scope(normalized, whitelist_domain)
            matching.append(
                WhitelistHit(
                    matched_domain=whitelist_domain, scope=scope, reason=reason
                )
            )
        elif whitelist_domain.endswith("." + normalized):
            scope = determine_scope(normalized, whitelist_domain)
            matching.append(
                WhitelistHit(
                    matched_domain=whitelist_domain, scope=scope, reason=reason
                )
            )

    return matching if matching else None
