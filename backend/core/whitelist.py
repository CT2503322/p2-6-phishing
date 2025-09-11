import os
import re
from pathlib import Path
from typing import Set, Optional, List
from urllib.parse import urlparse
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


def validate_domain(domain: str) -> bool:
    """
    Validate domain name using regex pattern and IDNA encoding.

    Supports:
    - Basic domain format (label.label)
    - IDNA encoded domains (xn--...)
    - IPv4 addresses
    - Bracketed IPv6 addresses

    Args:
        domain: Domain to validate

    Returns:
        True if valid domain, False otherwise
    """
    if not domain or len(domain) > 253:
        return False

    domain = domain.strip()

    # Handle IPv6 addresses [::1]
    if domain.startswith("[") and domain.endswith("]"):
        domain = domain[1:-1]
        try:
            return ":" in domain  # Basic IPv6 check
        except:
            return False

    # Handle IPv4 addresses
    try:
        parts = domain.split(".")
        if len(parts) == 4 and all(
            part.isdigit() and 0 <= int(part) <= 255 for part in parts
        ):
            return True
    except:
        pass

    # Enhanced regex pattern for domain validation
    # Support ASCII domains and basic structure check
    # Note: We'll rely more heavily on IDNA validation for non-ASCII domains
    ascii_pattern = re.compile(
        r"""
        ^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*
        [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?
        (?:\.[a-zA-Z]{2,})?$
        """,
        re.VERBOSE,
    )

    # Allow Unicode characters if the domain contains non-ASCII chars
    unicode_pattern = re.compile(
        r"""
        ^(?:[a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF](?:[a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF-]{0,61}[a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])?\.)*
        [a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF](?:[a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF-]{0,61}[a-zA-Z0-9\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])?
        (?:\.[a-zA-Z]{2,})?$
        """,
        re.VERBOSE | re.UNICODE,
    )

    if not (ascii_pattern.match(domain) or unicode_pattern.match(domain)):
        return False

    # Additional IDNA validation
    try:
        # Try to encode as IDNA to check if it's valid
        encoded = domain.encode("idna")
        decoded = encoded.decode("idna")
        # If successful, ensure the round-trip is consistent
        if domain == decoded:
            return True
        else:
            # Domain might already be IDNA format
            return True
    except (UnicodeError, UnicodeDecodeError):
        # If it fails IDNA encoding/decoding, it's not a valid domain
        # but the regex might still accept it
        return False


def matches_wildcard(domain: str, pattern: str) -> bool:
    """
    Check if domain matches a wildcard pattern.

    Supports:
    - *.domain.com (matches sub.domain.com, mail.domain.com, etc.)
    - domain.* (matches domain.com, domain.org, etc.)
    - *domain* (contains match)

    Args:
        domain: Domain to check
        pattern: Wildcard pattern

    Returns:
        True if matches, False otherwise
    """
    if not pattern or not domain:
        return False

    domain = domain.lower().strip()
    pattern = pattern.lower().strip()

    # Convert wildcard to regex pattern
    regex_pattern = re.escape(pattern)
    regex_pattern = regex_pattern.replace(r"\*", ".*")
    regex_pattern = f"^{regex_pattern}$"

    try:
        return bool(re.match(regex_pattern, domain))
    except re.error:
        return False


def find_wildcard_matches(domain: str, wl: Set[str]) -> List[tuple[str, str]]:
    """
    Find all wildcard matches for a domain from whitelist.

    Args:
        domain: Domain to check
        wl: Whitelist set

    Returns:
        List of (matched_pattern, scope) tuples
    """
    normalized = normalize_domain(domain)
    matches = []

    for pattern in wl:
        if "*" in pattern and matches_wildcard(normalized, pattern):
            # Determine scope based on pattern type
            if pattern.startswith("*."):
                # *.domain.com matches subdomains
                scope = "wildcard-subdomain"
            elif pattern.endswith(".*"):
                # domain.* matches TLD variations
                scope = "wildcard-tld"
            else:
                # *domain* or other patterns
                scope = "wildcard-pattern"

            matches.append((pattern, scope))

        # Also check subdomain matches for wildcard patterns
        elif pattern.startswith("*.") and normalized.endswith(pattern[2:]):
            matches.append((pattern, "wildcard-apex"))

    return matches


def determine_scope(normalized_domain: str, matched_domain: str) -> str:
    """
    Determine the scope of the whitelist match.

    Args:
        normalized_domain: The domain being checked (normalized)
        matched_domain: The whitelisted domain that matched (normalized)

    Returns:
        'exact' | 'apex' | 'subdomain' | 'wildcard-subdomain' | 'wildcard-tld' | 'wildcard-pattern'
    """
    if normalized_domain == matched_domain:
        return "exact"

    # Handle wildcard scopes
    if "*" in matched_domain:
        if matched_domain.startswith("*."):
            return "wildcard-subdomain"
        elif matched_domain.endswith(".*"):
            return "wildcard-tld"
        else:
            return "wildcard-pattern"

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

    # Validate domain format
    if not validate_domain(normalized):
        return None

    matching = []

    # First, check for wildcard matches (higher precedence)
    wildcard_matches = find_wildcard_matches(normalized, wl)
    for wildcard_pattern, scope in wildcard_matches:
        matching.append(
            WhitelistHit(matched_domain=wildcard_pattern, scope=scope, reason=reason)
        )

    # Then check for regular (non-wildcard) matches
    for whitelist_domain in wl:
        # Skip wildcard patterns as they're handled above
        if "*" in whitelist_domain:
            continue

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
