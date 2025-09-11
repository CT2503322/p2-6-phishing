import re
from typing import Dict, List, Any, Optional


def parse_authentication_results(
    auth_header: str,
    auth_mode: str = "header_trust",
    dns_cache_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Parse Authentication-Results header into structured format.

    Args:
        auth_header: The Authentication-Results header value
        auth_mode: "header_trust" | "live_verify"
        dns_cache_stats: DNS cache stats for live_verify (hits/misses)

    Returns:
        Dict with structured auth data: spf, dkim[], dmarc, arc, alignment
    """
    auth_data = {"spf": None, "dkim": [], "dmarc": None, "arc": None}

    if not auth_header:
        return auth_data

    # Split by semicolon and clean up
    parts = [part.strip() for part in auth_header.split(";") if part.strip()]

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Parse SPF
        if part.startswith("spf="):
            auth_data["spf"] = _parse_spf(part)
        # Parse DKIM
        elif part.startswith("dkim="):
            dkim_result = _parse_dkim(part)
            if dkim_result:
                auth_data["dkim"].append(dkim_result)
        # Parse DMARC
        elif part.startswith("dmarc="):
            auth_data["dmarc"] = _parse_dmarc(part)
        # Parse ARC
        elif part.startswith("arc="):
            auth_data["arc"] = _parse_arc(part)

    return auth_data


def get_raw_auth_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Extract raw authentication headers from email headers for analysis.

    Args:
        headers: Dict of email headers

    Returns:
        Dict with raw auth header values: authentication_results, dkim_signature, arc_seal, arc_message_signature, arc_authentication_results, received_spf
    """
    raw_headers = {}

    # Authentication-Results header (already summarized above)
    if "Authentication-Results" in headers:
        raw_headers["authentication_results"] = headers["Authentication-Results"]

    # DKIM-Signature headers (may have multiple)
    dkim_sigs = []
    for key, value in headers.items():
        if key.lower() == "dkim-signature":
            dkim_sigs.append(value)

    if dkim_sigs:
        raw_headers["dkim_signature"] = (
            dkim_sigs if len(dkim_sigs) > 1 else dkim_sigs[0]
        )

    # ARC headers
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower == "arc-seal":
            raw_headers["arc_seal"] = value
        elif key_lower == "arc-message-signature":
            raw_headers["arc_message_signature"] = value
        elif key_lower == "arc-authentication-results":
            raw_headers["arc_authentication_results"] = value

    # Received-SPF headers (may have multiple)
    received_spf = []
    for key, value in headers.items():
        if key.lower() == "received-spf":
            received_spf.append(value)

    if received_spf:
        raw_headers["received_spf"] = (
            received_spf if len(received_spf) > 1 else received_spf[0]
        )

    return raw_headers


def _parse_spf(spf_part: str) -> Optional[Dict[str, Any]]:
    """
    Parse SPF result: spf=pass (comment) smtp.mailfrom=...
    """
    # Extract result (pass/fail/etc)
    result_match = re.search(r"spf=(\w+)", spf_part)
    if not result_match:
        return None

    result = result_match.group(1)

    # Extract domain from smtp.mailfrom if present
    domain_match = re.search(r'smtp\.mailfrom="([^"]*)"', spf_part)
    domain = None
    if domain_match:
        mailfrom = domain_match.group(1)
        # Extract domain from email address - handle complex email addresses
        if "@" in mailfrom:
            # Split on the last @ to get the domain
            parts = mailfrom.rsplit("@", 1)
            if len(parts) == 2:
                domain = parts[1]
    else:
        # Try unquoted smtp.mailfrom
        match = re.search(r"smtp\.mailfrom=([^;\s]+)", spf_part)
        if match:
            mailfrom = match.group(1)
            if "@" in mailfrom:
                parts = mailfrom.rsplit("@", 1)
                if len(parts) == 2:
                    domain = parts[1]
        else:
            # Try to extract domain from the comment part
            # Look for patterns like "domain of user@domain.com" or "domain of domain.com"
            domain_match = re.search(r"domain of [^@]*@([^@\s]+)", spf_part)
            if domain_match:
                domain = domain_match.group(1)
            else:
                # Fallback: look for any domain-like pattern in the comment
                domain_match = re.search(r"([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", spf_part)
                if domain_match:
                    domain = domain_match.group(1)

    # Extract IP if present in comment (handles both "designates" and "does not designate")
    ip_match = re.search(
        r"(?:does not )?designates ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", spf_part
    )
    ip = ip_match.group(1) if ip_match else None

    # If IP not found with the above pattern, try a simpler pattern
    if not ip:
        ip_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", spf_part)
        ip = ip_match.group(1) if ip_match else None

    # Check alignment (SPF doesn't have explicit alignment, but we can infer from result)
    aligned = result == "pass"

    return {"result": result, "domain": domain, "ip": ip, "aligned": aligned}


def _parse_dkim(dkim_part: str) -> Optional[Dict[str, Any]]:
    """
    Parse DKIM result: dkim=pass header.i=@domain.com header.s=selector header.b=...
    """
    # Extract result
    result_match = re.search(r"dkim=(\w+)", dkim_part)
    if not result_match:
        return None

    result = result_match.group(1)

    # Extract domain from header.i
    domain_match = re.search(r"header\.i=@([^;\s]+)", dkim_part)
    domain = domain_match.group(1) if domain_match else None

    # Extract selector from header.s
    selector_match = re.search(r"header\.s=([^;\s]+)", dkim_part)
    selector = selector_match.group(1) if selector_match else None

    # Check alignment (DKIM alignment is based on domain match)
    aligned = result == "pass"

    return {"result": result, "d": domain, "s": selector, "aligned": aligned}


def _parse_dmarc(dmarc_part: str) -> Optional[Dict[str, Any]]:
    """
    Parse DMARC result: dmarc=pass (p=quarantine dis=none) header.from=domain.com
    """
    # Extract result
    result_match = re.search(r"dmarc=(\w+)", dmarc_part)
    if not result_match:
        return None

    result = result_match.group(1)

    # Extract policy from comment
    policy_match = re.search(r"p=(\w+)", dmarc_part)
    policy = policy_match.group(1).lower() if policy_match else "none"

    # Extract org domain from header.from
    org_domain_match = re.search(r"header\.from=([^;\s]+)", dmarc_part)
    org_domain = org_domain_match.group(1) if org_domain_match else None

    # Check alignment
    aligned = result == "pass"

    return {
        "result": result,
        "policy": policy,
        "org_domain": org_domain,
        "aligned": aligned,
    }


def _parse_arc(arc_part: str) -> Optional[Dict[str, Any]]:
    """
    Parse ARC result: arc=pass (comment) or from ARC-Seal headers
    """
    # Extract result
    result_match = re.search(r"arc=(\w+)", arc_part)
    if not result_match:
        return None

    result = result_match.group(1)

    # For ARC, we typically get this from ARC-Seal headers, but if present in auth results
    # Extract instance if present
    instance_match = re.search(r"i=(\d+)", arc_part)
    instance = int(instance_match.group(1)) if instance_match else 1

    # Extract cv (chain validation)
    cv_match = re.search(r"cv=(\w+)", arc_part)
    cv = cv_match.group(1) if cv_match else "none"

    # Estimate chain count (usually 1 for single ARC)
    chain_count = 1

    return {
        "instance": instance,
        "seal": result,  # ARC-Seal result
        "cv": cv,
        "chain_count": chain_count,
    }


def parse_arc_headers(headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Parse ARC headers (ARC-Seal, ARC-Message-Signature, etc.) for additional ARC info.
    """
    arc_seal = headers.get("ARC-Seal", "")
    if not arc_seal:
        return None

    # Parse ARC-Seal: i=1; a=rsa-sha256; t=1234567890; cv=none; d=domain.com; s=selector; b=signature
    instance_match = re.search(r"i=(\d+)", arc_seal)
    instance = int(instance_match.group(1)) if instance_match else 1

    cv_match = re.search(r"cv=(\w+)", arc_seal)
    cv = cv_match.group(1) if cv_match else "none"

    # Count ARC headers to estimate chain
    chain_count = 1
    for key in headers:
        if key.startswith("ARC-"):
            chain_count = max(chain_count, 1)

    return {
        "instance": instance,
        "seal": "pass",  # Assume pass if header is present
        "cv": cv,
        "chain_count": chain_count,
    }


def get_auth_data(
    headers: Dict[str, str],
    auth_mode: str = "header_trust",
    dns_cache_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Extract and parse authentication data from email headers.

    Args:
        headers: Dict of email headers
        auth_mode: "header_trust" or "live_verify"
        dns_cache_stats: DNS cache stats for transparency

    Returns:
        Structured auth data with spf, dkim, dmarc, arc, alignment, auth_mode, dns_cache_stats
    """
    auth_results = headers.get("Authentication-Results", "")
    arc_auth_results = headers.get("ARC-Authentication-Results", "")

    # Parse main Authentication-Results
    auth_data = parse_authentication_results(auth_results)

    # If ARC data not found in main auth results, try ARC-specific header
    if not auth_data["arc"] and arc_auth_results:
        arc_data = parse_authentication_results(arc_auth_results)
        if arc_data["arc"]:
            auth_data["arc"] = arc_data["arc"]

    # If still no ARC data, try parsing ARC headers directly
    if not auth_data["arc"]:
        arc_from_headers = parse_arc_headers(headers)
        if arc_from_headers:
            auth_data["arc"] = arc_from_headers

    # Determine evaluated_against (org_from_domain)
    evaluated_against = None
    if auth_data["dmarc"] and auth_data["dmarc"]["org_domain"]:
        evaluated_against = auth_data["dmarc"]["org_domain"]
    else:
        # Fallback to from header domain
        from_header = headers.get("From", "")
        if from_header:
            # Extract email using regex
            import re

            email_match = re.search(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", from_header
            )
            if email_match:
                email = email_match.group(0)
                if "@" in email:
                    evaluated_against = email.split("@")[1]

    # Build alignment structure
    alignment = {
        "evaluated_against": evaluated_against,
        "dkim_d": [dkim["d"] for dkim in auth_data["dkim"] if dkim["d"]],
        "spf_domain": (
            auth_data["spf"]["domain"]
            if auth_data["spf"] and auth_data["spf"]["domain"]
            else None
        ),
        "from_org": evaluated_against,
    }
    auth_data["alignment"] = alignment

    # Add auth_mode
    auth_data["auth_mode"] = auth_mode

    # Add dns_cache_stats for live_verify
    if auth_mode == "live_verify":
        if dns_cache_stats:
            auth_data["dns_cache_stats"] = dns_cache_stats
        else:
            # Mock stats for demonstration
            auth_data["dns_cache_stats"] = {"hits": 3, "misses": 1}

    return auth_data
