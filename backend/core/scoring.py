from __future__ import annotations

from backend.core.lexical_score import lexical_score
from backend.core.position import score_keyword_positions
from backend.core.attachment_checks import archive_name_suspicious, is_dangerous
from backend.core.helpers import norm_domain, parse_core_addresses
from backend.core.identity_checks import is_freemx, is_idn_or_confusable, mentions_brand
from backend.core.routing_checks import msgid_domain_mismatch, received_anomaly
from backend.core.url_checks import WHITELIST_DOMAINS, check_urls


def label_from(score):
    """Label based on score."""
    if score >= 10:
        return 'HIGH'
    if score >= 5:
        return 'MEDIUM'
    return 'LOW'


def _address_domains(address: str | None) -> tuple[str | None, str | None]:
    if not address or '@' not in address:
        return None, None
    host = address.split('@', 1)[1]
    return (
        norm_domain(host, keep_subdomains=True),
        norm_domain(host),
    )


def score_email(headers, body_text, urls, attachments):
    """Combine heuristics to produce a phishing score.

    Returns (label, score, explanations, matched_keywords, suspicious_urls).
    """
    score = 0
    explanations: list[str] = []
    matched_keywords: list[str] = []

    from_addr, reply_to, return_path = parse_core_addresses(headers)
    from_host, from_dom = _address_domains(from_addr)
    reply_host, reply_dom = _address_domains(reply_to)
    return_host, return_dom = _address_domains(return_path)

    # Identity
    if reply_dom and from_dom and reply_dom != from_dom:
        score += 3
        explanations.append(
            f"+3 points: Reply-to domain differs from From domain ({reply_dom})"
        )
    if return_dom and from_dom and return_dom != from_dom:
        score += 2
        explanations.append(
            f"+2 points: Return-path domain differs from From domain ({return_dom})"
        )
    confusable_target = from_host or from_dom
    if confusable_target and (reason := is_idn_or_confusable(confusable_target)):
        score += 3
        explanations.append(
            f"+3 points: From domain contains IDN or confusable characters ({reason} in {confusable_target})"
        )
    if from_dom and is_freemx(from_dom):
        mentioned_brands = mentions_brand(headers.get('subject', ''), body_text)
        if mentioned_brands:
            score += 2
            explanations.append(
                f"+2 points: Free email provider ({from_dom}) with brand mention ({', '.join(mentioned_brands)})"
            )

    # Routing
    received_values = []
    if hasattr(headers, 'getall'):
        try:
            received_values = headers.getall('received')  # type: ignore[attr-defined]
        except Exception:
            received_values = []
    else:
        received_header = headers.get('received') if isinstance(headers, dict) else None
        if isinstance(received_header, (list, tuple)):
            received_values = list(received_header)
        elif received_header:
            received_values = [received_header]
    if received_values:
        if anomaly_reason := received_anomaly(received_values):
            score += 2
            explanations.append(f"+2 points: Anomalous Received headers ({anomaly_reason})")
    mismatched_msgid_dom = msgid_domain_mismatch(headers.get('message-id'), from_dom)
    if mismatched_msgid_dom:
        score += 1
        explanations.append(f"+1 point: Message-ID domain mismatch ({mismatched_msgid_dom})")

    # Lexical
    lex_score, matched_phrases, matched_descriptions = lexical_score(headers.get('subject', ''), body_text)
    matched_keywords = matched_phrases
    if lex_score:
        score += lex_score
        descriptor_text = ', '.join(matched_descriptions) if matched_descriptions else ', '.join(matched_phrases)
        explanations.append(
            f"+{lex_score} points: Matched phishing language ({descriptor_text})"
        )

    # Keyword position weighting (subject/early body emphasis)
    if matched_phrases:
        pos_points, _, pos_hits = score_keyword_positions(headers.get('subject', ''), body_text, matched_phrases)
        if pos_points:
            score += pos_points
            for hit in pos_hits:
                loc = "subject" if hit.location == "subject" else ("early body" if hit.location == "early_body" else "body")
                explanations.append(f"+{hit.points} points: Keyword '{hit.keyword}' in {loc}")

    # URLs
    suspicious_urls = check_urls(urls, sender_domain=from_host)
    url_points_applied = 0
    for finding in suspicious_urls:
        url = finding.get('url')
        reasons = finding.get('reasons') or []
        raw_points = int(finding.get('score', 0) or 0)
        if not url or raw_points <= 0:
            continue
        applied = min(raw_points, 4)
        if url_points_applied + applied > 8:
            applied = max(0, 8 - url_points_applied)
        if applied <= 0:
            continue
        url_points_applied += applied
        score += applied
        url_str = url.geturl()
        reason_str = '; '.join(reasons)
        explanations.append(
            f"+{applied} points: Suspicious URL {url_str} ({reason_str})"
        )

    # Attachments
    for att in attachments:
        if is_dangerous(att):
            score += 4
            explanations.append(f"+4 points: Dangerous attachment extension in {att}")
        if archive_name_suspicious(att):
            score += 2
            explanations.append(f"+2 points: Suspicious archive attachment {att}")

    # Whitelist floor
    if from_dom in WHITELIST_DOMAINS and score > 0:
        score = max(0, score - 4)
        explanations.append(f"-4 points: {from_dom} in whitelist")

    return label_from(score), score, explanations, matched_keywords, suspicious_urls
