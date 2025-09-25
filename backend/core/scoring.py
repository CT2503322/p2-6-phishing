from backend.core.lexical_score import lexical_score
from backend.core.attachment_checks import archive_name_suspicious, is_dangerous
from backend.core.helpers import norm_domain, parse_core_addresses
from backend.core.identity_checks import is_freemx, is_idn_or_confusable, mentions_brand
from backend.core.routing_checks import msgid_domain_mismatch, received_anomaly
from backend.core.url_checks import WHITELIST_DOMAINS, check_urls, anchor_text_domain_mismatch, is_high_risk_tld, is_shortener, looks_credential_harvest


def label_from(score):
    """Label based on score.
    """
    if score >= 10:
        return 'HIGH'
    elif score >= 5:
        return 'MEDIUM'
    else:
        return 'LOW'


def score_email(headers, body_text, urls, attachments):
    """Main scoring function that combines all heuristics from the parsed EML file.
    Returns label, score, explanations, matched_keywords, suspicious_urls.
    """
    score = 0
    explanations = []
    matched_keywords = []
    from_addr, reply_to, return_path = parse_core_addresses(headers)
    from_dom = norm_domain(from_addr.split('@')[1]) if from_addr and '@' in from_addr else None
    rt_dom = norm_domain(reply_to.split('@')[1]) if reply_to and '@' in reply_to else None
    rp_dom = norm_domain(return_path.split('@')[1]) if return_path and '@' in return_path else None

    # Identity
    if rt_dom and rt_dom != from_dom:
        score += 3
        explanations.append(f"+3 points: Reply-to domain differs from From domain ({rt_dom})")
    if rp_dom and rp_dom != from_dom:
        score += 2
        explanations.append(f"+2 points: Return-path domain differs from From domain ({rp_dom})")
    if reason := is_idn_or_confusable(from_dom):
        score += 3
        explanations.append(f"+3 points: From domain contains IDN or confusable characters ({reason} in {from_dom})")
    if is_freemx(from_dom) and (mentioned_brands := mentions_brand(headers.get('subject', ''), body_text)):
        score += 2
        explanations.append(f"+2 points: Free email provider ({from_dom}) with brand mention ({', '.join(mentioned_brands)})")

    # Routing
    if anomaly_reason := received_anomaly(headers.getall('received') if hasattr(headers, 'getall') else []):
        score += 2
        explanations.append(f"+2 points: Anomalous Received headers ({anomaly_reason})")
    mismatched_msgid_dom = msgid_domain_mismatch(headers.get('message-id'), from_dom)
    if mismatched_msgid_dom:
        score += 1
        explanations.append(f"+1 point: Message-ID domain mismatch ({mismatched_msgid_dom})")

    # Lexical
    lex_score, matched_keywords, keyword_hits = lexical_score(headers.get('subject', ''), body_text)
    score += lex_score
    if keyword_hits:
        for hit in keyword_hits:
            location = hit.location.replace('_', ' ')
            explanations.append(f"+{hit.points} points: Keyword '{hit.keyword}' in {location}")
    elif matched_keywords:
        explanations.append(f"+{lex_score} points: Matched phishing keywords ({', '.join(matched_keywords)})")

    # URLs
    suspicious_urls = check_urls(urls)
    for u, reasons in suspicious_urls:
        url_str = u.geturl()
        reason_str = "; ".join(reasons)
        points_added = 0
        if anchor_text_domain_mismatch(u):
            points_added += 3
        if is_high_risk_tld(u.hostname):
            points_added += 2
        if is_shortener(u.hostname):
            points_added += 1
        if looks_credential_harvest(u.path, u.query):
            points_added += 2
        score += points_added
        if points_added > 0:
            explanations.append(f"+{points_added} points: Suspicious URL {url_str} ({reason_str})")

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
