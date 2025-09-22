from backend.core.lexical_score import lexical_score
from backend.core.attachment_checks import archive_name_suspicious, is_dangerous
from backend.core.helpers import norm_domain, parse_core_addresses
from backend.core.identity_checks import is_freemx, is_idn_or_confusable, mentions_brand
from backend.core.routing_checks import msgid_domain_mismatch, received_anomaly
from backend.core.url_checks import WHITELIST_DOMAINS, anchor_text_domain_mismatch, is_high_risk_tld, is_shortener, looks_credential_harvest


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
    """
    score = 0
    from_addr, reply_to, return_path = parse_core_addresses(headers)
    from_dom = norm_domain(from_addr.split('@')[1]) if from_addr and '@' in from_addr else None
    rt_dom = norm_domain(reply_to.split('@')[1]) if reply_to and '@' in reply_to else None
    rp_dom = norm_domain(return_path.split('@')[1]) if return_path and '@' in return_path else None

    # Identity
    if rt_dom and rt_dom != from_dom: score += 3
    if rp_dom and rp_dom != from_dom: score += 2
    if is_idn_or_confusable(from_dom): score += 3
    if is_freemx(from_dom) and mentions_brand(headers.get('subject', ''), body_text): score += 2

    # Routing
    if received_anomaly(headers.getall('received') if hasattr(headers, 'getall') else []): score += 2
    if msgid_domain_mismatch(headers.get('message-id'), from_dom): score += 1

    # Lexical (single pass with zones)
    score += lexical_score(headers.get('subject',''), body_text)

    # URLs
    for u in urls:
        if anchor_text_domain_mismatch(u): score += 3
        if is_high_risk_tld(u.hostname): score += 2
        if is_shortener(u.hostname): score += 1
        if looks_credential_harvest(u.path, u.query): score += 2

    # Attachments
    for att in attachments:
        if is_dangerous(att): score += 4
        if archive_name_suspicious(att): score += 2

    # Whitelist floor
    if from_dom in WHITELIST_DOMAINS: score = max(0, score - 4)

    return label_from(score), score
