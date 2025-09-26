from __future__ import annotations

import re
from typing import List, Sequence, Tuple, Set
from urllib.parse import ParseResult

POINT_PREFIX_PATTERN = re.compile(r"^([+-]\d+)\s+points?:\s*(.*)$", re.IGNORECASE)


def build_explanations(
    label: str,
    score: int,
    raw_reasons: Sequence[str],
    matched_keywords: Sequence[str] | None = None,
    suspicious_urls: Sequence[Tuple[ParseResult, Sequence[str]]] | None = None,
    attachments: Sequence[str] | None = None,
) -> List[str]:
    """Convert scoring signals into reader-friendly explanations with actions."""

    reasons = list(raw_reasons or [])
    matched = [kw for kw in (matched_keywords or []) if kw]
    urls = list(suspicious_urls or [])
    attachment_names = [att for att in (attachments or []) if att]
    has_attachment_signal = any("attachment" in reason.lower() for reason in reasons)

    detail_lines = []
    for reason in reasons:
        humanized = _humanize_reason(reason)
        if humanized:
            detail_lines.append(humanized)

    label_upper = (label or "").upper()

    if not detail_lines:
        if label_upper == "LOW":
            detail_lines.append(
                "No strong phishing indicators were detected. Action: Stay alert for unusual requests even when a message looks safe."
            )
        else:
            detail_lines.append(
                "The message was flagged by the scoring engine, but specific signals could not be interpreted. Action: Treat the email as suspicious and verify through another channel."
            )

    summary = _build_summary(label_upper, score, matched)
    lines: List[str] = [summary] + detail_lines

    general_actions: List[str] = []
    if label_upper in {'MEDIUM', 'HIGH'}:
        general_actions = _general_actions(
            label_upper,
            urls,
            attachment_names,
            has_attachment_signal,
        )
        for action_line in general_actions:
            if action_line not in lines:
                lines.append(action_line)

    action_items = _collect_action_items(detail_lines, general_actions)
    if label_upper != 'LOW' and action_items:
        lines.append(_format_action_summary(action_items))

    return lines


def _build_summary(label: str, score: int, matched_keywords: Sequence[str]) -> str:
    severity_text = {
        "HIGH": "High risk phishing alert",
        "MEDIUM": "Elevated phishing risk",
        "LOW": "Low phishing risk",
    }
    guidance_text = {
        "HIGH": "Treat this message as malicious unless you can independently verify the sender.",
        "MEDIUM": "Proceed with caution and confirm key details before acting.",
        "LOW": "No immediate red flags were detected, but stay vigilant.",
    }

    summary = f"{severity_text.get(label, 'Phishing assessment')}: composite score {score}. {guidance_text.get(label, '')}"

    if matched_keywords:
        keywords_preview = ", ".join(list(dict.fromkeys(matched_keywords))[:3])
        summary += f" Flagged keywords: {keywords_preview}."

    return summary


def _general_actions(
    label: str,
    suspicious_urls: Sequence[Tuple[ParseResult, Sequence[str]]],
    attachments: Sequence[str],
    has_attachment_signal: bool,
) -> List[str]:
    actions: List[str] = []
    actions.append(
        "Next step: Verify the sender using a trusted contact method before responding or sharing information."
    )

    if suspicious_urls:
        seen_urls = set()
        for url, _ in suspicious_urls:
            url_text = _stringify_url(url)
            if url_text and url_text not in seen_urls:
                actions.append(
                    f"Next step: Do not visit {url_text}; navigate to the destination using a bookmark or manually typed address instead."
                )
                seen_urls.add(url_text)

    if has_attachment_signal:
        if attachments:
            attachments_preview = ", ".join(list(dict.fromkeys(attachments))[:2])
            actions.append(
                f"Next step: Delete or quarantine attachments ({attachments_preview}) until security confirms they are safe."
            )
        else:
            actions.append(
                "Next step: Delete any attachments from this email and only open files that security has cleared."
            )

    if label == "HIGH":
        actions.append(
            "Next step: Report this message to your security or IT response team and remove it from your inbox."
        )

    return actions


def _collect_action_items(detail_lines: Sequence[str], general_actions: Sequence[str]) -> List[str]:
    items: List[str] = []
    seen: Set[str] = set()

    for line in detail_lines:
        action = _extract_action_clause(line)
        if action and action not in seen:
            items.append(action)
            seen.add(action)

    for raw in general_actions:
        normalized = raw.replace('Next step:', '', 1).strip()
        normalized = normalized.rstrip('. ')
        if normalized and normalized not in seen:
            items.append(normalized)
            seen.add(normalized)

    return items


def _extract_action_clause(text: str) -> str | None:
    if 'Action:' not in text:
        return None
    clause = text.split('Action:', 1)[1].strip()
    clause = clause.rstrip('. ')
    return clause or None


def _format_action_summary(actions: Sequence[str], limit: int = 4) -> str:
    limited = list(actions)[:limit]
    summary = '; '.join(limited)
    if len(actions) > limit:
        summary += '; ...'
    return f'Action checklist: {summary}.'


def _humanize_reason(reason: str) -> str:
    delta, description = _split_points(reason)
    description = description.strip()

    handler_map = [
        ("Reply-to domain differs", _handle_reply_to_mismatch),
        ("Return-path domain differs", _handle_return_path_mismatch),
        ("From domain contains IDN", _handle_confusable_domain),
        ("Free email provider", _handle_free_provider_brand),
        ("Anomalous Received headers", _handle_received_anomaly),
        ("Message-ID domain mismatch", _handle_message_id_mismatch),
        ("Matched phishing keywords", _handle_keyword_group),
        ("Keyword '", _handle_single_keyword),
        ("Suspicious URL", _handle_suspicious_url),
        ("Dangerous attachment extension", _handle_dangerous_attachment),
        ("Suspicious archive attachment", _handle_archive_attachment),
        ("in whitelist", _handle_whitelist_hit),
    ]

    for needle, handler in handler_map:
        if needle in description:
            return handler(delta, description)

    return _compose_line(
        delta,
        f"Indicator: {description}",
        "Verify the message with the sender via a trusted channel before taking action.",
    )


def _handle_reply_to_mismatch(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    domain = parts[0] if parts else "an unknown domain"
    explanation = (
        f"The reply-to address routes responses to {domain}, which differs from the visible sender domain. Attackers often redirect replies to capture sensitive information."
    )
    action = "Confirm the request using a known-good channel before replying."
    return _compose_line(delta, explanation, action)


def _handle_return_path_mismatch(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    domain = parts[0] if parts else "an unknown domain"
    explanation = (
        f"The return-path domain {domain} does not match the From address, suggesting the email may have been sent from an unexpected system."
    )
    action = "Inspect the headers or involve security before trusting the message."
    return _compose_line(delta, explanation, action)


def _handle_confusable_domain(delta: int | None, description: str) -> str:
    match = re.search(r"\((.+?)\s+in\s+([^)]+)\)", description)
    if match:
        reason, domain = match.groups()
    else:
        parts = _extract_parentheticals(description)
        reason = parts[0] if parts else "confusable characters"
        domain = parts[1] if len(parts) > 1 else "the sender domain"
    explanation = (
        f"The sender domain {domain} uses {reason}, which can mimic a trusted brand or service."
    )
    action = "Compare the domain carefully and avoid logging in via links in the email."
    return _compose_line(delta, explanation, action)


def _handle_free_provider_brand(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    provider = parts[0] if parts else "a free provider"
    brands = parts[1] if len(parts) > 1 else "a well-known brand"
    explanation = (
        f"The message originates from the free email provider {provider} while referencing {brands}, a common impersonation tactic."
    )
    action = "Reach out through the brand's official support channels before complying."
    return _compose_line(delta, explanation, action)


def _handle_received_anomaly(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    reason = parts[0] if parts else "unexpected routing behaviour"
    explanation = (
        f"The Received headers show {reason}, indicating the email may have bypassed expected mail servers."
    )
    action = "Let your mail or security team review the full headers."
    return _compose_line(delta, explanation, action)


def _handle_message_id_mismatch(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    domain = parts[0] if parts else "an unknown domain"
    explanation = (
        f"The Message-ID domain differs from the sender ({domain}), which is often seen in forged emails."
    )
    action = "Verify the sender's legitimacy before following any instructions."
    return _compose_line(delta, explanation, action)


def _handle_keyword_group(delta: int | None, description: str) -> str:
    parts = _extract_parentheticals(description)
    keywords_text = parts[0] if parts else "high-risk keywords"
    keyword_list = ", ".join(
        kw.strip() for kw in keywords_text.split(",") if kw.strip()
    ) or keywords_text
    explanation = (
        f"The content contains known phishing keywords ({keyword_list}), signalling social engineering language."
    )
    action = "Scrutinise the request and confirm it via another medium before acting."
    return _compose_line(delta, explanation, action)


def _handle_single_keyword(delta: int | None, description: str) -> str:
    match = re.search(r"Keyword '(.+?)' in (.+)", description)
    if match:
        keyword, location = match.groups()
        location = location.replace("_", " ")
    else:
        keyword, location = "high-risk language", "the message"
    explanation = (
        f"The {location} includes the phishing trigger word '{keyword}', which attackers use to create urgency."
    )
    action = "Slow down and confirm the legitimacy of the request before responding."
    return _compose_line(delta, explanation, action)


def _handle_suspicious_url(delta: int | None, description: str) -> str:
    match = re.search(r"Suspicious URL\s+(\S+)\s+\(([^)]+)\)", description)
    if match:
        url, reason = match.groups()
    else:
        url, reason = "a linked site", "suspicious characteristics"
    explanation = (
        f"The link {url} looks risky ({reason})."
    )
    action = "Do not click the link; browse to the site manually if you need to verify it."
    return _compose_line(delta, explanation, action)


def _handle_dangerous_attachment(delta: int | None, description: str) -> str:
    match = re.search(r"in\s+(.+)$", description)
    attachment = match.group(1) if match else "the attachment"
    explanation = (
        f"The attachment {attachment} uses a high-risk file type often associated with malware."
    )
    action = "Delete the attachment and only open files that security has approved."
    return _compose_line(delta, explanation, action)


def _handle_archive_attachment(delta: int | None, description: str) -> str:
    match = re.search(r"attachment\s+(.+)$", description)
    attachment = match.group(1) if match else "the archive"
    explanation = (
        f"The archive {attachment} could conceal malicious payloads."
    )
    action = "Do not extract or open the archive until security clears it."
    return _compose_line(delta, explanation, action)


def _handle_whitelist_hit(delta: int | None, description: str) -> str:
    domain = description.replace("in whitelist", "").strip()
    explanation = (
        f"The sender domain {domain} is on the whitelist, reducing the score despite other indicators."
    )
    action = "Double-check that the whitelist entry is still appropriate if the email feels suspicious."
    return _compose_line(delta, explanation, action)


def _split_points(reason: str) -> Tuple[int | None, str]:
    match = POINT_PREFIX_PATTERN.match(reason.strip())
    if not match:
        return None, reason
    try:
        delta = int(match.group(1))
    except ValueError:
        delta = None
    description = match.group(2).strip()
    return delta, description


def _score_prefix(delta: int | None) -> str:
    if not delta:
        return ""
    points = abs(delta)
    point_word = "point" if points == 1 else "points"
    qualifier = "indicator" if delta > 0 else "mitigation"
    return f"{points}-{point_word} {qualifier}: "


def _compose_line(delta: int | None, explanation: str, action: str | None = None) -> str:
    prefix = _score_prefix(delta)
    text = explanation.rstrip(". ") + "."
    if action:
        action_clause = action.rstrip(". ") + "."
        return f"{prefix}{text} Action: {action_clause}"
    return f"{prefix}{text}"


def _extract_parentheticals(text: str) -> List[str]:
    return [match.group(1).strip() for match in re.finditer(r"\(([^)]+)\)", text)]


def _stringify_url(url: ParseResult) -> str:
    if hasattr(url, "geturl"):
        return url.geturl()
    return str(url)
