"""Utilities to parse Authentication-Results and Received-SPF headers."""

from __future__ import annotations

import re
from typing import Iterable, Mapping

_COMMENT_RE = re.compile(r"\(([^()]*)\)")
_METHOD_RESULT_RE = re.compile(r"^([a-z0-9_.-]+)\s*=\s*([^\s]+)(.*)$", re.IGNORECASE)
_RECEIVED_SPF_RE = re.compile(r"^(?P<result>[a-z]+)(?P<rest>.*)$", re.IGNORECASE)


def extract_authentication_metadata(headers: Mapping[str, Iterable[str]] | None) -> dict[str, list[dict]]:
    """Return parsed authentication metadata from raw header map."""

    if not headers:
        return {"authentication_results": [], "received_spf": []}

    auth_results: list[dict] = []
    for header_name in ("Authentication-Results", "ARC-Authentication-Results"):
        values = headers.get(header_name, [])
        auth_results.extend(_parse_authentication_results(values, header_name))

    received_spf = parse_received_spf(headers.get("Received-SPF", []))
    return {
        "authentication_results": auth_results,
        "received_spf": received_spf,
    }


def parse_authentication_results(values: Iterable[str] | None, header_name: str = "Authentication-Results") -> list[dict]:
    """Parse Authentication-Results style headers into structured data."""

    return _parse_authentication_results(values, header_name)


def parse_received_spf(values: Iterable[str] | None) -> list[dict]:
    """Parse Received-SPF headers into structured data."""

    if not values:
        return []

    entries: list[dict] = []
    for raw in values:
        if not raw:
            continue
        body = _strip_header_prefix(raw, "Received-SPF")
        if not body:
            continue
        tokens = [token.strip() for token in body.split(";") if token.strip()]
        if not tokens:
            continue

        first = tokens[0]
        comment_parts, first_clean = _separate_comments(first)
        match = _RECEIVED_SPF_RE.match(first_clean)
        if not match:
            continue
        result = match.group("result").lower()
        remainder = match.group("rest").strip()

        properties: dict[str, str] = {}
        if remainder:
            properties.update(_tokens_to_properties(remainder.split()))

        for token in tokens[1:]:
            token_comments, clean = _separate_comments(token)
            if clean and "=" in clean:
                key, value = clean.split("=", 1)
                properties[key.strip().lower()] = value.strip()
            if token_comments:
                comment_parts.extend(token_comments)

        entry: dict[str, object] = {"result": result}
        if properties:
            entry["properties"] = properties
        if comment_parts:
            entry["comment"] = " ".join(comment_parts).strip()
        entries.append(entry)
    return entries


def _parse_authentication_results(values: Iterable[str] | None, header_name: str) -> list[dict]:
    if not values:
        return []

    entries: list[dict] = []
    for raw in values:
        if not raw:
            continue
        body = _strip_header_prefix(raw, header_name)
        if not body:
            continue

        parts = [part.strip() for part in body.split(";") if part.strip()]
        if not parts:
            continue

        entry: dict[str, object] = {
            "header": header_name,
            "authserv_id": parts[0],
            "results": [],
        }
        for token in parts[1:]:
            parsed = _parse_auth_method_token(token)
            if parsed:
                entry["results"].append(parsed)
        entries.append(entry)
    return entries


def _parse_auth_method_token(token: str) -> dict | None:
    comment_parts, clean = _separate_comments(token)
    clean = clean.strip()
    if not clean:
        return None

    match = _METHOD_RESULT_RE.match(clean)
    if not match:
        return None

    method = match.group(1).lower()
    result = match.group(2).lower()
    remainder = match.group(3).strip()

    properties = _tokens_to_properties(remainder.split()) if remainder else {}

    parsed: dict[str, object] = {
        "method": method,
        "result": result,
    }
    if properties:
        parsed["properties"] = properties
    if comment_parts:
        parsed["comment"] = " ".join(comment_parts).strip()
    return parsed


def _tokens_to_properties(tokens: list[str]) -> dict[str, str]:
    properties: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key:
            properties[key] = value
    return properties


def _separate_comments(text: str) -> tuple[list[str], str]:
    comments = [match.strip() for match in _COMMENT_RE.findall(text) if match.strip()]
    stripped = _COMMENT_RE.sub("", text)
    return comments, stripped


def _strip_header_prefix(raw: str, header_name: str) -> str:
    prefix = f"{header_name}:"
    if raw.lower().startswith(prefix.lower()):
        return raw[len(prefix):].strip()
    return raw.strip()
