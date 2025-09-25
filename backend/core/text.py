"""Text processing utilities for phishing detection heuristics."""

from __future__ import annotations

import re
import unicodedata
from typing import List

_WHITESPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[A-Za-z0-9']+")
_CONTROL_CATEGORIES = {"Cc", "Cf", "Cs"}


def normalize_text(
    text: str | None,
    *,
    lowercase: bool = True,
    strip_accents: bool = True,
    collapse_whitespace: bool = True,
) -> str:
    """Return a consistently cleaned version of ``text``."""

    if not text:
        return ""

    normalized = unicodedata.normalize("NFKC", text)
    normalized = _strip_control_characters(normalized)

    if strip_accents:
        normalized = _strip_accents(normalized)

    if lowercase:
        normalized = normalized.lower()

    if collapse_whitespace:
        normalized = _WHITESPACE_RE.sub(" ", normalized).strip()

    return normalized


def clean_text(text: str | None) -> str:
    """Convenience wrapper that normalises, strips accents, and collapses whitespace."""

    return normalize_text(text, lowercase=True, strip_accents=True, collapse_whitespace=True)


def tokenize_words(
    text: str | None,
    *,
    lowercase: bool = True,
    min_length: int = 1,
) -> List[str]:
    """Tokenise ``text`` into alphanumeric words after normalisation."""

    if min_length < 1:
        raise ValueError("min_length must be >= 1")

    cleaned = normalize_text(text, lowercase=lowercase, strip_accents=True, collapse_whitespace=True)
    if not cleaned:
        return []

    tokens = [token for token in _TOKEN_RE.findall(cleaned) if len(token) >= min_length]
    return tokens


def _strip_control_characters(text: str) -> str:
    cleaned_chars = []
    for ch in text:
        category = unicodedata.category(ch)
        if category in _CONTROL_CATEGORIES:
            if ch in ("\n", "\r", "\t"):
                cleaned_chars.append(" ")
            continue
        cleaned_chars.append(ch)
    return "".join(cleaned_chars)


def _strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
