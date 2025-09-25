import hashlib
import json
import math
import os
from typing import Any, Dict, Iterable, List, Tuple

from cachetools import TTLCache
from openai import OpenAI
from threading import Lock

SUPPORTED_LLM_MODELS: List[str] = ["gpt-5-nano", "gpt-4.1-nano", "gpt-4o-mini"]

_BODY_EXCERPT_LIMIT = int(os.getenv("LLM_BODY_EXCERPT_LIMIT", "2000"))
_CACHE_MAXSIZE = int(os.getenv("LLM_CACHE_MAXSIZE", "256"))
_CACHE_TTL_SECONDS = int(os.getenv("LLM_CACHE_TTL_SECONDS", "900"))
_MAX_BATCH_SIZE = max(1, int(os.getenv("LLM_MAX_BATCH_SIZE", "4")))

_CACHE = TTLCache(maxsize=_CACHE_MAXSIZE, ttl=_CACHE_TTL_SECONDS)
_CLIENTS: Dict[str, OpenAI] = {}
_CLIENT_LOCK = Lock()

_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst who evaluates emails for phishing. "
    "You must respond with strict JSON that follows the requested schema. "
    "Do not emit Markdown or explanatory text."
)


def get_supported_models() -> List[str]:
    """Return the list of LLM model identifiers supported by the service."""
    return list(SUPPORTED_LLM_MODELS)


def _get_client(api_key: str) -> OpenAI:
    """Return a cached OpenAI client for the given API key."""
    if not api_key:
        raise ValueError("Missing OpenAI API key")
    with _CLIENT_LOCK:
        client = _CLIENTS.get(api_key)
        if client is None:
            client = OpenAI(api_key=api_key)
            _CLIENTS[api_key] = client
        return client


def prepare_email_payload(parsed: Dict[str, Any], url_strings: Iterable[str], email_id: str) -> Dict[str, Any]:
    """Normalise email data for prompt construction and caching."""
    attachments_raw = parsed.get("attachments") or ""
    attachments: List[str]
    if isinstance(attachments_raw, list):
        attachments = [str(item).strip() for item in attachments_raw if str(item).strip()]
    elif isinstance(attachments_raw, str):
        parts = [part.strip() for part in attachments_raw.split(";") if part.strip()]
        attachments = parts
    else:
        attachments = [str(attachments_raw).strip()] if attachments_raw else []
    attachments = sorted(set(attachments))

    url_list = sorted({u.strip() for u in url_strings if u and u.strip()})

    body_text = parsed.get("body") or ""
    body_clean = body_text.strip()
    if len(body_clean) > _BODY_EXCERPT_LIMIT:
        truncated_len = len(body_clean) - _BODY_EXCERPT_LIMIT
        body_clean = (
            body_clean[:_BODY_EXCERPT_LIMIT]
            + f"... (truncated {truncated_len} chars)"
        )

    if not body_clean:
        body_clean = "[no body text provided]"

    body_hash = hashlib.sha256((parsed.get("body") or "").encode("utf-8")).hexdigest()

    flags: List[str] = []
    if attachments:
        flags.append("has_attachments")
    if url_list:
        flags.append("has_urls")
    if parsed.get("subject") and parsed["subject"].isupper():
        flags.append("subject_all_caps")
    if not (parsed.get("body") or "").strip():
        flags.append("empty_body")

    return {
        "id": email_id,
        "from": (parsed.get("from") or "").strip(),
        "subject": (parsed.get("subject") or "").strip(),
        "body_excerpt": body_clean,
        "body_length": len(parsed.get("body") or ""),
        "body_hash": body_hash,
        "attachments": attachments,
        "urls": url_list,
        "flags": flags,
    }


def analyze_payloads(api_key: str, model: str, payloads: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Run LLM analysis with caching and batching for the supplied payloads."""
    if not payloads:
        return {}
    if model not in SUPPORTED_LLM_MODELS:
        raise ValueError(f"Unsupported model: {model}")

    client = _get_client(api_key)

    results: Dict[str, Dict[str, Any]] = {}
    pending: List[Tuple[Dict[str, Any], str]] = []

    for payload in payloads:
        cache_key = _cache_key(model, payload)
        cached = _CACHE.get(cache_key)
        if cached is not None:
            results[payload["id"]] = dict(cached)
        else:
            pending.append((payload, cache_key))

    for chunk in _chunk(pending, _MAX_BATCH_SIZE):
        if not chunk:
            continue
        chunk_payloads = [item[0] for item in chunk]
        messages = _build_messages(chunk_payloads)
        raw_response = _call_llm(client, model, messages)
        response_obj = _parse_llm_json(raw_response)
        analyses = _coerce_analyses(response_obj)

        missing = [p["id"] for p in chunk_payloads if p["id"] not in analyses]
        if missing:
            raise ValueError(f"LLM response missing analyses for: {missing}")

        for payload, cache_key in chunk:
            analysis = _normalise_analysis(analyses[payload["id"]])
            _CACHE[cache_key] = dict(analysis)
            results[payload["id"]] = analysis

    return results


def _cache_key(model: str, payload: Dict[str, Any]) -> str:
    signature = {
        "model": model,
        "from": payload.get("from", ""),
        "subject": payload.get("subject", ""),
        "body_hash": payload.get("body_hash", ""),
        "attachments": payload.get("attachments", []),
        "urls": payload.get("urls", []),
    }
    encoded = json.dumps(signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _build_messages(payloads: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    emails_json = json.dumps(payloads, indent=2, ensure_ascii=True)
    user_content = (
        "Analyze each email object in the JSON array and detect phishing risks. "
        "For every `id`, respond with JSON matching this schema:\n"
        "{\n  \"analyses\": {\n    \"<id>\": {\n      \"probability\": <integer 0-100>,\n"
        "      \"indicators\": [\"indicator\"],\n      \"reasoning\": \"text\"\n    }\n  }\n}\n\n"
        "Probability is the likelihood that the email is phishing. "
        "Indicators must quote concrete evidence from the email. "
        "Return only valid JSON.\n\n"
        f"Emails:\n{emails_json}"
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def _call_llm(client: OpenAI, model: str, messages: List[Dict[str, str]]) -> str:
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0,
        top_p=0,
        max_tokens=800,
    )
    return response.choices[0].message.content or ""


def _strip_code_fence(text: str) -> str:
    value = text.strip()
    if not value.startswith("```"):
        return value
    # Remove the first fence
    value = value[3:]
    if value.startswith("json"):
        value = value[4:]
    end = value.rfind("```")
    if end != -1:
        value = value[:end]
    return value.strip()


def _extract_json_fragment(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object detected in LLM response")
    return text[start : end + 1]


def _parse_llm_json(raw_text: str) -> Dict[str, Any]:
    cleaned = _strip_code_fence(raw_text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        fragment = _extract_json_fragment(cleaned)
        return json.loads(fragment)


def _coerce_analyses(data: Dict[str, Any]) -> Dict[str, Any]:
    analyses = data.get("analyses")
    if analyses is None:
        raise ValueError("LLM response missing 'analyses' key")
    if isinstance(analyses, dict):
        return analyses
    if isinstance(analyses, list):
        result: Dict[str, Any] = {}
        for item in analyses:
            if isinstance(item, dict) and "id" in item:
                entry = dict(item)
                entry_id = str(entry.pop("id"))
                result[entry_id] = entry
        return result
    raise ValueError("Invalid 'analyses' structure in LLM response")


def _normalise_analysis(raw: Dict[str, Any]) -> Dict[str, Any]:
    prob_value = raw.get("probability", 0)
    if isinstance(prob_value, str):
        digits = "".join(ch for ch in prob_value if ch.isdigit())
        prob_value = int(digits) if digits else 0
    elif isinstance(prob_value, (int, float)):
        prob_value = int(round(float(prob_value)))
    else:
        prob_value = 0
    prob_value = max(0, min(100, prob_value))

    indicators_raw = raw.get("indicators")
    if isinstance(indicators_raw, str):
        indicators = [indicators_raw.strip()] if indicators_raw.strip() else []
    elif isinstance(indicators_raw, list):
        indicators = [str(item).strip() for item in indicators_raw if str(item).strip()]
    else:
        indicators = []

    reasoning = raw.get("reasoning", "")
    reasoning_str = str(reasoning).strip()

    return {
        "probability": prob_value,
        "indicators": indicators,
        "reasoning": reasoning_str,
    }


def _chunk(items: List[Tuple[Dict[str, Any], str]], size: int) -> List[List[Tuple[Dict[str, Any], str]]]:
    if size <= 0:
        size = 1
    return [items[i : i + size] for i in range(0, len(items), size)]
