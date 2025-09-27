import sys
import os
import tempfile
import html
import re
import json
import hashlib
import time
from openai import OpenAI
from dotenv import load_dotenv
from typing import Any, Dict, Tuple

# Load environment variables from .env.local or .env in project root
env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env.local")
load_dotenv(dotenv_path=env_path)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.url_checks import extract_urls
from backend.ingestion.parse_eml import parse_eml
from backend.core.scoring import score_email
from backend.core.ml import train_nb_complement, train_nb_multinomial, train_logistic_regression,train_decision_tree, predict_phishing, load_training_data, load_model, save_model
from fastapi import UploadFile, FastAPI, File, HTTPException, Body
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Phish Detector API",
    version="0.0.3",
    docs_url="/docs",
    openapi_url="/openapi.json",
)


def highlight_body(body_text, matched_keywords, suspicious_urls):
    """Highlight suspicious parts in the body with <mark> tags and tooltips."""
    highlighted = html.escape(body_text)
    # Highlight keywords
    for kw in matched_keywords:
        highlighted = re.sub(
            re.escape(kw),
            f'<mark title="Matched phishing keyword">\\0</mark>',
            highlighted,
            flags=re.IGNORECASE,
        )
    # Highlight suspicious URLs
    for entry in suspicious_urls:
        if isinstance(entry, dict):
            url_obj = entry.get('url')
            reasons = entry.get('reasons', [])
        elif isinstance(entry, (tuple, list)) and len(entry) >= 2:
            url_obj, reasons = entry[0], entry[1]
        else:
            continue
        if not url_obj:
            continue
        url_str = url_obj.geturl()
        reason_str = '; '.join(str(reason) for reason in reasons if reason)
        escaped_url = html.escape(url_str)
        title_attr = html.escape(reason_str) if reason_str else 'Suspicious link'
        highlighted = highlighted.replace(
            escaped_url, f'<mark title="{title_attr}">{escaped_url}</mark>'
        )
    return highlighted



def _clone_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(payload))


SUPPORTED_LLM_MODELS = ("gpt-5-nano", "gpt-4.1-nano", "gpt-4o-mini")
DEFAULT_LLM_MODEL = SUPPORTED_LLM_MODELS[0]
LLM_CACHE_TTL_SECONDS = int(os.getenv("LLM_CACHE_TTL", "300"))
_LLM_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}


def _normalize_parsed_email(parsed: Dict[str, Any]) -> str:
    try:
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except TypeError:
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _hash_parsed_email(parsed: Dict[str, Any]) -> str:
    return hashlib.sha256(_normalize_parsed_email(parsed).encode("utf-8")).hexdigest()


def _cache_key(model: str, digest: str) -> Tuple[str, str]:
    return model, digest


def _get_cached_llm_payload(model: str, digest: str) -> Dict[str, Any] | None:
    entry = _LLM_CACHE.get(_cache_key(model, digest))
    if not entry:
        return None
    timestamp, payload = entry
    if time.monotonic() - timestamp <= LLM_CACHE_TTL_SECONDS:
        return _clone_payload(payload)
    _LLM_CACHE.pop(_cache_key(model, digest), None)
    return None


def _set_cached_llm_payload(model: str, digest: str, payload: Dict[str, Any]) -> None:
    _LLM_CACHE[_cache_key(model, digest)] = (time.monotonic(), _clone_payload(payload))


def _validate_llm_model(model: str) -> None:
    if model not in SUPPORTED_LLM_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported model: {model}. Supported: {list(SUPPORTED_LLM_MODELS)}",
        )


def _build_llm_prompt(
    email_from: str,
    email_subject: str,
    email_body: str,
    email_attachments: Any,
    email_urls: list,
) -> str:
    url_list = [url.geturl() for url in email_urls] or []
    lines = [
        "You are an expert at detecting phishing emails. Analyze the following email carefully and provide a detailed assessment focusing on specific phishing indicators.",
        "",
        "**Email Details:**",
        f"- From: {email_from}",
        f"- Subject: {email_subject}",
        f"- Body: {email_body}",
        f"- Attachments: {email_attachments}",
        f"- URLs found in body: {url_list}",
        "",
        "**Common phishing indicators to look for:**",
        "- Spoofed or suspicious sender information",
        "- Urgent or threatening language",
        "- Requests for personal/sensitive information",
        "- Suspicious URLs (phishing links, shortened URLs, etc.)",
        "- Mismatched or abnormal headers",
        "- Unexpected attachments",
        "- Poor grammar or unprofessional language",
        "- Generic greetings or personalization issues",
        "- Too-good-to-be-true offers or scams",
        "",
        "**Task:**",
        "Provide your analysis in the following JSON format only (no additional text):",
        "{",
        '  "probability": <integer 0-100, percentage likelihood this is phishing>,',
        '  "indicators": ["specific red flag 1", "specific red flag 2", ...],',
        '  "reasoning": "brief overall explanation"',
        "}",
        "",
        "Be precise and focus on concrete evidence from the email.",
    ]
    return "\n".join(lines)



def _call_llm_model(client: OpenAI, model: str, prompt: str) -> str:
    response = client.chat.completions.create(
        model=model, messages=[{"role": "system", "content": prompt}], stream=True
    )
    full_response = ""
    for chunk in response:
        if chunk.choices[0].delta.content:
            full_response += chunk.choices[0].delta.content
    return full_response


def _parse_llm_json(raw_response: str) -> Dict[str, Any]:
    try:
        return json.loads(raw_response.strip()) if raw_response.strip() else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422, detail=f"Failed to parse LLM response: {raw_response}"
        ) from exc


def _create_llm_payload(
    parsed: Dict[str, Any],
    model: str,
    llm_analysis: Dict[str, Any],
    email_body: str,
    email_urls: list,
) -> Dict[str, Any]:
    probability_raw = llm_analysis.get("probability", 0)
    try:
        probability = float(probability_raw)
    except (TypeError, ValueError):
        probability = 0.0
    label = "phishing" if probability > 50 else "safe"
    score = probability / 100.0

    indicators = llm_analysis.get("indicators", []) or []
    reasoning = llm_analysis.get("reasoning", "")

    explanations = []
    if isinstance(indicators, list):
        explanations.extend([f"Suspicious indicator: {ind}" for ind in indicators])
    if reasoning:
        explanations.append(f"LLM reasoning: {reasoning}")

    return {
        "label": label,
        "score": score,
        "explanations": explanations,
        "detection_method": "LLM",
        "llm_model": model,
    }


def _run_llm_analysis(parsed: Dict[str, Any], model: str) -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500, detail="OPENAI_API_KEY environment variable not set"
        )

    client = OpenAI(api_key=api_key)

    email_from = parsed.get("from", "")
    email_subject = parsed.get("subject", "")
    email_body = parsed.get("body", "")
    email_attachments = parsed.get("attachments", "")
    email_urls = extract_urls(email_body)

    prompt = _build_llm_prompt(
        email_from,
        email_subject,
        email_body,
        email_attachments,
        email_urls,
    )

    raw_response = _call_llm_model(client, model, prompt)
    llm_analysis = _parse_llm_json(raw_response)
    return _create_llm_payload(parsed, model, llm_analysis, email_body, email_urls)


def _get_or_create_llm_result(parsed: Dict[str, Any], model: str) -> Dict[str, Any]:
    digest = _hash_parsed_email(parsed)
    cached = _get_cached_llm_payload(model, digest)
    if cached:
        return cached
    payload = _run_llm_analysis(parsed, model)
    _set_cached_llm_payload(model, digest, payload)
    return payload


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/parse/eml")
async def parse_eml_endpoint(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    raw = await file.read()
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", delete=False, suffix=".eml"
        ) as tmp_file:
            tmp_file.write(raw)
            tmp_path = tmp_file.name

        parsed = parse_eml(tmp_path)
        os.unlink(tmp_path)
        return JSONResponse(parsed)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")


@app.post("/analyze/algorithmic")
async def analyze_algorithmic(data: dict):
    parsed = data["parsed"]
    try:
        headers = {
            "from": parsed.get("from", ""),
            "reply-to": parsed.get("reply-to", ""),
            "return-path": parsed.get("return-path", ""),
            "subject": parsed.get("subject", ""),
            "message-id": parsed.get("message_id", ""),
            "received": parsed.get("received", ""),
        }

        body_text = parsed.get("body", "")
        urls = extract_urls(body_text)
        attachments = [parsed.get("attachments", "")]
        label, score, explanations, matched_keywords, suspicious_urls = score_email(
            headers, body_text, urls, attachments
        )
        highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)
        return JSONResponse(
            {
                "label": label,
                "score": score,
                "explanations": explanations,
                "highlighted_body": highlighted_body,
                "detection_method": "algorithmic",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")


@app.post("/analyze/ml")
async def analyze_ml(data: dict):
    parsed = data["parsed"]
    ml_model = data.get("ml_model", "naivebayes_complement")
    try:
        body_text = parsed.get("body", "")
        headers = {
            "from": parsed.get("from", ""),
            "reply-to": parsed.get("reply-to", ""),
            "return-path": parsed.get("return-path", ""),
            "subject": parsed.get("subject", ""),
            "message-id": parsed.get("message_id", ""),
            "received": parsed.get("received", ""),
        }

        model = None
        model_name_map = {
            "naivebayes_complement": ("naivebayes_complement", train_nb_complement),
            "naivebayes_multinomial": ("naivebayes_multinomial", train_nb_multinomial),
            "logistic_regression": ("logistic_regression", train_logistic_regression),
            "decision_tree": ("decision_tree", train_decision_tree)
        }

        if ml_model in model_name_map:
            model_filename, train_func = model_name_map[ml_model]
            model = load_model(model_filename)
            if model is None:
                training_data = load_training_data()
                model = train_func(training_data)
                save_model(model, model_filename)
        else:
            raise HTTPException(status_code=400, detail="Invalid ML model specified")

        mlguess = predict_phishing(body_text, model)

        urls = extract_urls(body_text)
        attachments_value = parsed.get("attachments", "")
        if isinstance(attachments_value, (list, tuple)):
            attachments = list(attachments_value)
        elif attachments_value:
            attachments = [attachments_value]
        else:
            attachments = []

        heur_label, heur_score, heur_explanations, matched_keywords, suspicious_urls = score_email(
            headers, body_text, urls, attachments
        )
        explanations = list(heur_explanations) if heur_explanations else [
            f"Heuristic cross-check score {heur_score} ({heur_label})."
        ]
        highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)

        return JSONResponse(
            {
                "label": mlguess["label"],
                "score": mlguess["percent"],
                "explanations": explanations,
                "highlighted_body": highlighted_body,
                "detection_method": "ML",
                "ml_model": ml_model,
                "heuristic_label": heur_label,
                "heuristic_score": heur_score,
            }
        )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")


@app.post("/analyze/llm")
async def analyze_llm(data: dict):
    parsed = data["parsed"]
    model = data.get("model", DEFAULT_LLM_MODEL)
    _validate_llm_model(model)

    try:
        payload = _get_or_create_llm_result(parsed, model)
        return JSONResponse(payload)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"LLM analysis error: {e}")


@app.post("/analyze/llm/batch")
async def analyze_llm_batch(data: dict):
    items = data.get("items")
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail="`items` must be a non-empty list")

    default_model = data.get("model", DEFAULT_LLM_MODEL)
    _validate_llm_model(default_model)

    results = []
    try:
        for item in items:
            if not isinstance(item, dict):
                raise HTTPException(status_code=422, detail="Each batch item must be a dict")
            parsed = item.get("parsed")
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=422, detail="Each item must include a 'parsed' payload")
            model = item.get("model", default_model)
            _validate_llm_model(model)
            results.append(_get_or_create_llm_result(parsed, model))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"LLM batch analysis error: {e}")

    return JSONResponse({"results": results})


