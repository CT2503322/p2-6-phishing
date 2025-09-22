import sys
import os
import tempfile
import html
import re
import json
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env.local or .env in project root
env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env.local")
load_dotenv(dotenv_path=env_path)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.url_checks import extract_urls
from backend.ingestion.parse_eml import parse_eml
from backend.core.scoring import score_email
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
        highlighted = re.sub(re.escape(kw), f'<mark title="Matched phishing keyword">\\0</mark>', highlighted, flags=re.IGNORECASE)
    # Highlight suspicious URLs
    for u, reasons in suspicious_urls:
        url_str = u.geturl()
        reason_str = "; ".join(reasons)
        escaped_url = html.escape(url_str)
        highlighted = highlighted.replace(escaped_url, f'<mark title="{reason_str}">{escaped_url}</mark>')
    return highlighted


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/parse/eml")
async def parse_eml_endpoint(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    raw = await file.read()
    try:
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.eml') as tmp_file:
            tmp_file.write(raw)
            tmp_path = tmp_file.name

        parsed = parse_eml(tmp_path)
        os.unlink(tmp_path)
        return JSONResponse(parsed)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")


@app.post("/analyze/algorithmic")
async def analyze_algorithmic(data: dict):
    parsed = data['parsed']
    try:
        headers = {
            'from': parsed.get('from', ''),
            'reply-to': parsed.get('reply-to', ''),
            'return-path': parsed.get('return-path', ''),
            'subject': parsed.get('subject', ''),
            'message-id': parsed.get('message_id', ''),
            'received': parsed.get('received', '')
        }

        body_text = parsed.get('body', '')
        urls = extract_urls(body_text)
        attachments = [parsed.get('attachments', '')]
        label, score, explanations, matched_keywords, suspicious_urls = score_email(headers, body_text, urls, attachments)
        highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)
        return JSONResponse({"label": label, "score": score, "explanations": explanations, "highlighted_body": highlighted_body, "detection_method": "algorithmic"})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

@app.post("/analyze/ml")
async def analyze_ml(data: dict):
    parsed = data['parsed']
    ml_model = data['ml_model']
    try:
        # Placeholder for ML detection - using algorithmic for now
        headers = {
            'from': parsed.get('from', ''),
            'reply-to': parsed.get('reply-to', ''),
            'return-path': parsed.get('return-path', ''),
            'subject': parsed.get('subject', ''),
            'message-id': parsed.get('message_id', ''),
            'received': parsed.get('received', '')
        }

        body_text = parsed.get('body', '')
        urls = extract_urls(body_text)
        attachments = [parsed.get('attachments', '')]

        if ml_model == 'default_ml': # Placeholder
            label, score, explanations, matched_keywords, suspicious_urls = score_email(headers, body_text, urls, attachments)
            highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)
        elif ml_model == 'custom_ml': # Different logic here
            label, score, explanations, matched_keywords, suspicious_urls = score_email(headers, body_text, urls, attachments)
            highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)
        else:
            label, score, explanations, matched_keywords, suspicious_urls = score_email(headers, body_text, urls, attachments)
            highlighted_body = highlight_body(body_text, matched_keywords, suspicious_urls)

        return JSONResponse({"label": label, "score": score, "explanations": explanations, "highlighted_body": highlighted_body, "detection_method": "ML", "ml_model": ml_model})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

@app.post("/analyze/llm")
async def analyze_llm(data: dict):
    parsed = data['parsed']
    model = data.get('model', 'gpt-3.5-turbo')
    supported_models = ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-turbo']
    if model not in supported_models:
        raise HTTPException(status_code=400, detail=f"Unsupported model: {model}. Supported: {supported_models}")

    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY environment variable not set")

    try:
        client = OpenAI(api_key=api_key)

        # Extract email details
        email_from = parsed.get('from', '')
        email_subject = parsed.get('subject', '')
        email_body = parsed.get('body', '')
        email_attachments = parsed.get('attachments', '')
        email_urls = extract_urls(email_body)

        # Craft prompt for phishing analysis
        prompt = f"""You are an expert at detecting phishing emails. Analyze the following email carefully and provide a detailed assessment focusing on specific phishing indicators.

**Email Details:**
- From: {email_from}
- Subject: {email_subject}
- Body: {email_body}
- Attachments: {email_attachments}
- URLs found in body: {[url.geturl() for url in email_urls] or []}

**Common phishing indicators to look for:**
- Spoofed or suspicious sender information
- Urgent or threatening language
- Requests for personal/sensitive information
- Suspicious URLs (phishing links, shortened URLs, etc.)
- Mismatched or abnormal headers
- Unexpected attachments
- Poor grammar or unprofessional language
- Generic greetings or personalization issues
- Too-good-to-be-true offers or scams

**Task:**
Provide your analysis in the following JSON format only (no additional text):
{{
  "probability": <integer 0-100, percentage likelihood this is phishing>,
  "indicators": ["specific red flag 1", "specific red flag 2", ...],
  "reasoning": "brief overall explanation"
}}

Be precise and focus on concrete evidence from the email."""

        # Call OpenAI API with streaming
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": prompt}],
            stream=True
        )

        # Collect streaming response
        full_response = ""
        for chunk in response:
            if chunk.choices[0].delta.content:
                full_response += chunk.choices[0].delta.content

        # Parse the JSON response
        try:
            llm_analysis = json.loads(full_response.strip())
            probability = llm_analysis.get('probability', 0)
            indicators = llm_analysis.get('indicators', [])
            reasoning = llm_analysis.get('reasoning', '')
        except json.JSONDecodeError:
            raise HTTPException(status_code=422, detail=f"Failed to parse LLM response: {full_response}")

        # Determine label based on probability
        label = "phishing" if probability > 50 else "safe"
        score = probability / 100.0  # Convert to 0-1 for consistency with other endpoints

        # Create explanations combining indicators and reasoning
        explanations = []
        if indicators:
            explanations.extend([f"Suspicious indicator: {ind}" for ind in indicators])
        if reasoning:
            explanations.append(f"LLM reasoning: {reasoning}")

        # Extract suspicious elements for highlighting
        matched_keywords = []
        suspicious_urls = []

        # Find keywords from indicators that appear in body
        body_lower = email_body.lower()
        for ind in indicators:
            possible_keywords = re.findall(r'\b[^\s]+\b', ind.lower())
            for kw in possible_keywords:
                if kw in body_lower:
                    matched_keywords.append(kw)

        # Find suspicious URLs mentioned in indicators
        for ind in indicators:
            for url in email_urls:
                url_str = url.geturl()
                if url_str.lower() in ind.lower():
                    suspicious_urls.append((url, [f"LLM-detected: {ind}"]))

        return JSONResponse({
            "label": label,
            "score": score,
            "explanations": explanations,
            "detection_method": "LLM",
            "llm_model": model
        })

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"LLM analysis error: {e}")
