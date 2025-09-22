import sys
import os
import tempfile

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
        label, score = score_email(headers, body_text, urls, attachments)
        return JSONResponse({"label": label, "score": score, "detection_method": "algorithmic"})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

@app.post("/analyze/ml")
async def analyze_ml(data: dict):
    parsed = data['parsed']
    ml_model = data.get('ml_model', 'default_ml')
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

        if ml_model == 'default_ml':
            label, score = score_email(headers, body_text, urls, attachments)  # Placeholder
        elif ml_model == 'custom_ml':
            label, score = score_email(headers, body_text, urls, attachments)  # Different logic here
        else:
            label, score = score_email(headers, body_text, urls, attachments)

        return JSONResponse({"label": label, "score": score, "detection_method": "ML", "ml_model": ml_model})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")

@app.post("/analyze/llm")
async def analyze_llm(data: dict):
    parsed = data['parsed']
    try:
        # Placeholder for LLM detection - using algorithmic for now
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
        label, score = score_email(headers, body_text, urls, attachments)  # Placeholder
        return JSONResponse({"label": label, "score": score, "detection_method": "LLM"})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")
