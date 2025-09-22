import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.url_checks import extract_urls
from backend.ingestion.parse_eml import parse_eml
from backend.core.scoring import score_email
from fastapi import UploadFile, FastAPI, File, HTTPException
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


@app.post("/analyze/parsed")
async def analyze_parsed(parsed_data: dict):
    parsed_data = parsed_data['parsed']
    try:
        headers = {
            'from': parsed_data.get('from', ''),
            'reply-to': parsed_data.get('reply-to', ''),
            'return-path': parsed_data.get('return-path', ''),
            'subject': parsed_data.get('subject', ''),
            'message-id': parsed_data.get('message_id', ''),
            'received': parsed_data.get('received', '')
        }

        body_text = parsed_data.get('body', '')
        urls = extract_urls(body_text)
        attachments = [parsed_data.get('attachments', '')]
        label, score = score_email(headers, body_text, urls, attachments)
        return JSONResponse({"label": label, "score": score})
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Analysis error: {e}")
