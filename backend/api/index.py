import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.score import analyze as analyze_core
from backend.ingestion.parse_eml import parse_eml
from fastapi import UploadFile, FastAPI, File, HTTPException
from fastapi.responses import JSONResponse
from email import policy
from email.parser import BytesParser

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


@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    raw = await file.read()
    try:
        with tempfile.NamedTemporaryFile(mode='w+b', delete=False, suffix='.eml') as tmp_file:
            tmp_file.write(raw)
            tmp_path = tmp_file.name

        parsed = parse_eml(tmp_path)
        os.unlink(tmp_path)
        headers = {
            'from': parsed['from'],
            'to': parsed['to'],
            'cc': parsed['cc'],
            'bcc': parsed['bcc'],
            'subject': parsed['subject'],
            'date': parsed['date'],
            'reply_to': parsed['reply_to'],
            'return_path': parsed['return_path'],
            'message_id': parsed['message_id'],
            'mime_version': parsed['mime_version'],
            'content_type': parsed['content_type'],
            'content_transfer_encoding': parsed['content_transfer_encoding']
        }
        subject = parsed['subject']
        body = parsed['body']
        html = ''
        result = analyze_core(headers, subject, body, html)
        return JSONResponse(result)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")
