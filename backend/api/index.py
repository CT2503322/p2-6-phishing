import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.core.score import analyze as analyze_core
from fastapi import UploadFile, FastAPI, File, HTTPException
from fastapi.responses import JSONResponse
from email import policy
from email.parser import BytesParser

app = FastAPI(
    title="Phish Detector API",
    version="0.0.3",
    docs_url="/api/py/docs",
    openapi_url="/api/py/openapi.json",
)


@app.get("/api/py/health")
def health():
    return {"ok": True}


@app.post("/api/py/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")
    raw = await file.read()
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        from backend.ingestion.parse_eml import eml_to_parts, validate_email_message

        # Validate that the parsed message is actually a valid email
        if not validate_email_message(message):
            raise HTTPException(
                status_code=422, detail="Invalid or corrupted email format"
            )

        parts = eml_to_parts(message)
        result = analyze_core(
            parts["headers"], parts["subject"], parts["body"], parts["html"]
        )
        return JSONResponse(result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")
