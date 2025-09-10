import time
from typing import Dict, Any
from pathlib import Path
from dataclasses import asdict

from backend.core.score import analyze as analyze_core
from backend.ingestion.parse_eml import eml_to_parts, validate_email_message
from backend.ingestion.sender_identity import SenderIdentityAnalyzer
from dataclasses import asdict
from fastapi import UploadFile, FastAPI, File, HTTPException, Request
from fastapi.responses import JSONResponse
from email import policy
from email.parser import BytesParser

# Configuration
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB
ALLOWED_EXTENSIONS = {".eml"}

app = FastAPI(
    title="Phish Detector API",
    version="0.0.4",
    description="API for analyzing email files for phishing indicators",
    docs_url="/docs",
    openapi_url="/openapi.json",
)


def validate_file(file: UploadFile) -> None:
    """
    Validate uploaded file for size and extension.

    Args:
        file: The uploaded file to validate

    Raises:
        HTTPException: If validation fails
    """
    # Check file extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Only {', '.join(ALLOWED_EXTENSIONS)} files are supported",
        )


def validate_file_size(content: bytes) -> None:
    """
    Validate file size against maximum allowed size.

    Args:
        content: File content bytes

    Raises:
        HTTPException: If file is too large
    """
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB",
        )


@app.get("/health")
async def health() -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns:
        Health status
    """
    return {"status": "healthy", "timestamp": time.time(), "version": app.version}


@app.post("/analyze/eml")
async def analyze_eml(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    """
    Analyze an email file for phishing indicators.

    Args:
        request: FastAPI request object
        file: Uploaded .eml file

    Returns:
        Analysis results as JSON
    """
    start_time = time.time()

    try:
        # Validate file
        validate_file(file)

        # Read file content
        raw_content = await file.read()

        # Validate file size
        validate_file_size(raw_content)

        # Parse email
        parser = BytesParser(policy=policy.default)
        message = parser.parsebytes(raw_content)

        # Validate email structure
        if not validate_email_message(message):
            raise HTTPException(
                status_code=422, detail="Invalid or corrupted email format"
            )

        # Extract email components
        parts = eml_to_parts(message)

        # Perform analysis
        result = analyze_core(
            parts["headers"], parts["subject"], parts["body"], parts["html"]
        )

        # Add sender identity analysis
        sender_analyzer = SenderIdentityAnalyzer(message)
        sender_identity = sender_analyzer.analyze()
        result["sender_identity"] = asdict(sender_identity)

        # Add authentication data if available
        if "auth" in parts:
            result["auth"] = parts["auth"]

        # Add subscription metadata if available
        if "subscription" in parts:
            result["subscription"] = asdict(parts["subscription"])

        # Add MIME parts metadata
        if "mime_parts" in parts:
            result["mime_parts"] = parts["mime_parts"]

        # Add HTML metrics
        if "html_metrics" in parts:
            result["html_metrics"] = parts["html_metrics"]

        # Add text metrics
        if "text_metrics" in parts:
            result["text_metrics"] = parts["text_metrics"]

        # Add attachments (ensure it's always present)
        result["attachments"] = parts.get("attachments", [])

        # Add processing metadata
        processing_time = time.time() - start_time
        result["metadata"] = {
            "filename": file.filename,
            "file_size": len(raw_content),
            "processing_time": round(processing_time, 3),
            "api_version": app.version,
        }

        return JSONResponse(result)

    except HTTPException:
        raise
    except Exception as e:
        # Log the error (in a real app, you'd use proper logging)
        processing_time = time.time() - start_time
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed after {processing_time:.2f}s: {str(e)}",
        )
