import time
from typing import Dict, Any
from pathlib import Path
from dataclasses import asdict

from backend.core.score import analyze as analyze_core
from backend.ingestion.edit_distance import DETECTOR as EDIT_DISTANCE_DETECTOR
from backend.ingestion.parse_eml import (
    eml_to_parts,
    validate_email_message,
    get_message_text,
    get_message_html,
)
from backend.ingestion.sender_identity import SenderIdentityAnalyzer
from backend.ingestion.headers import HeaderNormalizer
from backend.ingestion.auth_parser import get_auth_data, get_raw_auth_headers
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

        # Get headers for analysis
        header_normalizer = HeaderNormalizer(message)
        headers = header_normalizer.get_all_headers()
        subject = message.get("Subject", "") or ""
        text_body = get_message_text(message)
        html_body = get_message_html(message)

        # Add sender identity analysis first (needed for scoring)
        sender_analyzer = SenderIdentityAnalyzer(message)
        sender_identity = sender_analyzer.analyze()

        # Perform core analysis with sender identity for confusable scoring
        result = analyze_core(headers, subject, text_body, html_body, sender_identity)

        # Add detailed keyword analysis
        from backend.core.keywords import analyze_keywords

        detailed_keyword_analysis = analyze_keywords(
            subject, text_body, use_positions=True
        )

        # Clean up the result - remove redundant fields from score.py analysis
        if "meta" in result:
            # Keep these from the meta section
            if "keywords" in result["meta"]:
                result["keywords"] = result["meta"]["keywords"]
            # Remove the entire meta block as requested
            del result["meta"]

        # Create key_headers structure
        key_headers = {
            "from": headers.get("From", ""),
            "to": headers.get("To", ""),
            "cc": headers.get("Cc", ""),
            "bcc": headers.get("Bcc", ""),
            "date": headers.get("Date", ""),
            "reply_to": headers.get("Reply-To", ""),
            "return_path": headers.get("Return-Path", ""),
            "message_id": headers.get("Message-ID", ""),
            "content_type": headers.get("Content-Type", ""),
        }
        result["key_headers"] = key_headers
        result["subject"] = subject

        # Add sender identity analysis (without auth duplication in it)
        # sender_identity is already created above for scoring
        # Remove auth data from sender_identity since it's handled separately
        if hasattr(sender_identity, "authentication_results"):
            sender_identity.authentication_results = {}
        result["sender_identity"] = asdict(sender_identity)

        # Add authentication data from auth parser
        auth_data = get_auth_data(headers)
        result["auth"] = auth_data

        # Add raw authentication headers for detailed analysis
        raw_auth_headers = get_raw_auth_headers(headers)
        result["raw_auth_headers"] = raw_auth_headers

        # Add subscription metadata
        subscription_metadata = header_normalizer.get_subscription_metadata()
        result["subscription"] = asdict(subscription_metadata)

        # Create domains list from all content
        from backend.core.score import extract_domains

        all_content = subject + "\n" + text_body + "\n" + html_body
        domains = list(extract_domains(all_content))
        result["domains"] = domains

        # Create HTML text (full extracted text)
        if html_body:
            from backend.ingestion.body_cleaner import strip_html_tags

            result["html_text"] = strip_html_tags(html_body)
        else:
            result["html_text"] = ""

        # Add parsed components from eml_to_parts
        result.update(parts)

        # Add explicit URL findings section from html_metrics
        if "html_metrics" in result:
            html_metrics = result["html_metrics"]
            if "url_findings" in html_metrics and html_metrics["url_findings"]:
                result["url_findings"] = html_metrics["url_findings"]

        # Add detailed keyword analysis results
        result["keyword_analysis"] = detailed_keyword_analysis

        # Add confusable findings summary for quick access
        confusable_findings = []
        if sender_identity.from_confusable_finding:
            confusable_findings.append(
                {
                    "type": "sender_from",
                    "domain": sender_identity.from_confusable_finding.domain,
                    "matched_brand": sender_identity.from_confusable_finding.matched_brand,
                    "skeleton_match": sender_identity.from_confusable_finding.skeleton_match,
                    "evidence": sender_identity.from_confusable_finding.evidence,
                }
            )
        if sender_identity.reply_to_confusable_finding:
            confusable_findings.append(
                {
                    "type": "sender_reply_to",
                    "domain": sender_identity.reply_to_confusable_finding.domain,
                    "matched_brand": sender_identity.reply_to_confusable_finding.matched_brand,
                    "skeleton_match": sender_identity.reply_to_confusable_finding.skeleton_match,
                    "evidence": sender_identity.reply_to_confusable_finding.evidence,
                }
            )
        if sender_identity.return_path_confusable_finding:
            confusable_findings.append(
                {
                    "type": "sender_return_path",
                    "domain": sender_identity.return_path_confusable_finding.domain,
                    "matched_brand": sender_identity.return_path_confusable_finding.matched_brand,
                    "skeleton_match": sender_identity.return_path_confusable_finding.skeleton_match,
                    "evidence": sender_identity.return_path_confusable_finding.evidence,
                }
            )
        result["confusable_findings"] = confusable_findings

        # Add edit-distance lookalike findings
        # Get recipient's organization domain from headers
        recipient_org = None
        to_header = headers.get("To", "").strip()
        if to_header and "@" in to_header:
            # Extract domain from the first recipient
            recipient_email = to_header.split(",")[0].strip()
            if "@" in recipient_email:
                recipient_org = recipient_email.split("@")[1].lower()

        # Analyze all domains for lookalikes
        all_domains_to_check = set()

        # Add sender domains
        if sender_identity.from_domain:
            all_domains_to_check.add(sender_identity.from_domain.lower())
        if sender_identity.reply_to_domain:
            all_domains_to_check.add(sender_identity.reply_to_domain.lower())
        if sender_identity.return_path_domain:
            all_domains_to_check.add(sender_identity.return_path_domain.lower())

        # Add domains from content
        for domain in domains:
            all_domains_to_check.add(domain.lower())

        # Perform lookalike detection
        lookalike_findings = EDIT_DISTANCE_DETECTOR.analyze_domains(
            list(all_domains_to_check), recipient_org=recipient_org
        )

        result["lookalike_domains"] = [
            asdict(finding) for finding in lookalike_findings
        ]

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
