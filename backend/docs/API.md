# API Usage

## API Testing with cURL

### Health Check
```bash
curl -s http://localhost:8000/api/py/health
```

### Analyze EML File
```bash
curl -F "file=@path/to/any.eml" http://localhost:8000/api/py/analyze/eml
```

**Response Format:**
```json
{
  "risk": 0.4,
  "label": "SAFE",
  "reasons": ["KEYWORDS"],
  "meta": {
    "keywords": [
      {
        "keyword": "urgent",
        "count": 2,
        "weight": 0.1
      }
    ],
    "headers": {
      "From": "...",
      "To": "...",
      "Subject": "..."
    },
    "subject": "..."
  }
}
```

## Response Fields

- **risk**: Float between 0.0 and 1.0 indicating phishing risk level
- **label**: Classification result ("SAFE", "PHISHING", or "UNSCORED")
- **reasons**: Array of strings indicating why the email was flagged
- **meta**: Additional analysis metadata including:
  - **keywords**: Array of detected suspicious keywords with counts and weights
  - **headers**: Parsed email headers
  - **subject**: Email subject line

## Scoring Logic

The system uses a combination of:
- **Keyword Analysis**: Detects suspicious words/phrases in subject and body
- **Domain Whitelisting**: Reduces risk score for emails from trusted domains
- **Threshold-based Classification**:
  - `risk = 0.0`: Label = "UNSCORED"
  - `risk < 1.0`: Label = "SAFE"
  - `risk >= 1.0`: Label = "PHISHING"

## Notes
- Only `.eml` files are supported
- The API validates that uploaded files contain valid email format (422 error for corrupted files)
- The API parses email headers, subject, and body content
- Risk scores are calculated based on keyword frequency and domain reputation
- Use `jq` for pretty-printing JSON responses
- The project uses FastAPI framework
- Virtual environment files (`.venv/`) are ignored by Git
- The API has a health check endpoint at `/api/py/health`
