# Testing

The project includes automated tests for the API endpoints using pytest.

## Run Tests

```bash
# Activate virtual environment (if not already activated)
.venv\Scripts\activate  # Windows (Command Prompt)
# or
source .venv/Scripts/activate  # Windows (Git Bash)
# or
source .venv/bin/activate  # Linux/macOS

# Run all tests
python -m pytest backend/tests/ -v

# Or run specific test files
python -m pytest backend/tests/test_api.py -v
python -m pytest backend/tests/test_core.py -v
python -m pytest backend/tests/test_addresses.py -v
python -m pytest backend/tests/test_auth_parser.py -v
python -m pytest backend/tests/test_attachments.py -v
python -m pytest backend/tests/test_body_cleaner.py -v
python -m pytest backend/tests/test_headers.py -v
python -m pytest backend/tests/test_sender_identity.py -v
```

**Note:** Tests should be run from the project root directory (`p2-6-phishing/`) to ensure proper module imports.

## Test Coverage

The comprehensive test suite includes:

### API Tests (`test_api.py`)

- Health endpoint verification
- Valid .eml file analysis
- Corrupted .eml file error handling
- Invalid file format rejection (.pdf files)
- HTTP status code validation
- Response content validation

### Core Tests (`test_core.py`)

- Keyword detection functionality
- Domain normalization and whitelist checking
- Risk score calculation
- Email analysis pipeline

### Authentication Tests (`test_auth_parser.py`)

- Authentication header parsing
- SPF, DKIM, and DMARC header validation
- Authentication result interpretation

### Address Tests (`test_addresses.py`)

- Email address parsing and validation
- Address format verification
- Local and domain part processing

### Attachment Tests (`test_attachments.py`)

- Email attachment detection
- Attachment format validation
- Security checks for suspicious attachments

### Body Processing Tests (`test_body_cleaner.py`, `test_body.py`)

- Email body content cleaning
- Body text extraction and normalization
- Content processing and sanitization

### Header Tests (`test_headers.py`)

- Email header parsing
- Header validation and normalization
- Header field extraction

### Sender Identity Tests (`test_sender_identity.py`, `test_sender_identity_integration.py`)

- Sender identity verification
- From/Reply-To header consistency checks
- Identity authentication validation

### MIME Processing Tests (`test_mime_metrics.py`)

- MIME structure parsing
- MIME type detection
- Multipart content handling

### Content ID Tests (`test_cid.py`)

- Content-ID processing
- Embedded content handling
- CID-based content references

### Inline Image Tests (`test_inline_images.py`)

- Inline image parsing
- Image content extraction
- Embedded image processing

### Test Utilities (`test_fixtures.py`, `test_reader.py`)

- Test fixture management
- Email reader functionality
- Sample data handling

Tests use sample files from `backend/tests/fixtures/` directory and run without requiring a live server.

## Manual Testing with cURL

After starting the server, you can manually test the API endpoints:

### Health Check (200 OK)

```bash
curl -s http://127.0.0.1:8000/api/py/health
```

**Response:**

```json
{"detail":"Healthy"}
```

### Valid EML File (200 OK)

```bash
curl -s -F "file=@backend/tests/fixtures/tada.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

**Response:**

```json
{
  "label": "SAFE",
  "meta": {...},
  "reasons": [],
  "risk": 0.0
}
```

### Corrupted EML File (422 Unprocessable Entity)

```bash
curl -s -F "file=@backend/tests/fixtures/tada-corrupted.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

**Response:**

```json
{
  "detail": "Invalid email format: Error reading email"
}
```

### Invalid File Type (400 Bad Request)

```bash
curl -s -F "file=@backend/tests/fixtures/tada.pdf" http://127.0.0.1:8000/api/py/analyze/eml
```

**Response:**

```json
{
  "detail": "Invalid file type. Only .eml files are allowed."
}
``````

### Authenticated Headers File

```bash
curl -s -F "file=@backend/tests/fixtures/auth_headers.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

### HTML Content File

```bash
curl -s -F "file=@backend/tests/fixtures/html.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

### Attachment File

```bash
curl -s -F "file=@backend/tests/fixtures/attachment_pdf.eml" http://127.0.0.1:8000/api/py/analyze/eml
```
