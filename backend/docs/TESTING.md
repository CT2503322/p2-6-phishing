# Testing

The project includes automated tests for the API endpoints using pytest.

## Run Tests
```bash
# Activate virtual environment (if not already activated)
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/macOS

# Run all tests
python -m pytest backend/tests/ -v

# Or run specific test file
python -m pytest backend/tests/test_api.py -v
python -m pytest backend/tests/test_core.py -v
python -m pytest backend/tests/test_ingestion.py -v
```

**Note:** Tests should be run from the project root directory (`phishing-detect/`) to ensure proper module imports.

## Test Coverage
The test suite includes:

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

### Ingestion Tests (`test_ingestion.py`)
- EML file parsing and validation
- Email message structure handling
- Header extraction
- Content type detection

Tests use sample files from `tests/samples/` directory and run without requiring a live server.

## Manual Testing with cURL

After starting the server, you can manually test the API endpoints:

### Health Check (200 OK)
```bash
curl -s http://127.0.0.1:8000/api/py/health
```

### Valid EML File (200 OK)
```bash
curl -s -F "file=@backend/tests/samples/tada.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

### Corrupted EML File (422 Unprocessable Entity)
```bash
curl -s -F "file=@backend/tests/samples/tada-corrupted.eml" http://127.0.0.1:8000/api/py/analyze/eml
```

### Invalid File Type (400 Bad Request)
```bash
curl -s -F "file=@backend/tests/samples/tada.pdf" http://127.0.0.1:8000/api/py/analyze/eml
```