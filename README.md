# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

- **Email Analysis**: Upload and analyze `.eml` files with comprehensive phishing detection
- **Multi-layered Detection**: Keyword detection, domain whitelisting, MIME parsing, authentication checks
- **HTML and Attachment Processing**: Handles complex email structures including HTML content and attachments
- **Sender Identity Analysis**: Validates sender information and email headers
- **Comprehensive Metrics**: Detailed analysis metrics and scoring algorithms
- **REST API**: FastAPI backend with `/health` and `/analyze/eml` endpoints
- **Modern Frontend**: Streamlit web application with multiple UI components for easy analysis
- **Advanced Detection Features**: Position-aware analysis, edit distance lookalike detection, and comprehensive attachment security scanning
- **Automated Testing**: Extensive test suite with 200+ test cases, pytest, fixtures, and integration testing

See [TODO.md](TODO.md) for detailed development roadmap.

## Project Structure

```
p2-6-phishing/
├── app.py                 # Main Streamlit application logic
├── main.py                # Streamlit application launcher
├── backend/               # FastAPI backend
│   ├── api/               # API endpoints
│   │   └── index.py       # Main API router with /health and /analyze/eml
│   ├── core/              # Core analysis logic
│   │   ├── keywords.py    # Keyword detection
│   │   ├── score.py       # Analysis logic
│   │   └── whitelist.py   # Domain whitelisting
│   ├── data/              # Data files
│   │   └── whitelist.txt  # Whitelisted domains
│   ├── docs/              # Documentation
│   │   ├── API.md         # API documentation
│   │   ├── SETUP.md       # Setup guide
│   │   └── TESTING.md     # Testing guide
│   ├── ingestion/         # Email parsing utilities
│   │   ├── __init__.py    # Package initialization
│   │   ├── addresses.py   # Address processing
│   │   ├── auth_parser.py # Authentication header parsing
│   │   ├── body_cleaner.py # Email body cleaning
│   │   ├── error_policy.py # Error handling policies
│   │   ├── headers.py     # Header processing utilities
│   │   ├── metrics.py     # Analysis metrics calculation
│   │   ├── mime.py        # MIME type handling
│   │   ├── models.py      # Data models for email processing
│   │   ├── parse_eml.py   # EML file parsing
│   │   ├── sender_identity.py # Sender identity analysis
│   │   ├── attachment_analysis.py # Advanced attachment analysis with security scanning
│   │   ├── position.py    # Position-based keyword weighting (NEW)
│   │   ├── edit_distance.py # Fuzzy domain matching and lookalike detection (NEW)
│   │   └── confusable.py  # Unicode confusable character analysis
│   ├── tests/             # Comprehensive test suite
│   │   ├── __init__.py
│   │   ├── fixtures/      # Test fixture files
│   │   │   ├── alt.eml
│   │   │   ├── attachment_pdf.eml
│   │   │   ├── auth_headers.eml
│   │   │   ├── broken_headers.eml
│   │   │   ├── html.eml
│   │   │   ├── plain.eml
│   │   │   ├── related_cid.eml
│   │   │   ├── tada-corrupted.eml
│   │   │   ├── tada.eml
│   │   │   └── tada.pdf
│   │   ├── test_addresses.py
│   │   ├── test_api.py
│   │   ├── test_attachments.py
│   │   ├── test_auth_parser.py
│   │   ├── test_body_cleaner.py
│   │   ├── test_body.py
│   │   ├── test_cid.py
│   │   ├── test_core.py
│   │   ├── test_fixtures.py
│   │   ├── test_headers.py
│   │   ├── test_inline_images.py
│   │   ├── test_mime_metrics.py
│   │   ├── test_reader.py
│   │   ├── test_sender_identity_integration.py
│   │   └── test_sender_identity.py
├── backend/
│   └── eml_extractor.py   # Email extraction utilities
├── frontend/
│   └── ui/                # Streamlit frontend components
│       ├── __init__.py
│       ├── analysis_results.py
│       ├── api_client.py
│       ├── components.py
│       ├── config.py
│       ├── email_display.py
│       ├── file_uploader.py
│       ├── file_validator.py
│       └── sidebar.py
├── .gitignore             # Git ignore rules
├── requirements.txt       # Python dependencies
├── TODO.md                # Development roadmap
└── README.md              # This file
```

## Quick Start

### Prerequisites

- Python 3.8+
- Git

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/CT2503322/p2-6-phishing.git
   cd p2-6-phishing
   ```

2. **Set up the backend:**

   ```bash
   # Create virtual environment
   python -m venv .venv

   # Activate virtual environment
   # Windows (Command Prompt):
   .venv\Scripts\activate
   # Windows (Git Bash):
   source .venv/Scripts/activate
   # Linux/macOS:
   source .venv/bin/activate

   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Start the development servers:**

   **Backend (Terminal 1):**

   ```bash
   # Activate virtual environment first
   .venv\Scripts\activate  # Windows (Command Prompt)
   # or
   source .venv/Scripts/activate  # Windows (Git Bash)
   # or
   source .venv/bin/activate  # Linux/macOS

   # Start the server
   uvicorn backend.api.index:app --reload --port 8000
   ```

   **Frontend (Terminal 2):**

   ```bash
   # Activate virtual environment first
   .venv\Scripts\activate  # Windows (Command Prompt)
   # or
   source .venv/Scripts/activate  # Windows (Git Bash)
   # or
   source .venv/bin/activate  # Linux/macOS

   # Start the Streamlit app
   streamlit run main.py
   ```

4. **Access the application:**
   - Frontend: [http://localhost:8501](http://localhost:8501)
   - API Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - API Health: [http://localhost:8000/health](http://localhost:8000/health)

## Available Scripts

To maintain code quality, you can use the following commands:

- **Run tests**: `python -m pytest backend/tests/ -v`
- **Start backend**: `uvicorn backend.api.index:app --reload --port 8000`
- **Start frontend**: `streamlit run main.py`

## API Usage

### Analyze Email File

```bash
curl -F "file=@sample.eml" http://localhost:8000/analyze/eml
```

**Response:**

```json
{
  "reasons": ["KEYWORDS"],
  "meta": {
    "keywords": [...],
    "headers": {...},
    "subject": "...",
    "domains": [...],
    "whitelisted_domains": [...]
  }
}
```

## Testing

Run the test suite:

```bash
# Activate virtual environment
.venv\Scripts\activate  # Windows (Command Prompt)
# or
source .venv/Scripts/activate  # Windows (Git Bash)
# or
source .venv/bin/activate  # Linux/macOS

# Run all tests
python -m pytest backend/tests/ -v
```

The test suite includes sample `.eml` files in `backend/tests/fixtures/` for testing various scenarios including corrupted emails and different file formats.

## Documentation

- [API Documentation](backend/docs/API.md)
- [Setup Guide](backend/docs/SETUP.md)
- [Testing Guide](backend/docs/TESTING.md)

## Deployment

The Streamlit frontend can be deployed on platforms like Streamlit Cloud, Heroku, or AWS. The FastAPI backend can be deployed separately on cloud platforms supporting Python applications.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License.
