# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

- **Email Analysis**: Upload and analyze `.eml` files for phishing indicators
- **Keyword Detection**: Identifies suspicious keywords in email content
- **Domain Whitelisting**: Checks against known safe domains
- **Risk Scoring**: Provides risk scores and classification (SAFE/PHISHING/UNSCORED)
- **REST API**: FastAPI backend with `/health` and `/analyze/eml` endpoints
- **Modern Frontend**: Streamlit web application for easy email analysis
- **Automated Testing**: Comprehensive test suite with pytest and sample files

See [TODO.md](TODO.md) for detailed development roadmap.

## Project Structure

```
p2-6-phishing/
├── main.py                # Streamlit application launcher
├── app.py                 # Main Streamlit application logic
├── backend/               # FastAPI backend
│   ├── api/               # API endpoints
│   │   └── index.py       # Main API router with /health and /analyze/eml
│   ├── core/              # Core analysis logic
│   │   ├── keywords.py    # Keyword detection
│   │   ├── score.py       # Risk scoring algorithm
│   │   └── whitelist.py   # Domain whitelisting
│   ├── data/              # Data files
│   │   └── whitelist.txt  # Whitelisted domains
│   ├── docs/              # Documentation
│   │   ├── API.md         # API documentation
│   │   ├── SETUP.md       # Setup guide
│   │   └── TESTING.md     # Testing guide
│   ├── ingestion/         # Email parsing utilities
│   │   └── parse_eml.py   # EML file parsing
│   └── tests/             # Test suite
│       ├── test_api.py    # API tests
│       ├── test_core.py   # Core logic tests
│       ├── test_ingestion.py # Ingestion tests
│       └── samples/       # Test sample files
│           ├── tada.eml    # Sample email
│           ├── tada-corrupted.eml # Corrupted email sample
│           └── tada.pdf    # Sample PDF
├── legacy/                # Legacy repositories
│   ├── old-busyclasher-repo/ # Previous version
│   └── old-p2-6-phishing-repo/ # Original version
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
  "risk": 0.4,
  "label": "SAFE",
  "reasons": ["KEYWORDS"],
  "meta": {
    "keywords": [...],
    "headers": {...},
    "subject": "..."
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

The test suite includes sample `.eml` files in `backend/tests/samples/` for testing various scenarios including corrupted emails and different file formats.

## Development Status

This project is actively developed with a focus on expanding phishing detection capabilities. The current implementation provides a solid foundation with core analysis features, while the roadmap includes advanced security checks and performance optimizations.

### Legacy Code
The `legacy/` directory contains previous versions of the project:
- `old-busyclasher-repo/`: Earlier iteration with different architecture
- `old-p2-6-phishing-repo/`: Original implementation

These are preserved for reference but are not actively maintained.

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
