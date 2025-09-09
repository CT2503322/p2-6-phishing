# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

- **Email Analysis**: Upload and analyze `.eml` files for phishing indicators
- **Keyword Detection**: Identifies suspicious keywords in email content
- **Domain Whitelisting**: Checks against known safe domains
- **Risk Scoring**: Provides risk scores and classification (SAFE/PHISHING/UNSCORED)
- **REST API**: FastAPI backend with comprehensive endpoints
- **Modern Frontend**: Streamlit web application for easy email analysis
- **Automated Testing**: Comprehensive test suite with pytest

## Project Structure

```
p2-6-phishing/
├── main.py                # Streamlit application entry point
├── ui/                    # Streamlit frontend (modular)
│   ├── app.py            # Main application logic
│   ├── api/              # API client functions
│   │   └── client.py
│   ├── components/       # Reusable UI components
│   │   ├── file_uploader.py
│   │   └── analysis_results.py
│   └── utils/            # Utility functions
│       └── helpers.py
├── backend/               # FastAPI backend
│   ├── api/               # API endpoints
│   ├── core/              # Core analysis logic
│   ├── docs/              # Documentation
│   ├── ingestion/         # Email parsing utilities
│   └── tests/             # Test suite
├── requirements.txt       # Python dependencies
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
