# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

- **Email Analysis**: Upload and analyze `.eml` files for phishing indicators
- **Keyword Detection**: Identifies suspicious keywords in email content
- **Domain Whitelisting**: Checks against known safe domains
- **Risk Scoring**: Provides risk scores and classification (SAFE/PHISHING/UNSCORED)
- **REST API**: FastAPI backend with comprehensive endpoints
- **Modern Frontend**: Next.js React application with TypeScript
- **Automated Testing**: Comprehensive test suite with pytest

## Project Structure

```
phishing-detect/
├── app/                    # Next.js frontend
├── backend/                # FastAPI backend
│   ├── api/               # API endpoints
│   ├── core/              # Core analysis logic
│   ├── docs/              # Documentation
│   ├── ingestion/         # Email parsing utilities
│   └── tests/             # Test suite
├── public/                # Static assets
└── requirements.txt       # Python dependencies
```

## Quick Start

### Prerequisites
- Node.js 18+ and npm
- Python 3.8+
- Git

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mengtechdigital/phishing-detect.git
   cd phishing-detect
   ```

2. **Set up the backend:**
   ```bash
   # Create virtual environment
   python -m venv .venv

   # Activate virtual environment
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Set up the frontend:**
   ```bash
   npm install
   ```

4. **Start the development servers:**

   **Backend (Terminal 1):**
   ```bash
   # Activate virtual environment first
   .venv\Scripts\activate  # Windows
   # or
   source .venv/bin/activate  # Linux/macOS

   # Start the server
   uvicorn backend.api.index:app --reload --port 8000
   ```

   **Frontend (Terminal 2):**
   ```bash
   npm run dev
   ```

5. **Access the application:**
   - Frontend: [http://localhost:3000](http://localhost:3000)
   - API Docs: [http://localhost:8000/api/py/docs](http://localhost:8000/api/py/docs)
   - API Health: [http://localhost:8000/api/py/health](http://localhost:8000/api/py/health)

## API Usage

### Analyze Email File
```bash
curl -F "file=@sample.eml" http://localhost:8000/api/py/analyze/eml
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
.venv\Scripts\activate  # Windows
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

The application is configured for deployment on Vercel with the backend API deployed separately.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License.
