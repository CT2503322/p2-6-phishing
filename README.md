# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

- **Multi-Method Detection**: Supports algorithmic (rule-based), machine learning, and LLM-based phishing detection
- **Email Analysis**: Upload and analyze `.eml` files or input email text for phishing indicators
- **Advanced Checks**: Keyword detection, domain whitelisting, URL analysis, attachment heuristics, identity verification, lexical scoring, and routing validation
- **Machine Learning**: Pre-trained models (Naive Bayes Complement/Multinomial, Logistic Regression) for statistical content-based classification using labeled email datasets
- **LLM Analysis**: Integration with OpenAI GPT models for intelligent phishing detection using advanced natural language processing and contextual understanding
- **Risk Scoring**: Provides risk scores and classification (SAFE/PHISHING/UNSCORED)
- **REST API**: FastAPI backend with `/health`, `/parse/eml`, `/analyze/algorithmic`, `/analyze/ml`, and `/analyze/llm` endpoints
- **Modern Frontend**: Streamlit web application with detection method selection for easy email analysis
- **Automated Testing**: Comprehensive test suite with pytest and sample files

See [TODO.md](TODO.md) for detailed development roadmap.

## Project Structure

```
p2-6-phishing/
├── main.py                # Streamlit application launcher
├── app.py                 # Main Streamlit application logic with detection method selection
├── .env.local.example     # Environment variables example file
├── backend/               # FastAPI backend
│   ├── api/               # API endpoints
│   │   └── index.py       # Main API router with /health, /parse/eml, analyze endpoints
│   ├── core/              # Core analysis logic modules
│   │   ├── attachment_checks.py    # Attachment heuristic validation
│   │   ├── helpers.py              # Utility functions
│   │   ├── identity_checks.py      # Sender identity verification
│   │   ├── lexical_score.py        # Lexical analysis scoring
│   │   ├── ml.py                   # Machine learning utilities and training
│   │   ├── routing_checks.py       # Email routing validation
│   │   ├── scoring.py              # Combined risk scoring algorithm
│   │   └── url_checks.py           # URL analysis and validation
│   │   └── models/                 # Directory for model artifacts (empty in repo)
│   ├── data/               # Data files and datasets
│   │   ├── whitelist.txt           # Whitelisted domains
│   │   └── combinedlabelled/       # Labeled email dataset for ML training
│   │       ├── ham/                # Ham (safe) email samples
│   │       └── spam/               # Spam (phishing) email samples
│   │       └── README.txt          # Dataset documentation
│   ├── docs/               # Documentation
│   │   ├── API.md          # API documentation
│   │   ├── SETUP.md        # Setup guide
│   │   └── TESTING.md      # Testing guide
│   ├── ingestion/          # Email parsing and cleaning utilities
│   │   ├── clean_html.py           # HTML content cleaning
│   │   ├── clean_zerowidth.py      # Zero-width character removal
│   │   └── parse_eml.py           # EML file parsing
│   ├── models/             # Pre-trained ML models (pickled)
│   │   ├── logistic_regression.pkl
│   │   ├── naivebayes_complement.pkl
│   │   └── naivebayes_multinomial.pkl
│   └── tests/              # Test suite
│       ├── test_api.py     # API integration tests
│       ├── test_core.py    # Core logic unit tests
│       ├── test_ingestion.py       # Ingestion pipeline tests
│       └── fixtures/               # Test fixture files
│           ├── tada.eml             # Sample email file
│           ├── tada-corrupted.eml   # Corrupted email sample
│           └── tada.pdf             # Sample PDF attachment
├── .gitignore             # Git ignore rules
├── requirements.txt       # Python dependencies
├── TODO.md                # Development roadmap
└── README.md              # This file
```

## Quick Start

### Prerequisites

- Python 3.13+
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

### Environment Variables

Create a `.env.local` file in the project root and add the following variables (required for LLM detection):

```
OPENAI_API_KEY=your_openai_api_key_here
```

## API Usage

The API supports multiple detection methods. First, parse an email file, then analyze it using your preferred method.

### Parse Email File

```bash
curl -X POST -F "file=@sample.eml" http://localhost:8000/parse/eml
```

### Analyze Algorithmic (Rule-based Detection)

```bash
curl -X POST http://localhost:8000/analyze/algorithmic \
  -H "Content-Type: application/json" \
  -d @parsed_email.json
```

### Analyze Machine Learning

```bash
curl -X POST http://localhost:8000/analyze/ml \
  -H "Content-Type: application/json" \
  -d '{"parsed": {...}, "ml_model": "logistic_regression"}'
```

### Analyze LLM

```bash
curl -X POST http://localhost:8000/analyze/llm \
  -H "Content-Type: application/json" \
  -d '{"parsed": {...}, "model": "gpt-3.5-turbo"}'
```

**Response Example:**

```json
{
  "label": "PHISHING",
  "score": 0.85,
  "explanations": ["Suspicious keyword: urgent", "Domain mismatch detected"],
  "highlighted_body": "<mark title='Matched phishing keyword'>urgent</mark> action required...",
  "detection_method": "algorithmic"
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

## Development Status

This project is actively developed with a focus on expanding phishing detection capabilities. The current implementation provides a solid foundation with core analysis features, while the roadmap includes advanced security checks and performance optimizations.

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
