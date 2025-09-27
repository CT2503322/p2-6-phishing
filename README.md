
-----

# Phishing Detection System

A full-stack web application for detecting phishing emails using machine learning and rule-based analysis. The system analyzes `.eml` files to identify potential phishing attempts based on keywords, domain whitelisting, and other security indicators.

## Features

**Multi-Method Detection**: Supports algorithmic (rule-based), machine learning, and LLM-based phishing detection.
**Email Analysis**: Upload and analyze `.eml` files or input email text for phishing indicators.
**Advanced Checks**: Keyword detection, domain whitelisting, URL analysis, attachment heuristics, identity verification, lexical scoring, and routing validation.
**Machine Learning**: Pre-trained models (Naive Bayes Complement/Multinomial, Logistic Regression) for statistical content-based classification using labeled email datasets.
**LLM Analysis**: Integration with OpenAI GPT models for intelligent phishing detection using advanced natural language processing and contextual understanding.
**Risk Scoring**: Provides risk scores and classification (SAFE/PHISHING/UNSCORED).
**REST API**: FastAPI backend with `/health`, `/parse/eml`, `/analyze/algorithmic`, `/analyze/ml`, and `/analyze/llm` endpoints.
**Modern Frontend**: Streamlit web application with detection method selection for easy email analysis.
**Automated Testing**: Comprehensive test suite with pytest and sample files.

See [TODO.md] for the detailed development roadmap.

-----

## System Architecture

The application consists of a Streamlit frontend that communicates with a FastAPI backend. The backend handles email parsing and delegates analysis to one of three detection engines: rule-based, machine learning, or LLM.

**User → Streamlit Frontend → FastAPI Backend → (Rule-Based | ML | LLM Engine) → JSON Response**

-----

## Project Structure

```
p2-6-phishing/
├── main.py                # Streamlit application launcher
├── app.py                   # Main Streamlit application logic with detection method selection
├── .env.local.example     # Environment variables example file
├── backend/                 # FastAPI backend
│   ├── api/                 # API endpoints
│   │   └── index.py         # Main API router with /health, /parse/eml, analyze endpoints
│   ├── core/                # Core analysis logic modules
│   │   ├── attachment_checks.py   # Attachment heuristic validation
│   │   ├── helpers.py           # Utility functions
│   │   ├── identity_checks.py   # Sender identity verification
│   │   ├── lexical_score.py     # Lexical analysis scoring
│   │   ├── ml.py                # Machine learning utilities and training script
│   │   ├── routing_checks.py    # Email routing validation
│   │   ├── scoring.py           # Combined risk scoring algorithm
│   │   └── url_checks.py        # URL analysis and validation
│   ├── data/                # Data files and datasets
│   │   ├── whitelist.txt      # Whitelisted domains
│   │   └── combinedlabelled/  # Labeled email dataset for ML training
│   │       ├── ham/           # Ham (safe) email samples
│   │       └── spam/          # Spam (phishing) email samples
│   │       └── README.txt     # Dataset documentation
│   ├── docs/                # Documentation
│   │   ├── API.md           # API documentation
│   │   ├── SETUP.md         # Setup guide
│   │   └── TESTING.md       # Testing guide
│   ├── ingestion/             # Email parsing and cleaning utilities
│   │   ├── clean_html.py      # HTML content cleaning
│   │   ├── clean_zerowidth.py # Zero-width character removal
│   │   └── parse_eml.py       # EML file parsing
│   ├── models/              # Pre-trained ML models (pickled)
│   │   ├── logistic_regression.pkl
│   │   ├── naivebayes_complement.pkl
│   │   └── naivebayes_multinomial.pkl
│   └── tests/               # Test suite
│       ├── test_api.py      # API integration tests
│       ├── test_core.py     # Core logic unit tests
│       ├── test_ingestion.py# Ingestion pipeline tests
│       └── fixtures/          # Test fixture files
│           ├── tada.eml
│           ├── tada-corrupted.eml
│           └── tada.pdf
├── .gitignore               # Git ignore rules
├── requirements.txt         # Python dependencies
├── TODO.md                  # Development roadmap
└── README.md                # This file
```

-----

## Quick Start

### Prerequisites

Python 3.10+
Git

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/CT2503322/p2-6-phishing.git
    cd p2-6-phishing
    ```

2.  **Set up the backend:**

    ```bash
    # Create and activate a virtual environment
    python -m venv .venv
    source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`

    # Install dependencies 
    pip install -r requirements.txt

    # Add your OpenAI API key to a file named .env.local in the project root, two
    levels above the main script 
      
    ```

3.  **Start the development servers:**

    **Backend (Terminal 1):**

    ```bash
    # Activate virtual environment
    source .venv/bin/activate
    # Start the server
    uvicorn backend.api.index:app --reload --port 8000
    ```

    **Frontend (Terminal 2):**

    ```bash
    # Activate virtual environment
    source .venv/bin/activate
    # Start the Streamlit app
    streamlit run main.py
    ```

4.  **Access the application:**

      - **Frontend**: [http://localhost:8501](https://www.google.com/search?q=http://localhost:8501)
      - **API Docs**: [http://localhost:8000/docs](https://www.google.com/search?q=http://localhost:8000/docs)

-----

## API Usage

The API workflow is a two-step process. First, parse an email to get its JSON representation. Second, send that JSON to an analysis endpoint.

### Step 1: Parse Email File

This endpoint converts an `.eml` file into a structured JSON object.

```bash
# Parse the email and save the output to a file
curl -X POST -F "file=@sample.eml" http://localhost:8000/parse/eml > parsed_email.json
```

### Step 2: Analyze with a Chosen Method

Use the `parsed_email.json` file generated in Step 1 as the payload for an analysis endpoint.

**Algorithmic Analysis:**

```bash
curl -X POST http://localhost:8000/analyze/algorithmic \
  -H "Content-Type: application/json" \
  -d @parsed_email.json
```

**Machine Learning Analysis:**

```bash
# The 'ml_model' field can be 'logistic_regression', 'naivebayes_complement', etc.
curl -X POST http://localhost:8000/analyze/ml \
  -H "Content-Type: application/json" \
  -d '{"parsed": '"$(cat parsed_email.json)"', "ml_model": "logistic_regression"}'
```

**LLM Analysis:**

```bash
# The 'model' field can be 'gpt-4o', 'gpt-4-turbo', etc.
curl -X POST http://localhost:8000/analyze/llm \
  -H "Content-Type: application/json" \
  -d '{"parsed": '"$(cat parsed_email.json)"', "model": "gpt-4o"}'
```

**Example Response:**

```json
{
  "label": "PHISHING",
  "score": 0.85,
  "explanations": ["Suspicious keyword: urgent", "Domain mismatch detected"],
  "highlighted_body": "<mark title='Matched phishing keyword'>urgent</mark> action required...",
  "detection_method": "algorithmic"
}
```

-----

## Model Training

The ML models can be retrained using the provided dataset in `backend/data/combinedlabelled/`. The `backend/core/ml.py` script handles the feature extraction and training process.

To retrain and save new model artifacts, run the script from the project root:

```bash
# Activate virtual environment first
source .venv/bin/activate

# Run the training script
python -m backend.core.ml --data_path backend/data/combinedlabelled/ --output_dir backend/models/
```

-----

## Testing

Run the complete test suite using pytest:

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests with verbose output
python -m pytest backend/tests/ -v
```

-----

## Deployment

The Streamlit frontend can be deployed on platforms like Streamlit Cloud, Heroku, or AWS. The FastAPI backend can be deployed separately on any cloud platform supporting Python applications, such as AWS Elastic Beanstalk or Google App Engine.

## Contributing

1.  Fork the repository
2.  Create a feature branch (`git checkout -b feature/your-feature`)
3.  Make your changes and add tests
4.  Commit your changes (`git commit -m 'Add some amazing feature'`)
5.  Push to the branch (`git push origin feature/your-feature`)
6.  Submit a pull request

## License

This project is licensed under the **MIT License**.