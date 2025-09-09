import pytest
from fastapi.testclient import TestClient
from backend.api.index import app
from io import BytesIO
import os

client = TestClient(app)

# Path to sample files
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def test_health_endpoint():
    """Test the health check endpoint."""
    response = client.get("/api/py/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_analyze_eml_valid():
    """Test analyzing a valid .eml file."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/api/py/analyze/eml",
        files={"file": ("tada.eml", BytesIO(file_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    assert "risk" in data
    assert "label" in data
    assert "reasons" in data
    assert "meta" in data
    assert isinstance(data["risk"], float)
    assert data["label"] in ["SAFE", "PHISHING", "UNSCORED"]


def test_analyze_eml_corrupted():
    """Test analyzing a corrupted .eml file."""
    sample_path = os.path.join(SAMPLES_DIR, "tada-corrupted.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/api/py/analyze/eml",
        files={"file": ("tada-corrupted.eml", BytesIO(file_content), "message/rfc822")},
    )
    assert response.status_code == 422
    assert "Invalid or corrupted email format" in response.json()["detail"]


def test_analyze_eml_invalid_file_type():
    """Test uploading a non-.eml file."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.pdf")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/api/py/analyze/eml",
        files={"file": ("tada.pdf", BytesIO(file_content), "application/pdf")},
    )
    assert response.status_code == 400
    assert "Only .eml files are supported" in response.json()["detail"]


def test_analyze_eml_no_file():
    """Test posting without a file."""
    response = client.post("/api/py/analyze/eml")
    assert response.status_code == 422  # FastAPI validation error for missing file
