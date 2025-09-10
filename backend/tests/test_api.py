import pytest
from fastapi.testclient import TestClient
from backend.api.index import app
from io import BytesIO
import os

client = TestClient(app)

# Path to sample files
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def test_health_endpoint():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data
    assert isinstance(data["timestamp"], float)


def test_analyze_eml_valid():
    """Test analyzing a valid .eml file."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/analyze/eml",
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
        "/analyze/eml",
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
        "/analyze/eml",
        files={"file": ("tada.pdf", BytesIO(file_content), "application/pdf")},
    )
    assert response.status_code == 400
    assert "Only .eml files are supported" in response.json()["detail"]


def test_analyze_eml_no_file():
    """Test posting without a file."""
    response = client.post("/analyze/eml")
    assert response.status_code == 422  # FastAPI validation error for missing file


def test_analyze_eml_file_too_large():
    """Test uploading a file that exceeds size limit."""
    # Create a file larger than 200MB
    large_content = b"x" * (201 * 1024 * 1024)  # 201MB

    response = client.post(
        "/analyze/eml",
        files={"file": ("large.eml", BytesIO(large_content), "message/rfc822")},
    )
    assert response.status_code == 413
    assert "File too large" in response.json()["detail"]
    assert "200MB" in response.json()["detail"]


def test_analyze_eml_empty_file():
    """Test uploading an empty file."""
    response = client.post(
        "/analyze/eml",
        files={"file": ("empty.eml", BytesIO(b""), "message/rfc822")},
    )
    # Empty file gets processed but fails email validation
    assert response.status_code == 422
    error_detail = response.json()["detail"]
    # Should fail with email validation error
    assert "Invalid or corrupted email format" in error_detail


def test_analyze_eml_no_filename():
    """Test uploading a file without filename."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/analyze/eml",
        files={"file": ("", BytesIO(file_content), "message/rfc822")},
    )
    # FastAPI returns 422 for validation errors
    assert response.status_code == 422
    error_detail = response.json()["detail"]
    # Check that it's a validation error
    assert isinstance(error_detail, list) or "validation" in str(error_detail).lower()


def test_analyze_eml_with_metadata():
    """Test that analysis response includes metadata."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/analyze/eml",
        files={"file": ("test.eml", BytesIO(file_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # Check metadata is present
    assert "metadata" in data
    metadata = data["metadata"]
    assert metadata["filename"] == "test.eml"
    assert isinstance(metadata["file_size"], int)
    assert isinstance(metadata["processing_time"], float)
    assert "api_version" in metadata


def test_analyze_eml_auth_data_included():
    """Test that authentication data is included when present."""
    sample_path = os.path.join(SAMPLES_DIR, "auth_headers.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/analyze/eml",
        files={"file": ("auth.eml", BytesIO(file_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # Should have authentication data
    assert "auth" in data
    assert isinstance(data["auth"], dict)


def test_health_endpoint_structure():
    """Test health endpoint returns proper structure."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()

    required_fields = ["status", "timestamp", "version"]
    for field in required_fields:
        assert field in data

    assert data["status"] == "healthy"
    assert isinstance(data["timestamp"], (int, float))
    assert isinstance(data["version"], str)


def test_analyze_eml_subscription_metadata_included():
    """Test that subscription metadata is included in analysis response."""
    sample_path = os.path.join(SAMPLES_DIR, "tada.eml")
    with open(sample_path, "rb") as f:
        file_content = f.read()

    response = client.post(
        "/analyze/eml",
        files={"file": ("tada.eml", BytesIO(file_content), "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()

    # Check that subscription metadata is included
    assert "subscription" in data
    subscription = data["subscription"]
    assert isinstance(subscription, dict)

    # Check the structure matches our model
    if subscription.get("list_unsubscribe"):
        list_unsubscribe = subscription["list_unsubscribe"]
        assert "one_click" in list_unsubscribe
        assert "http" in list_unsubscribe or "mailto" in list_unsubscribe
        if "http" in list_unsubscribe:
            assert isinstance(list_unsubscribe["http"], str)
        if "mailto" in list_unsubscribe:
            assert isinstance(list_unsubscribe["mailto"], str)
