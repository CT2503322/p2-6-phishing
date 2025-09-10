"""
API client for communicating with the phishing analysis backend.
"""

import requests
import tempfile
import os
from typing import Dict, Any, Optional

from .config import API_BASE_URL, ANALYZE_ENDPOINT, HEALTH_ENDPOINT


def analyze_email_file(file) -> Optional[Dict[str, Any]]:
    """
    Send email file to backend API for analysis.

    Args:
        file: Streamlit uploaded file object

    Returns:
        Dict containing analysis results or None if failed
    """
    # Create temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        tmp_file.write(file.getvalue())
        tmp_file_path = tmp_file.name

    try:
        # Send file to API
        with open(tmp_file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(ANALYZE_ENDPOINT, files=files)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"API Error: {response.status_code}")
            return None

    except Exception as e:
        print(f"Error connecting to API: {str(e)}")
        return None

    finally:
        # Clean up temporary file
        os.unlink(tmp_file_path)


def check_api_health() -> bool:
    """
    Check if the backend API is healthy and running.

    Returns:
        True if API is healthy, False otherwise
    """
    try:
        response = requests.get(HEALTH_ENDPOINT, timeout=5)
        return response.status_code == 200
    except Exception:
        return False


def get_api_info() -> Optional[Dict[str, Any]]:
    """
    Get detailed API information from the health endpoint.

    Returns:
        Dict containing API info or None if failed
    """
    try:
        response = requests.get(HEALTH_ENDPOINT, timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception:
        return None
