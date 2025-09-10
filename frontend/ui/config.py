"""
Configuration constants for the phishing email analyzer UI.
"""

# API Configuration
API_BASE_URL = "http://localhost:8000"
ANALYZE_ENDPOINT = f"{API_BASE_URL}/analyze/eml"
HEALTH_ENDPOINT = f"{API_BASE_URL}/health"

# UI Configuration
MAX_FILE_SIZE_MB = 200  # Match API limit
PAGE_TITLE = "Phishing Email Analyzer"

# File Processing
SUPPORTED_EXTENSIONS = ["eml"]
MAX_DISPLAY_CONTENT_LENGTH = 2000
MAX_PART_CONTENT_LENGTH = 500
