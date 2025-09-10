"""
EML ingestion package for processing email messages.
"""

from .parse_eml import EmlReader
from .mime import MultiPartParser

__all__ = ["EmlReader", "MultiPartParser"]
