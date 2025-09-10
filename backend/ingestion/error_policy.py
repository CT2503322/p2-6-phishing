"""
Centralized error policy for defensive parsing.
"""

from typing import Any, Callable, Optional


def safe_call(func: Callable, *args, default: Any = None, **kwargs) -> Any:
    """
    Safely call a function, returning default on exception.
    """
    try:
        return func(*args, **kwargs)
    except Exception:
        return default


def safe_getattr(obj: Any, attr: str, default: Any = None) -> Any:
    """
    Safely get an attribute, returning default on exception.
    """
    try:
        return getattr(obj, attr)
    except Exception:
        return default


def safe_method_call(
    obj: Any, method: str, *args, default: Any = None, **kwargs
) -> Any:
    """
    Safely call a method on an object, returning default on exception.
    """
    try:
        return getattr(obj, method)(*args, **kwargs)
    except Exception:
        return default
