"""
sample_project/utils/helper.py
Utility functions — clean file with no vulnerabilities.
"""
import re
from datetime import datetime


def sanitize_input(text: str) -> str:
    """Remove special characters from user input."""
    return re.sub(r"[^a-zA-Z0-9 _-]", "", text)


def format_date(dt: datetime) -> str:
    """Format a datetime to a readable string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp value between minimum and maximum."""
    return max(minimum, min(maximum, value))


def paginate(items: list, page: int, per_page: int = 10) -> list:
    """Return a slice of items for the given page."""
    start = (page - 1) * per_page
    return items[start : start + per_page]
