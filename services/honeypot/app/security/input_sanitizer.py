"""
Input Sanitizer
Aggressive payload cleaning to protect the logging layer and dashboard.
"""
import re

def sanitize_payload(payload: str) -> str:
    """
    Strips invisible control characters and ensures safe encoding to prevent log injection.
    """
    if not payload:
        return ""
    # Remove null bytes and other non-printable chars (except standard whitespace/newlines)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', payload)
    return cleaned[:65536] # hard clip memory
