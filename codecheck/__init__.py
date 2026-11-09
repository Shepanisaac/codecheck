"""CodeCheck: a small static security analyzer for Python."""
__version__ = "0.1.0"

from .analyzer import Finding, analyze_source  # noqa: E402,F401
