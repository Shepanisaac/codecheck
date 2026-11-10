"""CodeCheck: a small static security analyzer for Python and JavaScript."""
__version__ = "0.2.0"

from .core import Finding, MissingDependency  # noqa: E402,F401
from .languages import analyze_source, language_for  # noqa: E402,F401
