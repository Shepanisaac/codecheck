"""Maps file extensions to analyzers."""
from __future__ import annotations

import os

from .core import Finding, MissingDependency  # noqa: F401  (re-exported)

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
}


def language_for(path: str) -> str | None:
    return EXTENSIONS.get(os.path.splitext(path)[1].lower())


def is_generated(path: str) -> bool:
    """Minified/bundled output is noise when walking a directory (explicit files are always scanned)."""
    return path.endswith((".min.js", ".bundle.js", ".min.mjs"))


def analyze_source(source: str, filename: str = "<string>", language: str | None = None) -> list[Finding]:
    """Analyze source text. The language is taken from `language`, else the filename, else Python."""
    language = language or language_for(filename) or "python"
    if language == "python":
        from .analyzer import analyze_source as run
    elif language == "javascript":
        from .js_analyzer import analyze_js as run
    else:
        raise ValueError(f"unsupported language: {language}")
    return run(source, filename)
