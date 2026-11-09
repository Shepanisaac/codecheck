"""Output formats: human-readable text, JSON, and SARIF 2.1.0 (GitHub code scanning, IDEs)."""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

from . import __version__
from .analyzer import Finding
from .rules import RULES

_COLORS = {"high": "\033[31;1m", "medium": "\033[33m", "low": "\033[36m"}
_RESET, _DIM = "\033[0m", "\033[2m"


def to_text(findings: list[Finding], color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    def c(s, code):
        return f"{code}{s}{_RESET}" if color else s

    if not findings:
        return "No issues found."
    by_file = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)
    out = []
    for path in sorted(by_file):
        out.append(c(path, "\033[1m"))
        for f in sorted(by_file[path], key=lambda x: (x.line, x.col)):
            tag = c(f"{f.severity.upper():<6}", _COLORS[f.severity])
            out.append(f"  {f.line}:{f.col:<3} {tag} {f.rule_id}  {f.message}")
            out.append(c(f"           {f.cwe} · {f.owasp}", _DIM))
            if f.snippet:
                out.append(f"           > {f.snippet[:110]}")
        out.append("")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    out.append(f"{len(findings)} issue(s): {counts['high']} high, "
               f"{counts['medium']} medium, {counts['low']} low")
    return "\n".join(out)


def to_json(findings: list[Finding]) -> str:
    return json.dumps({"tool": "codecheck", "version": __version__,
                       "findings": [f.to_dict() for f in findings]}, indent=2)


_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "3.0"}


def to_sarif(findings: list[Finding]) -> str:
    rule_ids = sorted(RULES)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    rules = [{
        "id": rid,
        "name": RULES[rid].title.replace(" ", ""),
        "shortDescription": {"text": RULES[rid].title},
        "help": {"text": RULES[rid].help},
        "properties": {"tags": ["security", RULES[rid].cwe, RULES[rid].owasp],
                       "security-severity": _SECURITY_SEVERITY[RULES[rid].severity]},
    } for rid in rule_ids]
    results = [{
        "ruleId": f.rule_id,
        "ruleIndex": index[f.rule_id],
        "level": _LEVEL[f.severity],
        "message": {"text": f.message},
        "properties": {"tainted": f.tainted, "security-severity": _SECURITY_SEVERITY[f.severity]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file.replace(os.sep, "/")},
            "region": {"startLine": f.line, "startColumn": f.col,
                       "snippet": {"text": f.snippet}},
        }}],
    } for f in findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CodeCheck", "version": __version__,
                                      "rules": rules}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)
