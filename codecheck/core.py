"""Language-independent pieces shared by every analyzer: findings, taint flags, suppression."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict

from .rules import RULES, SEVERITY_ORDER

# Taint flags attached to every evaluated expression / variable.
TAINT = 1  # value may be attacker-controlled
DYN = 2    # string assembled at runtime (concatenation, template, format)
RAW = 4    # attacker text not yet transformed by a function (relevant to reflected XSS)
SAFE = 8   # value provably inert (sanitized, numeric or boolean): never counts as string building
PROP = TAINT | RAW

SECRET_RE = re.compile(
    r"(^|_)(pass|password|passwd|pwd|secret|api_?key|apikey|access_?key|"
    r"auth_?token|token|private_?key|client_secret|credentials?)($|_)")
NOT_A_SECRET_SUFFIX = {
    "type", "field", "name", "url", "path", "header", "label", "file", "len",
    "length", "expiry", "ttl", "endpoint", "env", "var", "prompt", "message",
    "msg", "help", "hint", "text", "placeholder", "format", "param", "key_name",
}
# `# nosec`, `// nosec`, `# codecheck: ignore[CS002]`, `// codecheck: ignore`
SUPPRESS_RE = re.compile(
    r"(?:#|//|/\*)\s*(?:nosec|codecheck:\s*ignore)(?:\[([A-Za-z0-9_,\s]+)\])?")


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    col: int
    snippet: str = ""
    tainted: bool = False

    @property
    def cwe(self) -> str:
        return RULES[self.rule_id].cwe

    @property
    def owasp(self) -> str:
        return RULES[self.rule_id].owasp

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cwe"], d["owasp"] = self.cwe, self.owasp
        return d


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def looks_like_secret_name(name: str) -> bool:
    s = _snake(name)
    return bool(SECRET_RE.search(s)) and s.split("_")[-1] not in NOT_A_SECRET_SUFFIX


FETCH_CREDENTIALS = {"include", "same-origin", "omit"}  # fetch()'s `credentials` option


def is_placeholder(value: str) -> bool:
    return not value or value.startswith(("<", "${", "{{")) or value in FETCH_CREDENTIALS


def join(a: int, b: int) -> int:
    """Combine flags where either side may be the value: SAFE only survives if both are safe."""
    return ((a | b) & ~SAFE) | (a & b & SAFE)


def merge_env(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = join(out[k], v) if k in out else v & ~SAFE
    for k in a:
        if k not in b:
            out[k] = a[k] & ~SAFE
    return out


class MissingDependency(RuntimeError):
    """A language frontend needs an optional package that is not installed."""


class BaseAnalyzer:
    def __init__(self, source: str, filename: str = "<string>"):
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.found: dict[tuple, Finding] = {}

    def add(self, rule_id: str, line: int, col: int, message: str,
            severity: str | None = None, tainted: bool = False) -> None:
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        m = SUPPRESS_RE.search(text)
        if m:
            ids = m.group(1)
            if not ids or rule_id in {i.strip() for i in ids.split(",")}:
                return
        severity = severity or RULES[rule_id].severity
        key = (rule_id, line, col)
        old = self.found.get(key)
        if old and SEVERITY_ORDER[old.severity] >= SEVERITY_ORDER[severity]:
            return
        self.found[key] = Finding(rule_id, severity, message, self.filename,
                                  line, col, text.strip(), tainted)

    @staticmethod
    def sev(flags: int, taint_msg: str, dyn_msg: str | None = None):
        """Pick (severity, message, tainted) from flags, or None if clean."""
        if flags & PROP:
            return "high", taint_msg, True
        if dyn_msg and flags & DYN:
            return "medium", dyn_msg, False
        return None

    def results(self) -> list[Finding]:
        return sorted(self.found.values(), key=lambda f: (f.line, f.col, f.rule_id))
