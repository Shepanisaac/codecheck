"""Rule catalogue. Each rule maps to a CWE and an OWASP Top 10 (2021) category."""
from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    cwe: str
    owasp: str
    severity: str  # default severity; the analyzer may raise it when taint is proven
    help: str


_RULES = [
    Rule("CS001", "Code injection via eval/exec", "CWE-95",
         "A03:2021 Injection", "medium",
         "Avoid eval/exec. Use ast.literal_eval for literals or a purpose-built parser."),
    Rule("CS002", "SQL injection", "CWE-89",
         "A03:2021 Injection", "medium",
         "Use parameterized queries: cursor.execute(sql, params). Never build SQL with f-strings, +, % or .format()."),
    Rule("CS003", "OS command injection", "CWE-78",
         "A03:2021 Injection", "medium",
         "Pass an argument list to subprocess without shell=True; validate or quote untrusted input (shlex.quote)."),
    Rule("CS004", "Hardcoded credentials", "CWE-798",
         "A07:2021 Identification and Authentication Failures", "medium",
         "Load secrets from environment variables or a secrets manager, and rotate any that were committed."),
    Rule("CS005", "Weak hash algorithm (MD5/SHA-1)", "CWE-328",
         "A02:2021 Cryptographic Failures", "medium",
         "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords."),
    Rule("CS006", "Insecure deserialization", "CWE-502",
         "A08:2021 Software and Data Integrity Failures", "medium",
         "Never unpickle/unmarshal untrusted data. Use JSON, or yaml.safe_load for YAML."),
    Rule("CS007", "TLS certificate validation disabled", "CWE-295",
         "A07:2021 Identification and Authentication Failures", "medium",
         "Leave certificate verification on. Pin or supply a CA bundle instead of disabling checks."),
    Rule("CS008", "Debug mode enabled", "CWE-489",
         "A05:2021 Security Misconfiguration", "medium",
         "Disable debug mode in production; drive it from configuration."),
    Rule("CS009", "Path traversal", "CWE-22",
         "A01:2021 Broken Access Control", "medium",
         "Normalize the path and confirm it stays under an allowed base directory; use secure_filename for uploads."),
    Rule("CS010", "Insecure randomness for a secret", "CWE-338",
         "A02:2021 Cryptographic Failures", "medium",
         "Use the secrets module (secrets.token_urlsafe, secrets.choice) for tokens, passwords and OTPs."),
    Rule("CS011", "Cross-site scripting / template injection", "CWE-79",
         "A03:2021 Injection", "medium",
         "Render untrusted data through an auto-escaping template; never mark it safe or use it as a template."),
    Rule("CS012", "Server-side request forgery", "CWE-918",
         "A10:2021 Server-Side Request Forgery", "medium",
         "Validate URLs against an allowlist of hosts/schemes and block internal address ranges."),
]

RULES = {r.id: r for r in _RULES}
