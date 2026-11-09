# CodeCheck

A small static security analyzer for Python. It parses code into an AST, tracks
untrusted data from sources (`request.*`, `input()`, `sys.argv`, Flask URL params)
to dangerous sinks (SQL, shell, `eval`, file paths, URLs, templates), and reports
findings mapped to CWE and OWASP Top 10 (2021).

```
python -m codecheck path/to/project                 # text report
python -m codecheck src -f sarif -o results.sarif   # GitHub code scanning / IDEs
python -m codecheck src --fail-on high              # CI gate (exit 1 on high)
python -m unittest discover tests                    # run the tests
```

Suppress a finding with `# nosec` or `# codecheck: ignore[CS005]` on the line.

## How it works

1. **Parse** each file with `ast`; resolve import aliases (`import os as o`).
2. **Walk** statements in order, keeping an environment `variable -> flags`
   (`TAINT`, `DYN` string built at runtime, `RAW` reflected text). Branches are merged,
   loops run twice so taint flows backwards through iterations.
3. **Check sinks** at every call; severity is *high* when taint is proven,
   *medium* when the pattern is merely risky (e.g. a dynamically built SQL string).
4. **Report** as text, JSON or SARIF 2.1.0.

## Rules

| ID | Finding | CWE | OWASP 2021 |
|----|---------|-----|-----------|
| CS001 | eval/exec | 95 | A03 |
| CS002 | SQL injection | 89 | A03 |
| CS003 | OS command injection | 78 | A03 |
| CS004 | Hardcoded credentials | 798 | A07 |
| CS005 | Weak hash (MD5/SHA-1) | 328 | A02 |
| CS006 | Insecure deserialization | 502 | A08 |
| CS007 | TLS validation disabled | 295 | A07 |
| CS008 | Debug mode on | 489 | A05 |
| CS009 | Path traversal | 22 | A01 |
| CS010 | Weak randomness for secrets | 338 | A02 |
| CS011 | XSS / template injection | 79 | A03 |
| CS012 | SSRF | 918 | A10 |

## Known limitations

- Intra-procedural: taint does not cross function calls you wrote (no call graph yet).
- Sanitizers are coarse: `shlex.quote` clears taint for every rule, not just command injection.
- Python only; no framework models beyond Flask/Django request objects.
- Heuristic secret detection is name-based.

## Roadmap

Inter-procedural taint via a call graph, per-rule sanitizers, Django/FastAPI models,
a JavaScript/PHP frontend (tree-sitter), and an ML/LLM triage layer that ranks findings
using accept/dismiss feedback.
