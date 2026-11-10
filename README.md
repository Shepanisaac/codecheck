# CodeCheck

A small static security analyzer for **Python** and **JavaScript** (Node, browser, JSX).
It parses code into a syntax tree, tracks untrusted data from sources (`request.*`, `req.query`,
`input()`, `location.hash`, `process.argv` ...) to dangerous sinks (SQL, shell, `eval`, file paths,
URLs, HTML), and reports findings mapped to CWE and OWASP Top 10 (2021).

## Install and run

Python 3.9+. Python scanning needs nothing else. JavaScript scanning needs a parser:

```
pip install tree-sitter tree-sitter-javascript      # or: pip install ".[js]"

python -m codecheck path/to/project                  # scans .py .js .jsx .mjs .cjs
python -m codecheck src -f sarif -o results.sarif    # GitHub code scanning / IDEs
python -m codecheck src --fail-on high               # CI gate (exit 1 on high)
python -m codecheck app.js --min-severity high       # only the serious ones
python -m unittest discover tests                    # run the tests
```

Without the JS parser installed, `.js` files are skipped with a message that says how to install it.
Directory scans skip `node_modules`, virtualenvs, `*.min.js` and `*.bundle.js`; a file named
explicitly is always scanned.

Suppress a finding with `# nosec` / `// nosec` or `# codecheck: ignore[CS005]` on the line.

## How it works

1. **Parse** with Python's `ast` or tree-sitter; resolve imports (`import os as o`,
   `const { exec } = require('child_process')`, `import * as cp from 'node:child_process'`).
2. **Walk** statements in order with an environment `variable -> flags`:
   `TAINT` (attacker-controlled), `DYN` (string built at runtime), `RAW` (reflected text),
   `SAFE` (sanitized/numeric, never counts as string building). Branches merge, loops run twice.
3. **Check sinks** at every call. *High* = taint proven to reach the sink; *medium* = risky pattern.
4. **Report** as text, JSON or SARIF 2.1.0.

Both languages share one rule set, one taint model and the same reports.

## Rules

| ID | Finding | CWE | OWASP 2021 | Python | JS |
|----|---------|-----|------------|:--:|:--:|
| CS001 | eval / exec / `new Function` / string timers | 95 | A03 | ✓ | ✓ |
| CS002 | SQL injection | 89 | A03 | ✓ | ✓ |
| CS003 | OS command injection | 78 | A03 | ✓ | ✓ |
| CS004 | Hardcoded credentials (incl. `x \|\| 'fallback'`, JWT secrets) | 798 | A07 | ✓ | ✓ |
| CS005 | Weak hash (MD5/SHA-1) | 328 | A02 | ✓ | ✓ |
| CS006 | Insecure deserialization | 502 | A08 | ✓ | ✓ |
| CS007 | TLS validation disabled | 295 | A07 | ✓ | ✓ |
| CS008 | Debug mode on | 489 | A05 | ✓ | - |
| CS009 | Path traversal | 22 | A01 | ✓ | ✓ |
| CS010 | Weak randomness for secrets | 338 | A02 | ✓ | ✓ |
| CS011 | XSS / template injection (reflected, DOM, JSX) | 79 | A03 | ✓ | ✓ |
| CS012 | SSRF | 918 | A10 | ✓ | ✓ |

## Known limitations

- Intra-procedural: taint does not flow through functions you wrote (no call graph yet).
- Sanitizers are coarse: `shlex.quote` / `parseInt` clear taint for every rule, not just one class.
- Command-line arguments, stdin and `process.argv` count as untrusted, so CLI tools that read a
  path from `argv` will be flagged for path traversal. Treat those as low-priority.
- JavaScript: plain JS and JSX only (no TypeScript yet). Framework models cover Express-style
  `req`/`res`, jQuery, React and the browser DOM; others (Koa, Fastify `reply`, Next.js) are partial.
- Secret detection is name-based.

## Roadmap

Inter-procedural taint via a call graph, per-rule sanitizers, TypeScript, PHP/Java frontends
(tree-sitter makes each one mostly a catalogue of sources and sinks), and an ML/LLM triage layer
that ranks findings using accept/dismiss feedback.
