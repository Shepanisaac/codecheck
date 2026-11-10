"""Command-line interface.

Exit codes: 0 = clean (or below --fail-on), 1 = findings at/above --fail-on, 2 = usage/parse error.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .core import Finding, MissingDependency
from .languages import analyze_source, is_generated, language_for
from .report import to_json, to_sarif, to_text
from .rules import SEVERITY_ORDER

SKIP_DIRS = {".git", ".hg", ".venv", "venv", "env", "node_modules", "__pycache__",
             "site-packages", "build", "dist", ".tox", ".mypy_cache", "coverage", ".next"}


def iter_source_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
                for f in sorted(files):
                    path = os.path.join(root, f)
                    if language_for(path) and not is_generated(path):
                        yield path
        else:
            print(f"codecheck: no such file or directory: {p}", file=sys.stderr)


def scan_paths(paths) -> tuple[list[Finding], list[str]]:
    findings, errors, missing = [], [], {}
    for path in iter_source_files(paths):
        lang = language_for(path)
        if lang is None:
            errors.append(f"{path}: unsupported file type (supported: .py, .js, .jsx, .mjs, .cjs)")
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            findings.extend(analyze_source(src, path, lang))
        except MissingDependency as e:
            missing.setdefault(str(e), []).append(path)
        except SyntaxError as e:
            errors.append(f"{path}:{e.lineno}: could not parse ({e.msg})")
        except OSError as e:
            errors.append(f"{path}: {e}")
        except RecursionError:
            errors.append(f"{path}: skipped (code nested too deeply to analyze)")
        except Exception as e:  # noqa: BLE001 - keep scanning the other files
            errors.append(f"{path}: internal error {type(e).__name__}: {e}")
    for msg, files in missing.items():
        errors.append(f"skipped {len(files)} file(s), e.g. {files[0]}. {msg}")
    return findings, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="codecheck",
                                 description="Static security analyzer for Python and JavaScript code.")
    ap.add_argument("paths", nargs="+", help="files or directories to scan")
    ap.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("-o", "--output", help="write report to this file instead of stdout")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                    help="hide findings below this severity (default: low)")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default="medium",
                    help="exit 1 if any finding is at or above this severity (default: medium)")
    ap.add_argument("--version", action="version", version=f"codecheck {__version__}")
    args = ap.parse_args(argv)

    findings, errors = scan_paths(args.paths)
    findings = [f for f in findings
                if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]]
    findings.sort(key=lambda f: (f.file, f.line, f.col))

    if args.format == "text":
        report = to_text(findings, color=False if args.output else None)
    elif args.format == "json":
        report = to_json(findings)
    else:
        report = to_sarif(findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
    else:
        print(report)
    for e in errors:
        print(f"warning: {e}", file=sys.stderr)

    if args.fail_on != "never" and any(
            SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 1
    return 2 if errors and not findings else 0


if __name__ == "__main__":
    sys.exit(main())
