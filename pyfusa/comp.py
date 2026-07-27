"""Standalone cyclomatic complexity report (DO-178C §6.3.4)."""

from __future__ import annotations

import ast
import os
from datetime import datetime, timezone
from typing import NamedTuple

import pyfusa
from pyfusa.config import Config
from pyfusa.rules.comp import (
    _ASIL_THRESHOLD,
    _DAL_THRESHOLD,
    _DEFAULT_THRESHOLD,
    _SKIP_DIRS,
    _complexity,
)

COMP_REPORT = "comp-report.json"


class FunctionComplexity(NamedTuple):
    file: str
    function: str
    complexity: int
    line: int
    status: str  # "PASS" | "FAIL"


def analyze(project_root: str, cfg: Config) -> tuple[list[FunctionComplexity], int]:
    """Return (results, threshold) for all non-private, non-test functions."""
    level = cfg.asil or cfg.dal or ""
    threshold = _ASIL_THRESHOLD.get(
        level, _DAL_THRESHOLD.get(level, _DEFAULT_THRESHOLD)
    )
    source_dirs = cfg.source_dirs or ["."]

    results: list[FunctionComplexity] = []
    for src in source_dirs:
        src_path = os.path.join(project_root, src)
        if not os.path.isdir(src_path):
            continue
        for dirpath, dirnames, filenames in os.walk(src_path):
            dirnames[:] = [
                d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                if fname.startswith("test_") or fname.endswith("_test.py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as f:
                        source = f.read()
                    tree = ast.parse(source, filename=fpath)
                except (SyntaxError, OSError):
                    continue
                rel = os.path.relpath(fpath, project_root)
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if node.name.startswith("_"):
                        continue
                    cc = _complexity(node)
                    results.append(
                        FunctionComplexity(
                            file=rel,
                            function=node.name,
                            complexity=cc,
                            line=node.lineno,
                            status="FAIL" if cc > threshold else "PASS",
                        )
                    )
    return results, threshold


def run(project_root: str, cfg: Config) -> dict:
    results, threshold = analyze(project_root, cfg)
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    over = sum(1 for r in results if r.status == "FAIL")

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "comp-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": "DO-178C §6.3.4",
        "threshold": threshold,
        "summary": {
            "total": len(results),
            "pass": len(results) - over,
            "fail": over,
        },
        "functions": [
            {
                "file": r.file,
                "function": r.function,
                "complexity": r.complexity,
                "line": r.line,
                "status": r.status,
            }
            for r in results
        ],
    }


def render_text(doc: dict) -> str:
    s = doc["summary"]
    lines = [
        f"Cyclomatic complexity report  project={doc['project']}  threshold={doc['threshold']}",
        f"total={s['total']}  pass={s['pass']}  fail={s['fail']}",
        "",
    ]
    fails = [f for f in doc["functions"] if f["status"] == "FAIL"]
    if fails:
        lines.append("FAIL (over threshold):")
        for f in sorted(fails, key=lambda x: -x["complexity"]):
            lines.append(
                f"  ✗ V(G)={f['complexity']:3d}  {f['file']}:{f['line']}  {f['function']}"
            )
    else:
        lines.append("All functions within threshold.")
    return "\n".join(lines)
