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
    cyclomatic_complexity,
)

COMP_REPORT = "comp-report.json"

# x-FuSa spec §9.2: "A ≤ 4, B ≤ 10 (default), C ≤ 15, D ≤ 20" — same mapping
# rules/comp.py already uses for DAL, reused here for the --dal CLI override.
DAL_THRESHOLD = _DAL_THRESHOLD


class FunctionComplexity(NamedTuple):
    file: str
    function: str
    complexity: int
    line: int
    status: str  # "PASS" | "FAIL"


# fusa:req REQ-CLI009
def analyze(
    project_root: str, cfg: Config, threshold_override: int | None = None
) -> tuple[list[FunctionComplexity], int]:
    """Return (results, threshold) for all non-private, non-test functions.

    `threshold_override` — set from `--threshold`/`--dal` (§9.2) — takes
    precedence over the project's configured ASIL/DAL when given.
    """
    if threshold_override is not None:
        threshold = threshold_override
    else:
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
                    cc = cyclomatic_complexity(node)
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


# fusa:req REQ-CLI009
def run(
    project_root: str,
    cfg: Config,
    threshold_override: int | None = None,
    dal: str = "",
) -> dict:
    """Build a §9.2/§13 canonical comp-report.

    Field names/shape MUST match FuSaOps's `comp.Report` decoder exactly —
    `totalFunctions`/`violations`/`results[].{name,exceedsThreshold}`, not an
    ad hoc `summary`/`functions[].{function,status}` shape. This is the one
    schema FuSaOps decodes directly off stdout (no `--output`), so a field
    rename here silently zero-values the whole cross-language rollup.
    """
    results, threshold = analyze(project_root, cfg, threshold_override)
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    over = sum(1 for r in results if r.status == "FAIL")

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "comp-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "threshold": threshold,
        "totalFunctions": len(results),
        "violations": over,
        "results": [
            {
                "file": r.file,
                "line": r.line,
                "name": r.function,
                "complexity": r.complexity,
                "exceedsThreshold": r.status == "FAIL",
            }
            for r in results
        ],
    }
    # dal (MAY) — omit when the threshold came from an explicit --threshold
    # rather than a DAL level, per §9.2.
    if dal:
        doc["dal"] = dal
    return doc


# fusa:req REQ-CLI009
def render_text(doc: dict) -> str:
    total = doc["totalFunctions"]
    violations = doc["violations"]
    lines = [
        f"Cyclomatic complexity report  project={doc['project']}  threshold={doc['threshold']}",
        f"total={total}  pass={total - violations}  fail={violations}",
        "",
    ]
    fails = [f for f in doc["results"] if f["exceedsThreshold"]]
    if fails:
        lines.append("FAIL (over threshold):")
        for f in sorted(fails, key=lambda x: -x["complexity"]):
            lines.append(
                f"  ✗ V(G)={f['complexity']:3d}  {f['file']}:{f['line']}  {f['name']}"
            )
    else:
        lines.append("All functions within threshold.")
    return "\n".join(lines)
