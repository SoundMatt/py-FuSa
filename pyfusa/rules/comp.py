"""Cyclomatic complexity analysis — COMP001 (DO-178C §6.3.4)."""

from __future__ import annotations

import ast
import os
from typing import List

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule

_DAL_THRESHOLD = {"DAL-A": 4, "DAL-B": 10, "DAL-C": 15, "DAL-D": 20}
_ASIL_THRESHOLD = {"ASIL-D": 4, "ASIL-C": 10, "ASIL-B": 15, "ASIL-A": 20}
_DEFAULT_THRESHOLD = 10

_SKIP_DIRS = {"__pycache__", ".venv", "venv", ".git", ".tox", "build", "dist", "node_modules"}


def _complexity(tree: ast.FunctionDef) -> int:
    """V(G) = 1 + decision points."""
    count = 1
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler,
                              ast.With, ast.Assert)):
            count += 1
        elif isinstance(node, ast.BoolOp):
            count += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            count += 1 + len(node.ifs)
        elif isinstance(node, ast.match_case):  # Python 3.10+
            if node.pattern is not None:
                count += 1
    return count


class COMP001(Rule):
    rule_id = "COMP001"
    description = "Cyclomatic complexity V(G) must not exceed the ASIL/DAL threshold (DO-178C §6.3.4)."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        level = cfg.asil or cfg.dal or ""
        threshold = _ASIL_THRESHOLD.get(level, _DAL_THRESHOLD.get(level, _DEFAULT_THRESHOLD))
        source_dirs = cfg.source_dirs or ["."]

        findings = []
        for src in source_dirs:
            src_path = os.path.join(project_root, src)
            if not os.path.isdir(src_path):
                continue
            for dirpath, dirnames, filenames in os.walk(src_path):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
                for fname in filenames:
                    if not fname.endswith(".py") or fname.startswith("test_") or fname.endswith("_test.py"):
                        continue
                    fpath = os.path.join(dirpath, fname)
                    try:
                        with open(fpath, encoding="utf-8", errors="replace") as f:
                            source = f.read()
                        tree = ast.parse(source, filename=fpath)
                    except (SyntaxError, OSError):
                        continue

                    for node in ast.walk(tree):
                        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        if node.name.startswith("_"):
                            continue
                        cc = _complexity(node)
                        if cc > threshold:
                            rel = os.path.relpath(fpath, project_root)
                            findings.append(pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_WARNING,
                                message=(
                                    f"function {node.name} has cyclomatic complexity {cc} "
                                    f"(threshold {threshold}) — DO-178C §6.3.4"
                                ),
                                location=pyfusa.Location(file=rel, line=node.lineno),
                                category=pyfusa.CATEGORY_LINT,
                                remediation=f"refactor {node.name} to reduce branching; extract helper functions",
                            ))
        return findings


ALL = [COMP001()]
