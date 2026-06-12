"""COUP001-003: Coupling analysis rules."""

from __future__ import annotations

import ast
import os
from typing import List

from pyfusa import Finding, Location, SEVERITY_INFO, SEVERITY_WARNING
from pyfusa.rules import Rule
from pyfusa.config import Config


def _python_files(root: str, cfg: Config) -> List[str]:
    source_dirs = cfg.source_dirs or ["."]
    paths: List[str] = []
    skip = {"__pycache__", ".git", ".tox", "venv", ".venv", "dist", "build"}
    for sdir in source_dirs:
        base = os.path.join(root, sdir)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".")]
            for fn in filenames:
                if fn.endswith(".py"):
                    paths.append(os.path.join(dirpath, fn))
    return paths


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _parse(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        return ast.parse(src, filename=path)
    except SyntaxError:
        return None


def _is_callable_annotation(ann) -> bool:
    if isinstance(ann, ast.Name) and ann.id in ("Callable", "callable"):
        return True
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id in ("Callable",)
    return False


# ---------------------------------------------------------------------------
# COUP001 — Module-level mutable variables (data coupling)
# ---------------------------------------------------------------------------
class COUP001(Rule):
    rule_id = "COUP001"
    standard = "iso26262"
    clause = "6.4.3"
    description = "Module-level mutable variable creates data coupling"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        MUTABLE_TYPES = (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)
        for path in _python_files(project_root, cfg):
            tree = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name) and not t.id.startswith("_"):
                            if isinstance(node.value, MUTABLE_TYPES):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_INFO,
                                    message=f"module-level mutable variable '{t.id}' creates data coupling",
                                    location=Location(file=rel, line=getattr(node, "lineno", 0), end_line=getattr(node, "end_lineno", 0), end_column=getattr(node, 'end_col_offset', -1) + 1),
                                    remediation="encapsulate mutable state in a class or use module-private names (_name)",
                                ))
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name) and not node.target.id.startswith("_"):
                        if node.value and isinstance(node.value, MUTABLE_TYPES):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_INFO,
                                message=f"module-level mutable variable '{node.target.id}' creates data coupling",
                                location=Location(file=rel, line=getattr(node, "lineno", 0), end_line=getattr(node, "end_lineno", 0), end_column=getattr(node, 'end_col_offset', -1) + 1),
                                remediation="encapsulate mutable state in a class or use module-private names (_name)",
                            ))
        return findings


# ---------------------------------------------------------------------------
# COUP002 — Exported functions accepting callable parameters (control coupling)
# ---------------------------------------------------------------------------
class COUP002(Rule):
    rule_id = "COUP002"
    standard = "iso26262"
    clause = "6.4.3"
    description = "Public function accepts callable parameter — control coupling"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("_"):
                        continue
                    for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                        ann = arg.annotation
                        if ann and _is_callable_annotation(ann):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_INFO,
                                message=f"public function '{node.name}' accepts Callable parameter '{arg.arg}' — control coupling",
                                location=Location(file=rel, line=getattr(node, "lineno", 0), end_line=getattr(node, "end_lineno", 0), end_column=getattr(node, 'end_col_offset', -1) + 1),
                                remediation="document control coupling; prefer strategy objects or well-defined protocols",
                            ))
        return findings


# ---------------------------------------------------------------------------
# COUP003 — Coupling report must be present
# ---------------------------------------------------------------------------
class COUP003(Rule):
    rule_id = "COUP003"
    standard = "iso26262"
    clause = "6.4.3"
    description = "Coupling analysis report (coupling-report.json) must be present"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        report_path = os.path.join(project_root, "coupling-report.json")
        if not os.path.exists(report_path):
            return [Finding(
                rule_id=self.rule_id,
                severity=SEVERITY_WARNING,
                message="coupling-report.json not found — run 'pyfusa coupling' to generate",
                location=Location(file="coupling-report.json"),
                remediation="run 'pyfusa coupling --dir .' to generate coupling-report.json",
            )]
        return []


ALL: List[Rule] = [COUP001(), COUP002(), COUP003()]
