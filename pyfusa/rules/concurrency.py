"""Concurrency and thread-safety rules (CONC-series)."""

from __future__ import annotations

import ast

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule
from pyfusa.rules.lint import _parse_file, _python_files


#fusa:req REQ-CONC001
class RuleThreadWithoutLock(Rule):
    rule_id = "CONC001"
    standard = "iso26262"
    clause = "5.4.7"
    description = "Thread creation without apparent synchronization context may introduce data races."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(project_root, cfg.source_dirs, cfg.exclude_patterns):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            # Check if threading module is used
            uses_threading = any(
                (isinstance(n, ast.Import) and any(a.name == "threading" for a in n.names))
                or (isinstance(n, ast.ImportFrom) and n.module == "threading")
                for n in ast.walk(tree)
            )
            if not uses_threading:
                continue
            # Look for Thread() creation
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                is_thread = (
                    (isinstance(func, ast.Attribute) and func.attr == "Thread"
                     and isinstance(func.value, ast.Name) and func.value.id == "threading")
                    or (isinstance(func, ast.Name) and func.id == "Thread")
                )
                if is_thread:
                    findings.append(pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message="Thread created; ensure shared state is protected by threading.Lock or Queue",
                        location=pyfusa.Location(file=rel_path, line=node.lineno, end_line=getattr(node, 'end_lineno', 0), end_column=getattr(node, 'end_col_offset', -1) + 1),
                        standard="iso26262",
                        remediation="use threading.Lock(), threading.RLock(), or queue.Queue to synchronize shared state",
                    ))
        return findings


#fusa:req REQ-CONC002
class RuleGlobalMutation(Rule):
    rule_id = "CONC002"
    standard = "iso26262"
    clause = "5.4.7"
    description = "Module-level global variables are a shared-state hazard in multi-threaded code."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(project_root, cfg.source_dirs, cfg.exclude_patterns):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for child in ast.walk(node):
                    if isinstance(child, ast.Global):
                        for name in child.names:
                            findings.append(pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_WARNING,
                                message=f"'global {name}' in function '{node.name}' introduces mutable shared state",
                                location=pyfusa.Location(file=rel_path, line=child.lineno, end_line=getattr(child, 'end_lineno', 0), end_column=getattr(child, 'end_col_offset', -1) + 1),
                                standard="iso26262",
                                remediation=f"pass '{name}' as a parameter or encapsulate in a class with explicit locking",
                            ))
        return findings


#fusa:req REQ-CONC003
class RuleAsyncWithoutAwait(Rule):
    rule_id = "CONC003"
    standard = "do178c"
    clause = "6.3.4"
    description = "async functions that never await may block the event loop."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(project_root, cfg.source_dirs, cfg.exclude_patterns):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.AsyncFunctionDef):
                    continue
                has_await = any(isinstance(c, ast.Await) for c in ast.walk(node))
                if not has_await:
                    findings.append(pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_INFO,
                        message=f"async function '{node.name}' contains no await expressions",
                        location=pyfusa.Location(file=rel_path, line=node.lineno, end_line=getattr(node, 'end_lineno', 0), end_column=getattr(node, 'end_col_offset', -1) + 1),
                        remediation=f"add await expressions or remove 'async' from '{node.name}' if not needed",
                    ))
        return findings


ALL: list[Rule] = [
    RuleThreadWithoutLock(),
    RuleGlobalMutation(),
    RuleAsyncWithoutAwait(),
]
