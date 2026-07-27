"""Python coding-standard lint rules (LINT-series)."""

from __future__ import annotations

import ast
import fnmatch
import os

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule

_MAX_FUNC_LINES = 60
_MAX_FILE_LINES = 500
_MAX_NESTING = 4
_MAX_COMPLEXITY = 10


def _is_excluded(rel_path: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
        if fnmatch.fnmatch(os.path.basename(rel_path), pat):
            return True
    return False


def _python_files(
    project_root: str, source_dirs: list[str], exclude_patterns: list[str]
) -> list[tuple[str, str]]:
    """Return list of (abs_path, rel_path) for all .py files in scope."""
    result = []
    for src_dir in source_dirs:
        abs_src = os.path.normpath(os.path.join(project_root, src_dir))
        for dirpath, dirnames, filenames in os.walk(abs_src):
            # Skip hidden directories and common non-source dirs
            dirnames[:] = [
                d
                for d in dirnames
                if not d.startswith(".")
                and d not in ("__pycache__", "build", "dist", ".tox", "node_modules")
            ]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                abs_path = os.path.join(dirpath, fname)
                try:
                    rel_path = os.path.relpath(abs_path, project_root).replace(
                        "\\", "/"
                    )
                except ValueError:
                    rel_path = abs_path
                if not _is_excluded(rel_path, exclude_patterns):
                    result.append((abs_path, rel_path))
    return result


def _parse_file(abs_path: str) -> tuple[ast.Module | None, str]:
    try:
        with open(abs_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
        tree = ast.parse(source, filename=abs_path)
        return tree, source
    except (SyntaxError, OSError):
        return None, ""


def _cyclomatic_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Approximate cyclomatic complexity for a function."""
    complexity = 1
    for child in ast.walk(node):
        if isinstance(
            child,
            (
                ast.If,
                ast.While,
                ast.For,
                ast.AsyncFor,
                ast.ExceptHandler,
                ast.With,
                ast.AsyncWith,
            ),
        ):
            complexity += 1
        elif (
            isinstance(child, ast.BoolOp)
            and isinstance(child.op, ast.And)
            or isinstance(child, ast.BoolOp)
            and isinstance(child.op, ast.Or)
        ):
            complexity += len(child.values) - 1
        elif isinstance(child, ast.comprehension) or isinstance(child, ast.IfExp):
            complexity += 1
    return complexity


def _max_nesting(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Find maximum block nesting depth inside a function."""
    _BLOCK_NODES = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.ExceptHandler,
    )

    def depth(n: ast.AST, current: int) -> int:
        max_d = current
        for child in ast.iter_child_nodes(n):
            if isinstance(child, _BLOCK_NODES):
                max_d = max(max_d, depth(child, current + 1))
            else:
                max_d = max(max_d, depth(child, current))
        return max_d

    return depth(node, 0)


# fusa:req REQ-LINT001
class RuleFunctionLength(Rule):
    rule_id = "LINT001"
    standard = "do178c"
    clause = "6.3.4"
    description = f"Functions must not exceed {_MAX_FUNC_LINES} lines (excluding blank lines and comments)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not (hasattr(node, "lineno") and hasattr(node, "end_lineno")):
                    continue
                length = node.end_lineno - node.lineno + 1
                if length > _MAX_FUNC_LINES:
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message=f"function '{node.name}' is {length} lines (limit: {_MAX_FUNC_LINES})",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=node.end_lineno,
                            ),
                            remediation=f"split '{node.name}' into smaller, single-purpose functions",
                        )
                    )
        return findings


# fusa:req REQ-LINT002
class RuleFileLength(Rule):
    rule_id = "LINT002"
    standard = "do178c"
    clause = "6.3.4"
    description = f"Source files must not exceed {_MAX_FILE_LINES} lines."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            try:
                with open(abs_path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            if len(lines) > _MAX_FILE_LINES:
                findings.append(
                    pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message=f"file has {len(lines)} lines (limit: {_MAX_FILE_LINES})",
                        location=pyfusa.Location(file=rel_path, line=1),
                        remediation="split large files into focused modules",
                    )
                )
        return findings


# fusa:req REQ-LINT003
class RuleNestingDepth(Rule):
    rule_id = "LINT003"
    standard = "do178c"
    clause = "6.3.4"
    description = f"Functions must not exceed {_MAX_NESTING} levels of block nesting."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                depth = _max_nesting(node)
                if depth > _MAX_NESTING:
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message=f"function '{node.name}' has nesting depth {depth} (limit: {_MAX_NESTING})",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            remediation="extract nested blocks into helper functions to reduce cognitive complexity",
                        )
                    )
        return findings


# fusa:req REQ-LINT004
class RuleCyclomaticComplexity(Rule):
    rule_id = "LINT004"
    standard = "do178c"
    clause = "6.3.4"
    description = f"Functions must not exceed cyclomatic complexity {_MAX_COMPLEXITY}."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                cc = _cyclomatic_complexity(node)
                if cc > _MAX_COMPLEXITY:
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message=f"function '{node.name}' has cyclomatic complexity {cc} (limit: {_MAX_COMPLEXITY})",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            remediation="reduce branches or extract decision logic into separate functions",
                        )
                    )
        return findings


# fusa:req REQ-LINT005
class RuleMutableDefaultArg(Rule):
    rule_id = "LINT005"
    standard = "iso26262"
    clause = "6.4.3"
    description = "Function default arguments must not be mutable (list, dict, set)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        kind = type(default).__name__.lower()
                        findings.append(
                            pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_WARNING,
                                message=f"function '{node.name}' has mutable default argument ({kind})",
                                location=pyfusa.Location(
                                    file=rel_path,
                                    line=node.lineno,
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                remediation="use 'None' as default and create the mutable object inside the function body",
                            )
                        )
        return findings


# fusa:req REQ-LINT006
class RuleStarImport(Rule):
    rule_id = "LINT006"
    standard = "do178c"
    clause = "6.3.4"
    description = "Wildcard imports (from x import *) pollute the namespace and obscure dependencies."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        mod = node.module or "?"
                        findings.append(
                            pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_WARNING,
                                message=f"wildcard import 'from {mod} import *' obscures module interface",
                                location=pyfusa.Location(
                                    file=rel_path,
                                    line=node.lineno,
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                remediation=f"import only what is needed: 'from {mod} import Name1, Name2'",
                            )
                        )
        return findings


# fusa:req REQ-LINT007
class RuleAssertStatement(Rule):
    rule_id = "LINT007"
    standard = "iso26262"
    clause = "6.4.3"
    description = "assert statements are removed by Python -O flag and must not be used for safety checks."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message="assert statement removed by Python -O; use explicit if/raise for safety checks",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="iso26262",
                            remediation="replace 'assert cond' with 'if not cond: raise ValueError(...)' for safety-critical checks",
                        )
                    )
        return findings


ALL: list[Rule] = [
    RuleFunctionLength(),
    RuleFileLength(),
    RuleNestingDepth(),
    RuleCyclomaticComplexity(),
    RuleMutableDefaultArg(),
    RuleStarImport(),
    RuleAssertStatement(),
]
