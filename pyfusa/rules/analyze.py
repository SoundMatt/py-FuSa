"""ANA001-009: Static analysis rules (Python AST-based)."""

from __future__ import annotations

import ast
import os
from typing import List

from pyfusa import SEVERITY_WARNING, Finding, Location
from pyfusa.config import Config
from pyfusa.rules import Rule


def _python_files(root: str, cfg: Config) -> List[str]:
    source_dirs = cfg.source_dirs or ["."]
    paths: List[str] = []
    skip = {
        "__pycache__",
        ".git",
        ".tox",
        "venv",
        ".venv",
        "node_modules",
        "dist",
        "build",
    }
    for sdir in source_dirs:
        base = os.path.join(root, sdir)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [
                d for d in dirnames if d not in skip and not d.startswith(".")
            ]
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
        return ast.parse(src, filename=path), src.splitlines()
    except SyntaxError:
        return None, []


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
    return ""


# fusa:req REQ-ANA009
class _DeadCodeVisitor(ast.NodeVisitor):
    """Find unreachable statements after return/raise/break/continue."""

    def __init__(self):
        self.dead: List[ast.stmt] = []

    def _check_body(self, stmts):
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                if i + 1 < len(stmts):
                    next_stmt = stmts[i + 1]
                    if not isinstance(
                        next_stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ):
                        self.dead.append(next_stmt)
                break

    def visit_FunctionDef(self, node):
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_If(self, node):
        self._check_body(node.body)
        if node.orelse:
            self._check_body(node.orelse)
        self.generic_visit(node)

    def visit_For(self, node):
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_While(self, node):
        self._check_body(node.body)
        self.generic_visit(node)


# fusa:req REQ-ANA003
class _SleepInThreadVisitor(ast.NodeVisitor):
    """Find time.sleep() calls inside thread worker functions (target=...)."""

    def __init__(self):
        self.hits: List[ast.Call] = []
        self._in_thread_target = False

    def visit_Call(self, node):
        name = _call_name(node)
        if name in ("threading.Thread", "Thread"):
            for kw in node.keywords:
                if kw.arg == "target" and isinstance(kw.value, ast.Lambda):
                    # lambda body
                    for n in ast.walk(kw.value.body):
                        if isinstance(n, ast.Call) and _call_name(n) in (
                            "time.sleep",
                            "sleep",
                        ):
                            self.hits.append(n)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# ANA001 — thread/task creation without termination signal
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA001
class ANA001(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA001"
    description = "Thread or task created without a stop/done event signal"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        THREAD_CALLS = {"threading.Thread", "Thread"}
        TASK_CALLS = {
            "asyncio.create_task",
            "asyncio.ensure_future",
            "loop.create_task",
        }
        ALL = THREAD_CALLS | TASK_CALLS
        SIGNALS = {
            "Event",
            "threading.Event",
            "Condition",
            "BoundedSemaphore",
            "stop",
            "done",
            "quit",
            "shutdown",
            "cancel",
        }

        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            # Collect names that look like signals
            signal_names: set = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and node.id in SIGNALS:
                    signal_names.add(node.id)
                if isinstance(node, ast.Assign):
                    if isinstance(node.value, ast.Call):
                        if _call_name(node.value) in ("threading.Event", "Event"):
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    signal_names.add(t.id)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_name(node) in ALL:
                    # Check if any sibling/ancestor scope has a signal var
                    has_signal = bool(signal_names)
                    if not has_signal:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_WARNING,
                                message="thread/task created without apparent stop-event signal",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                remediation="create a threading.Event() and pass it to the worker; check it in the loop",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# ANA002 — thread/task creation inside a loop
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA002
class ANA002(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA002"
    description = "Thread or task spawned inside a loop without concurrency bound"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        THREAD_CALLS = {
            "threading.Thread",
            "Thread",
            "asyncio.create_task",
            "asyncio.ensure_future",
            "concurrent.futures.submit",
            "executor.submit",
        }

        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)

            for node in ast.walk(tree):
                if isinstance(node, (ast.For, ast.While)):
                    for child in ast.walk(node):
                        if child is node:
                            continue
                        if (
                            isinstance(child, ast.Call)
                            and _call_name(child) in THREAD_CALLS
                        ):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message="thread/task created inside loop — may cause unbounded concurrency",
                                    location=Location(
                                        file=rel,
                                        line=getattr(child, "lineno", 0),
                                        end_line=getattr(child, "end_lineno", 0),
                                        end_column=getattr(child, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    remediation="use a thread pool (ThreadPoolExecutor) with a max_workers bound",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# ANA003 — time.sleep inside thread worker
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA003
class ANA003(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA003"
    description = "time.sleep() inside thread worker cannot be interrupted"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            v = _SleepInThreadVisitor()
            v.visit(tree)
            for node in v.hits:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=SEVERITY_WARNING,
                        message="time.sleep() inside thread target cannot be interrupted; use Event.wait(timeout)",
                        location=Location(
                            file=rel,
                            line=getattr(node, "lineno", 0),
                            end_line=getattr(node, "end_lineno", 0),
                            end_column=getattr(node, "end_col_offset", -1) + 1,
                        ),
                        remediation="replace time.sleep(t) with stop_event.wait(timeout=t)",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# ANA004 — resource cleanup in finally block that itself raises
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA004
class ANA004(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA004"
    description = "except/finally block that may raise swallows original exception"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Try):
                    for stmt in node.finalbody if hasattr(node, "finalbody") else []:
                        if isinstance(stmt, ast.Raise):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message="raise inside finally block will swallow original exception",
                                    location=Location(
                                        file=rel,
                                        line=getattr(stmt, "lineno", 0),
                                        end_line=getattr(stmt, "end_lineno", 0),
                                        end_column=getattr(stmt, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    remediation="avoid raising in finally; use contextlib.suppress or re-raise explicitly",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# ANA005 — re-fetching context/config inside function that already has it
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA005
class ANA005(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA005"
    description = "Redundant global/config lookup inside a function that accepts it as a parameter"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        GLOBAL_FETCHERS = {
            "os.environ.get",
            "os.getenv",
            "config.get",
            "settings.get",
            "getattr",
            "os.environ",
        }
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                param_names = {
                    a.arg
                    for a in node.args.args
                    + node.args.posonlyargs
                    + node.args.kwonlyargs
                }
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        name = _call_name(child)
                        if name in GLOBAL_FETCHERS:
                            # Check if a param with similar name exists
                            if child.args:
                                key = ""
                                if isinstance(child.args[0], ast.Constant):
                                    key = (
                                        str(child.args[0].value)
                                        .lower()
                                        .replace("-", "_")
                                    )
                                for p in param_names:
                                    if p.lower() == key or key.endswith(p.lower()):
                                        findings.append(
                                            Finding(
                                                rule_id=self.rule_id,
                                                severity=SEVERITY_WARNING,
                                                message=f"'{name}' call may duplicate parameter '{p}' — prefer passing values explicitly",
                                                location=Location(
                                                    file=rel,
                                                    line=getattr(child, "lineno", 0),
                                                    end_line=getattr(
                                                        child, "end_lineno", 0
                                                    ),
                                                    end_column=getattr(
                                                        child, "end_col_offset", -1
                                                    )
                                                    + 1,
                                                ),
                                                remediation="pass the value as a parameter rather than fetching from global state",
                                            )
                                        )
                                        break
        return findings


# ---------------------------------------------------------------------------
# ANA006 — unchecked return value (None check omitted)
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA006
class ANA006(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA006"
    description = "Return value of function call discarded without inspection"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        # Focus on common patterns where discarding is unsafe
        findings: List[Finding] = []
        MUST_CHECK = {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "os.rename",
            "os.remove",
            "os.unlink",
            "shutil.copy",
            "shutil.move",
            "shutil.rmtree",
        }
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    name = _call_name(node.value)
                    if name in MUST_CHECK:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_WARNING,
                                message=f"return value of '{name}' discarded — check for errors",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                remediation=f"assign result = {name}(...) and inspect return code or exceptions",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# ANA007 — potential None dereference
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA007
class ANA007(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA007"
    description = (
        "Potential None dereference: attribute access on value that may be None"
    )

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            nullable_vars: set = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    name = _call_name(node.value)
                    if any(
                        name.endswith(s)
                        for s in (".get", ".find", ".search", ".match", ".pop")
                    ):
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                nullable_vars.add(t.id)
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    if node.value.id in nullable_vars:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_WARNING,
                                message=f"'{node.value.id}' may be None; attribute access '.{node.attr}' is unsafe",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                remediation=f"guard with 'if {node.value.id} is not None:' before accessing attributes",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# ANA008 — mutable shared state modified in thread context
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA008
class ANA008(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA008"
    description = "Mutable variable from enclosing scope modified inside thread worker"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        THREAD_CALLS = {"threading.Thread", "Thread"}
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            # target=worker (a Name referencing a function defined in this
            # same file) is the realistic pattern -- a prior version only
            # ever inspected an inline `target=lambda: ...`, so this branch
            # was effectively dead: `global` inside a lambda body is a
            # SyntaxError, so no valid Python file could ever trigger it.
            functions_by_name = {
                n.name: n
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _call_name(node) in THREAD_CALLS:
                    for kw in node.keywords:
                        if kw.arg != "target":
                            continue
                        body_node = None
                        if isinstance(kw.value, ast.Lambda):
                            body_node = kw.value
                        elif isinstance(kw.value, ast.Name):
                            body_node = functions_by_name.get(kw.value.id)
                        if body_node is None:
                            continue
                        if any(
                            isinstance(child, ast.Global)
                            for child in ast.walk(body_node)
                        ):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message="thread target modifies shared mutable state via 'global' — use a Lock",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(
                                            node, "end_col_offset", -1
                                        )
                                        + 1,
                                    ),
                                    remediation="protect shared mutable state with threading.Lock()",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# ANA009 — dead code (unreachable after return/raise/break/continue)
# ---------------------------------------------------------------------------
# fusa:req REQ-ANA009
class ANA009(Rule):
    standard = "iso26262"
    clause = "6.4.3"
    rule_id = "ANA009"
    description = "Unreachable code detected after return/raise/break/continue"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            v = _DeadCodeVisitor()
            v.visit(tree)
            for node in v.dead:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=SEVERITY_WARNING,
                        message="unreachable code after return/raise/break/continue",
                        location=Location(
                            file=rel,
                            line=getattr(node, "lineno", 0),
                            end_line=getattr(node, "end_lineno", 0),
                            end_column=getattr(node, "end_col_offset", -1) + 1,
                        ),
                        remediation="remove dead code or restructure control flow",
                    )
                )
        return findings


ALL: List[Rule] = [
    ANA001(),
    ANA002(),
    ANA003(),
    ANA004(),
    ANA005(),
    ANA006(),
    ANA007(),
    ANA008(),
    ANA009(),
]
