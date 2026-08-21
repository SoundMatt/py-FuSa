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


def _dotted_name(node: ast.expr) -> str:
    """Resolve a Name or an arbitrary-depth Attribute chain to a dotted
    string, e.g. `os.environ.get` -> "os.environ.get". "" for anything
    else (a subscript, a call result, ...) -- a 2-level-only version of
    this used to make `os.environ.get(...)` (3 levels) unmatchable
    against a call-name set that explicitly lists it."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return ""


def _call_name(node: ast.Call) -> str:
    return _dotted_name(node.func)


def _scope_signal_names(scope_node, signal_names_kw: set) -> set:
    """Params + local Event()-typed assigns + bare signal-name references,
    restricted to `scope_node`'s own body -- does not descend into a
    nested function/lambda's body, since that establishes its own scope
    (used by ANA001, see below)."""
    names: set = set()
    if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for arg in scope_node.args.args + scope_node.args.kwonlyargs:
            if arg.arg in signal_names_kw:
                names.add(arg.arg)

    def walk_own_scope(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Name) and child.id in signal_names_kw:
                names.add(child.id)
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                if _call_name(child.value) in ("threading.Event", "Event"):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            names.add(t.id)
            walk_own_scope(child)

    for stmt in getattr(scope_node, "body", []):
        walk_own_scope(stmt)
    return names


def _thread_calls_with_scope(tree, call_names: set, signal_names_kw: set):
    """Yield (call_node, has_signal) for every call matching `call_names`
    in `tree`, where has_signal reflects only the enclosing function's own
    scope (module scope for top-level code) -- not the whole file."""
    results = []

    def visit(node, enclosing_scope):
        if isinstance(node, ast.Call) and _call_name(node) in call_names:
            results.append(
                (node, bool(_scope_signal_names(enclosing_scope, signal_names_kw)))
            )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child)
            else:
                visit(child, enclosing_scope)

    visit(tree, tree)  # tree (ast.Module) is the module-level pseudo-scope
    return results


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

            # For each thread/task-creation call, only the signal names
            # visible in *that call's own enclosing function* (params,
            # local Event()-typed assigns, bare signal-name references --
            # not descending into a further-nested function/lambda's own
            # body) count. A prior version collected signal_names once for
            # the whole file, so a variable named e.g. "stop" ANYWHERE in
            # the file silenced this check for every thread in the file,
            # including genuinely-unsignaled ones in unrelated functions.
            for node, has_signal in _thread_calls_with_scope(tree, ALL, SIGNALS):
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


def _is_none_guard(test: ast.expr, varname: str) -> bool:
    """`if <varname> is not None:` or a truthy `if <varname>:` check."""
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == varname
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.IsNot)
        and len(test.comparators) == 1
    ):
        comp = test.comparators[0]
        if isinstance(comp, ast.Constant) and comp.value is None:
            return True
    if isinstance(test, ast.Name) and test.id == varname:
        return True
    return False


def _unguarded_none_accesses(tree, nullable_vars: set) -> list:
    """Attribute accesses on a nullable var, excluding ones inside an
    `if <var> is not None:` (or truthy `if <var>:`) guard body for that
    same var.

    Deliberately does not (yet) recognize an early-exit guard
    (`if v is None: return` followed by unguarded use of v) -- a documented
    scope limit, not a silent gap: that pattern requires tracking whether a
    block always exits, which this single-pass check doesn't attempt.
    """
    findings: list = []

    def visit(node, guarded: frozenset) -> None:
        if isinstance(node, ast.If):
            newly_guarded = {v for v in nullable_vars if _is_none_guard(node.test, v)}
            for child in node.body:
                visit(child, guarded | newly_guarded)
            for child in node.orelse:
                visit(child, guarded)
            return
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in nullable_vars and node.value.id not in guarded:
                findings.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child, guarded)

    visit(tree, frozenset())
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
            for node in _unguarded_none_accesses(tree, nullable_vars):
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
