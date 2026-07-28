"""Design FMEA (Failure Mode and Effects Analysis) — x-FuSa spec §9.2 `fmea`.

Follows IEC 60812:2018 / the AIAG & VDA FMEA Handbook (2019) shape: one entry
per public function/component, each carrying `failureMode`/`effect`/`cause`
derived heuristically from the function's actual signature/behaviour (return
type, exception paths, threading calls — see §1.6.1 rule B: these MUST vary
with the item, never one fixed string for every entry).
"""

from __future__ import annotations

import ast
import csv
import io
import os
from datetime import datetime, timezone
from typing import List, Tuple

import pyfusa
from pyfusa.config import Config
from pyfusa import content_quality

FMEA_FILE = "fmea.json"

# §9.2 fmea — this project has no numeric occurrence/detection scale, so
# ratingScale/occurrence/detection/rpn (all MAY) are omitted; severity stays
# the textual "high"|"medium"|"low" form the spec explicitly allows in place
# of a 1-10 numeric scale.
_ACTION_PRIORITY = {"high": "high", "medium": "medium", "low": "low"}


def _python_files(root: str, cfg: Config) -> List[str]:
    source_dirs = cfg.source_dirs or ["."]
    paths: List[str] = []
    skip = {"__pycache__", ".git", ".tox", "venv", ".venv", "dist", "build"}
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


def _has_raise(node) -> bool:
    return any(isinstance(n, ast.Raise) for n in ast.walk(node))


def _has_thread(node) -> bool:
    THREAD = {
        "Thread",
        "threading.Thread",
        "asyncio.create_task",
        "asyncio.ensure_future",
    }
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            fn = n.func
            if isinstance(fn, ast.Name) and fn.id in THREAD:
                return True
            if (
                isinstance(fn, ast.Attribute)
                and f"{getattr(fn.value, 'id', '')}.{fn.attr}" in THREAD
            ):
                return True
    return False


def _returns_none(node) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Return) and (
            n.value is None
            or isinstance(n.value, ast.Constant)
            and n.value.value is None
        ):
            return True
    return False


def _has_args(node) -> bool:
    args = node.args
    return bool(args.args or args.kwonlyargs or args.vararg or args.kwarg)


def _req_ids_from_comments(lines: List[str], start: int, end: int) -> List[str]:
    ids: List[str] = []
    for line in lines[start:end]:
        stripped = line.strip()
        if "#fusa:req" in stripped:
            parts = stripped.split("#fusa:req", 1)
            if len(parts) > 1:
                ids.extend(parts[1].split())
    return ids


# fusa:req REQ-DFMEA006
def _derive_analysis(
    returns_none: bool,
    has_thread: bool,
    has_raise: bool,
    has_args: bool,
    req_ids: List[str],
) -> Tuple[str, str, str, str, List[str]]:
    """Heuristic derivation of failureMode/effect/cause/severity/mitigations
    from a function's actual shape (§1.6.1 rule B: this MUST vary across
    distinct input shapes, not emit one fixed string for every entry)."""
    modes: List[str] = []
    effects: List[str] = []
    causes: List[str] = []
    mitigations: List[str] = []

    if has_raise:
        modes.append("uncaught exception propagates to caller")
        effects.append("loss of service for the calling component")
        causes.append("an unhandled error path inside the function body")
        mitigations.append("add explicit exception handling at the call site")
    if has_thread:
        modes.append("background thread/task leaked or left unjoined")
        effects.append("resource exhaustion under sustained load")
        causes.append("a spawned thread/task with no lifecycle management")
        mitigations.append("add explicit join()/cancellation and lifecycle tests")
    if returns_none:
        modes.append("silent None return on the failure path")
        effects.append("caller dereferences None and crashes downstream")
        causes.append("a failure path that returns None instead of raising")
        mitigations.append("check the return value for None before use")
    if has_args:
        modes.append("invalid/out-of-range argument accepted without validation")
        effects.append("incorrect computation propagates silently")
        causes.append("no input validation on the function's parameters")
        mitigations.append("add parameter validation and a boundary-value test")
    if not modes:
        modes.append("unexpected return value for an untested input")
        effects.append("incorrect computation with no observable symptom")
        causes.append("no branching logic requiring dedicated failure handling")
        mitigations.append("add unit test coverage for this function")

    if has_thread or has_raise:
        severity = "high"
    elif req_ids:
        severity = "medium"
    else:
        severity = "low"

    return (
        "; ".join(modes),
        "; ".join(effects),
        "; ".join(causes),
        severity,
        mitigations,
    )


def _item_id(component: str, function: str) -> str:
    # x-FuSa spec §9.2 single-field identity: "Component.Function"
    return f"{component}.{function}" if component and component != "." else function


def _package_name(path: str, root: str) -> str:
    rel = _rel(path, root)
    return os.path.dirname(rel).replace(os.sep, ".") or "."


def _is_public(name: str) -> bool:
    return not name.startswith("_")


# fusa:req REQ-DFMEA001
def scan(project_root: str, cfg: Config) -> List[dict]:
    """Analyze every public module-level function and class method under
    `cfg.source_dirs`. Traversal is intentionally restricted to module-level
    + class-body methods (not arbitrarily-nested inner functions) so that
    `summary.componentsInProject` uses the *same denominator* as
    `trace --func-coverage` (§9.2 fmea, §1.4.1.2) rather than a different,
    incompatible count."""
    entries: List[dict] = []
    counter = 0
    for path in _python_files(project_root, cfg):
        tree, lines = _parse(path)
        if tree is None:
            continue
        rel = _rel(path, project_root)
        pkg = _package_name(path, project_root)

        candidates: List[Tuple[ast.AST, bool]] = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                candidates.append((node, False))
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        candidates.append((child, True))

        for node, _is_method in candidates:
            if not _is_public(node.name):
                continue
            counter += 1
            start = getattr(node, "lineno", 1)
            end = getattr(node, "end_lineno", start)
            req_ids = _req_ids_from_comments(lines, start - 1, end)
            returns_none = _returns_none(node)
            has_thread = _has_thread(node)
            has_raise = _has_raise(node)
            has_args = _has_args(node)

            mode, effect, cause, severity, mitigations = _derive_analysis(
                returns_none, has_thread, has_raise, has_args, req_ids
            )

            entries.append(
                {
                    "id": f"FMEA-{counter:03d}",
                    "component": pkg,
                    "function": node.name,
                    "item": _item_id(pkg, node.name),
                    "file": rel,
                    "line": start,
                    "failureMode": mode,
                    "effect": effect,
                    "cause": cause,
                    "severity": severity,
                    "actionPriority": _ACTION_PRIORITY.get(severity, "low"),
                    "mitigations": mitigations,
                    "requirementIds": req_ids,
                }
            )
    return entries


# fusa:req REQ-DFMEA006
def _coverage(project_root: str, cfg: Config, analyzed: int) -> dict:
    from pyfusa import trace as _trace

    _tagged, total_public = _trace.compute_func_coverage(project_root, cfg)
    pct = round(100.0 * analyzed / total_public, 1) if total_public else 100.0
    return {
        "componentsAnalyzed": analyzed,
        "componentsInProject": total_public,
        "coveragePct": pct,
        "componentInventoryMethod": (
            "public (non-underscore-prefixed) module-level functions and "
            "class methods under sourceDirs, excluding the test tree — the "
            "same count trace --func-coverage uses (§1.4.1.2)"
        ),
    }


# fusa:req REQ-DFMEA001
def to_dict(entries: List[dict], project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    high_priority = sum(1 for e in entries if e.get("actionPriority") == "high")
    summary = {"total": len(entries), "highPriority": high_priority}
    summary.update(_coverage(project_root, cfg, len(entries)))

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "fmea-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": cfg.standard,
        "entries": entries,
        "summary": summary,
    }
    existing = content_quality.load_existing_attestation(project_root, FMEA_FILE)
    if existing:
        doc["attestation"] = existing
    return doc


# fusa:req REQ-DFMEA001
def to_csv(entries: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "item",
            "file",
            "failureMode",
            "effect",
            "cause",
            "severity",
            "actionPriority",
            "mitigations",
            "requirementIds",
        ]
    )
    for e in entries:
        w.writerow(
            [
                e["id"],
                e["item"],
                e["file"],
                e["failureMode"],
                e["effect"],
                e.get("cause", ""),
                e["severity"],
                e.get("actionPriority", ""),
                "; ".join(e.get("mitigations", [])),
                "; ".join(e["requirementIds"]),
            ]
        )
    return buf.getvalue()


# fusa:req REQ-QUALBASE005
def quality_findings(doc: dict) -> List[pyfusa.Finding]:
    """§1.6/§1.6.1 content-quality baseline over this document's own qualitative
    fields (failureMode/effect/cause), run against the just-generated doc
    (not a stale copy on disk)."""
    entries = doc.get("entries", [])
    fields = ["failureMode", "effect", "cause"]
    findings = content_quality.scan_placeholder(entries, fields, FMEA_FILE)
    findings.extend(content_quality.scan_blanket_fallback(entries, fields, FMEA_FILE))
    return findings
