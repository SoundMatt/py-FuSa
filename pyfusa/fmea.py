"""dFMEA generation (§fmea command)."""

from __future__ import annotations

import ast
import csv
import io
import os
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config


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


def _req_ids_from_comments(lines: List[str], start: int, end: int) -> List[str]:
    ids: List[str] = []
    for line in lines[start:end]:
        stripped = line.strip()
        if "#fusa:req" in stripped:
            parts = stripped.split("#fusa:req", 1)
            if len(parts) > 1:
                ids.extend(parts[1].split())
    return ids


def _derive_analysis(
    name: str, returns_none: bool, has_thread: bool, has_raise: bool, req_ids: List[str]
):
    failure_modes: List[str] = []
    effects: List[str] = []
    cyber_risks: List[str] = []

    if has_raise:
        failure_modes.append("uncaught exception / early return")
        effects.append("loss of service")
    if has_thread:
        failure_modes.append("goroutine / thread leak")
        effects.append("resource exhaustion")
        cyber_risks.append("race condition")
    if returns_none:
        failure_modes.append("silent None return")
        effects.append("caller dereferences None")
    if not failure_modes:
        failure_modes.append("unexpected return value")
        effects.append("incorrect computation")

    if has_thread or has_raise:
        severity = "high"
    elif req_ids:
        severity = "medium"
    else:
        severity = "low"

    detection = "unit testing"
    if has_thread:
        detection = "integration testing"

    return failure_modes, effects, severity, detection, cyber_risks


def _package_name(path: str, root: str) -> str:
    rel = _rel(path, root)
    return os.path.dirname(rel).replace(os.sep, ".") or "."


# fusa:req REQ-DFMEA001
def scan(project_root: str, cfg: Config) -> List[dict]:
    entries: List[dict] = []
    for path in _python_files(project_root, cfg):
        tree, lines = _parse(path)
        if tree is None:
            continue
        rel = _rel(path, project_root)
        pkg = _package_name(path, project_root)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue
            # Only public functions
            end = getattr(node, "end_lineno", getattr(node, "lineno", 0))
            start = getattr(node, "lineno", 1)
            req_ids = _req_ids_from_comments(lines, start - 1, end)
            returns_none = _returns_none(node)
            has_thread = _has_thread(node)
            has_raise = _has_raise(node)

            failure_modes, effects, severity, detection, cyber_risks = _derive_analysis(
                node.name, returns_none, has_thread, has_raise, req_ids
            )

            entries.append(
                {
                    "component": pkg,
                    "function": node.name,
                    "file": rel,
                    "line": start,
                    "failure_modes": failure_modes,
                    "effects": effects,
                    "severity": severity,
                    "detection_control": detection,
                    "requirement_ids": req_ids,
                    "cyber_risks": cyber_risks,
                }
            )
    return entries


# fusa:req REQ-DFMEA001
def to_dict(entries: List[dict], project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "fmea",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa dFMEA v1",
        "module": module,
        "entries": entries,
    }


# fusa:req REQ-DFMEA001
def to_csv(entries: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "component",
            "function",
            "file",
            "failure_modes",
            "effects",
            "severity",
            "detection_control",
            "requirement_ids",
            "cyber_risks",
        ]
    )
    for e in entries:
        w.writerow(
            [
                e["component"],
                e["function"],
                e["file"],
                "; ".join(e["failure_modes"]),
                "; ".join(e["effects"]),
                e["severity"],
                e["detection_control"],
                "; ".join(e["requirement_ids"]),
                "; ".join(e["cyber_risks"]),
            ]
        )
    return buf.getvalue()
