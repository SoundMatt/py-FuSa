"""Test evidence bundle — pyfusa verify (§9.2)."""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

import pyfusa
from pyfusa.config import Config

EVIDENCE_FILE = ".fusa-evidence.json"


def _run_pytest(project_root: str, timeout: int = 120) -> Optional[dict]:
    """Run pytest --tb=no -q -rA and parse output into test results.

    -rA ("report all") forces pytest to print a one-line summary entry
    for every test regardless of outcome. Plain -q's "short test summary
    info" section only ever lists failures/errors -- verified: a mixed
    pass/fail run under -q alone produced zero PASSED lines, so the
    per-test loop below only ever saw the FAILED entry and (since
    `results` was then non-empty) the summary-line fallback that would
    have corrected the count was skipped too, silently reporting
    summary.passed=0 for a run that actually had a passing test.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--tb=no", "-q", "--no-header", "-rA"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        return _parse_pytest_output(output, result.returncode)
    except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


# PASSED/FAILED/ERROR lines: "PASSED tests/test_foo.py::test_bar", possibly
# followed by " - <reason>" for FAILED/ERROR.
_RESULT_LINE_RE = re.compile(r"^(PASSED|FAILED|ERROR)\s+(\S+)(?:\s+-\s+.*)?$")
# SKIPPED lines carry no dotted test-node-id, only a file:line: "SKIPPED
# [1] tests/test_foo.py:12: reason".
_SKIPPED_LINE_RE = re.compile(r"^SKIPPED\s+\[\d+\]\s+(\S+):.*$")
_STATUS_MAP = {"PASSED": "pass", "FAILED": "fail", "ERROR": "error"}


def _extract_count(output: str, word: str) -> int:
    m = re.search(rf"(\d+) {word}\b", output)
    return int(m.group(1)) if m else 0


def _parse_pytest_output(output: str, returncode: int) -> dict:
    """Parse pytest -q -rA output (see _run_pytest) into a results
    structure."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        m = _RESULT_LINE_RE.match(line)
        if m:
            results.append({"name": m.group(2), "status": _STATUS_MAP[m.group(1)]})
            continue
        m = _SKIPPED_LINE_RE.match(line)
        if m:
            results.append({"name": m.group(1), "status": "skip"})

    # Aggregate counts always come from pytest's own summary line
    # ("3 passed, 1 failed, ..."), each category searched independently --
    # not by fixed position (pytest doesn't print categories in a
    # consistent order; "1 failed, 1 passed" is just as common as "1
    # passed, 1 failed") and never derived from len(results): an
    # unexpected pytest output format could make the per-test loop above
    # miss a line without the summary line also being wrong, so the
    # authoritative counts stay correct even when the detailed list isn't
    # complete.
    passed = _extract_count(output, "passed")
    failed = _extract_count(output, "failed")
    errored = _extract_count(output, "errors?")
    skipped = _extract_count(output, "skipped")

    return {
        "results": results,
        "summary": {
            "total": passed + failed + errored + skipped,
            "passed": passed,
            "failed": failed,
            "errored": errored,
            "skipped": skipped,
        },
        "exitCode": returncode,
    }


# fusa:req REQ-QUAL002
def run(project_root: str, cfg: Config, timeout: int = 120) -> dict:
    """Run tests and build the evidence bundle."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    parsed = _run_pytest(project_root, timeout=timeout)
    if parsed is None:
        summary = {"total": 0, "passed": 0, "failed": 0, "errored": 0, "skipped": 0}
        results = []
        exit_code = -1
    else:
        summary = parsed["summary"]
        results = parsed["results"]
        exit_code = parsed["exitCode"]

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "verify",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "module": module,
        "pythonVersion": platform.python_version(),
        "testRunner": "pytest",
        "exitCode": exit_code,
        "summary": summary,
        "results": results,
    }
    return doc


# fusa:req REQ-CLI009
def load(project_root: str) -> Optional[dict]:
    path = os.path.join(project_root, EVIDENCE_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


# fusa:req REQ-CLI009
def save(doc: dict, project_root: str) -> str:
    path = os.path.join(project_root, EVIDENCE_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


# fusa:req REQ-CLI009
def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"verify  module={doc.get('module', '')}  python={doc.get('pythonVersion', '')}",
        f"total={s.get('total', 0)}  passed={s.get('passed', 0)}  "
        f"failed={s.get('failed', 0)}  skipped={s.get('skipped', 0)}  "
        f"errored={s.get('errored', 0)}",
    ]
    for r in doc.get("results", [])[:20]:
        marker = {"pass": "✓", "fail": "✗", "skip": "–", "error": "E"}.get(
            r["status"], "?"
        )
        lines.append(f"  {marker} {r['name']}")
    if len(doc.get("results", [])) > 20:
        lines.append(f"  ... ({len(doc['results']) - 20} more)")
    return "\n".join(lines)
