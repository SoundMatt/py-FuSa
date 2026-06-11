"""Test evidence bundle — pyfusa verify (§9.2)."""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Optional

import pyfusa
from pyfusa.config import Config

EVIDENCE_FILE = ".fusa-evidence.json"


def _run_pytest(project_root: str, timeout: int = 120) -> Optional[dict]:
    """Run pytest --tb=no -q and parse output into test results."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--tb=no", "-q", "--no-header"],
            cwd=project_root,
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout + result.stderr
        return _parse_pytest_output(output, result.returncode)
    except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _parse_pytest_output(output: str, returncode: int) -> dict:
    """Parse pytest -q output into a results structure."""
    results = []
    # Lines like: PASSED tests/test_foo.py::test_bar
    # Or summary line: 5 passed, 1 failed, 2 errors in 0.12s
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("PASSED"):
            name = line.split(" ", 1)[1].strip() if " " in line else line
            results.append({"name": name, "status": "pass"})
        elif line.startswith("FAILED"):
            name = line.split(" ", 1)[1].strip() if " " in line else line
            results.append({"name": name, "status": "fail"})
        elif line.startswith("ERROR"):
            name = line.split(" ", 1)[1].strip() if " " in line else line
            results.append({"name": name, "status": "error"})

    # If no per-test lines, try verbose format: test_name PASSED/FAILED
    if not results:
        for line in output.splitlines():
            m = re.match(r"^(tests/\S+)\s+(PASSED|FAILED|ERROR|SKIPPED)", line)
            if m:
                status_map = {"PASSED": "pass", "FAILED": "fail", "ERROR": "error", "SKIPPED": "skip"}
                results.append({"name": m.group(1), "status": status_map[m.group(2)]})

    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] == "fail")
    errored = sum(1 for r in results if r["status"] == "error")
    skipped = sum(1 for r in results if r["status"] == "skip")

    # Parse summary line for counts when per-test lines aren't available
    summary_match = re.search(
        r"(\d+) passed(?:,\s*(\d+) failed)?(?:,\s*(\d+) error)?", output
    )
    if summary_match and not results:
        passed = int(summary_match.group(1) or 0)
        failed = int(summary_match.group(2) or 0)
        errored = int(summary_match.group(3) or 0)

    return {
        "results": results,
        "summary": {
            "total": len(results) if results else (passed + failed + errored + skipped),
            "passed": passed,
            "failed": failed,
            "errored": errored,
            "skipped": skipped,
        },
        "exitCode": returncode,
    }


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


def load(project_root: str) -> Optional[dict]:
    path = os.path.join(project_root, EVIDENCE_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save(doc: dict, project_root: str) -> str:
    path = os.path.join(project_root, EVIDENCE_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"verify  module={doc.get('module','')}  python={doc.get('pythonVersion','')}",
        f"total={s.get('total',0)}  passed={s.get('passed',0)}  "
        f"failed={s.get('failed',0)}  skipped={s.get('skipped',0)}  "
        f"errored={s.get('errored',0)}",
    ]
    for r in doc.get("results", [])[:20]:
        marker = {"pass": "✓", "fail": "✗", "skip": "–", "error": "E"}.get(r["status"], "?")
        lines.append(f"  {marker} {r['name']}")
    if len(doc.get("results", [])) > 20:
        lines.append(f"  ... ({len(doc['results'])-20} more)")
    return "\n".join(lines)
