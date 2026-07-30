"""Structural coverage analysis from pytest-cov output (§coverage)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional

import pyfusa
from pyfusa.config import Config

_DAL_THRESHOLDS = {
    "DAL-A": 100.0,  # MC/DC — approximated by 100% branch+statement
    "DAL-B": 100.0,  # branch/decision
    "DAL-C": 100.0,  # statement
    "DAL-D": 0.0,  # no structural coverage required
}

_ASIL_THRESHOLDS = {
    "ASIL-D": 100.0,  # MC/DC
    "ASIL-C": 100.0,  # branch
    "ASIL-B": 100.0,  # branch
    "ASIL-A": 80.0,  # statement
    "QM": 0.0,
}


def _run_pytest_cov(project_root: str, source: str) -> Optional[float]:
    """Run pytest --cov and extract coverage percentage."""
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--cov=" + source,
                "--cov-report=term-missing",
                "-q",
            ],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        # Look for: TOTAL   ... 87%
        m = re.search(r"^TOTAL\s+\d+\s+\d+\s+(\d+)%", output, re.MULTILINE)
        if m:
            return float(m.group(1))
    except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _read_coverage_xml(path: str) -> Optional[float]:
    """Parse coverage.xml for line-rate."""
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        m = re.search(r'line-rate="([0-9.]+)"', content)
        if m:
            return float(m.group(1)) * 100
    except OSError:
        pass
    return None


def _parse_llvm_mcdc(path: str) -> dict:  # fusa:req REQ-COV001
    """Parse LLVM MC/DC JSON export and compute per-function coverage.

    Expected structure (subset):
    {
      "data": [{
        "functions": [{
          "name": "...",
          "mcdc_records": [{"conditions": [{"covered_true_count": N, "covered_false_count": M}]}]
        }]
      }]
    }

    A condition is MC/DC covered iff covered_true_count > 0 AND covered_false_count > 0.
    Returns a dict with:
      total_conditions, covered_conditions, functions (list of function summaries),
      uncovered_functions (list of function names with uncovered conditions).
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {
            "error": str(e),
            "total_conditions": 0,
            "covered_conditions": 0,
            "functions": [],
            "uncovered_functions": [],
        }

    total_cond = 0
    covered_cond = 0
    funcs = []
    uncovered_funcs = []

    for segment in raw.get("data", []):
        for fn in segment.get("functions", []):
            fn_name = fn.get("name", "<unknown>")
            fn_total = 0
            fn_covered = 0
            for rec in fn.get("mcdc_records", []):
                for cond in rec.get("conditions", []):
                    fn_total += 1
                    if (
                        cond.get("covered_true_count", 0) > 0
                        and cond.get("covered_false_count", 0) > 0
                    ):
                        fn_covered += 1
            total_cond += fn_total
            covered_cond += fn_covered
            fn_pct = (fn_covered * 100 / fn_total) if fn_total else 100.0
            fn_entry = {
                "name": fn_name,
                "totalConditions": fn_total,
                "coveredConditions": fn_covered,
                "coveragePct": round(fn_pct, 1),
            }
            funcs.append(fn_entry)
            if fn_total > 0 and fn_covered < fn_total:
                uncovered_funcs.append(fn_name)

    return {
        "total_conditions": total_cond,
        "covered_conditions": covered_cond,
        "functions": funcs,
        "uncovered_functions": uncovered_funcs,
    }


# fusa:req REQ-COV001
def run(
    project_root: str,
    cfg: Config,
    dal: str = "",
    asil: str = "",
    mcdc: bool = False,
    mcdc_file: str = "",
    mcdc_threshold: float = 100.0,
) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    source = (cfg.source_dirs or ["pyfusa"])[0]

    # Try to read existing coverage.xml first (faster)
    cov_pct = _read_coverage_xml(os.path.join(project_root, "coverage.xml"))

    # Fall back to running pytest
    if cov_pct is None:
        cov_pct = _run_pytest_cov(project_root, source)

    if cov_pct is None:
        cov_pct = 0.0

    level = asil or dal or cfg.asil or ""
    threshold = _ASIL_THRESHOLDS.get(level, _DAL_THRESHOLDS.get(level, 0.0))
    passed = cov_pct >= threshold if threshold > 0 else True

    cov_type = "statement"
    if level in ("DAL-A", "ASIL-D"):
        cov_type = "MC/DC (approximated)"
    elif level in ("DAL-B", "ASIL-C", "ASIL-B"):
        cov_type = "branch"

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "coverage-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "module": module,
        "level": level or "unspecified",
        "coverageType": cov_type,
        "coveragePct": round(cov_pct, 1),
        "threshold": threshold,
        "passed": passed,
    }

    # Feature 3: MC/DC Coverage
    if mcdc:
        mcdc_path = mcdc_file or os.path.join(project_root, "coverage.json")
        mcdc_data = _parse_llvm_mcdc(mcdc_path)
        total_cond = mcdc_data.get("total_conditions", 0)
        covered_cond = mcdc_data.get("covered_conditions", 0)
        mcdc_pct = (covered_cond * 100 / total_cond) if total_cond else 100.0
        uncovered = mcdc_data.get("uncovered_functions", [])
        mcdc_passed = (len(uncovered) == 0) and (mcdc_pct >= mcdc_threshold)
        doc["mcdc"] = {
            "totalConditions": total_cond,
            "coveredConditions": covered_cond,
            "coveragePct": round(mcdc_pct, 1),
            "threshold": mcdc_threshold,
            "passed": mcdc_passed,
            "uncoveredFunctions": uncovered,
            "functions": mcdc_data.get("functions", []),
        }
        if mcdc_data.get("error"):
            doc["mcdc"]["error"] = mcdc_data["error"]
        # Hard gate: if any annotated function has uncovered conditions, overall fails
        if not mcdc_passed:
            doc["passed"] = False

    return doc
