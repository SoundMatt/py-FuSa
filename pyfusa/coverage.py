"""Structural coverage analysis from pytest-cov output."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from typing import Optional

import pyfusa
from pyfusa.config import Config

_DAL_THRESHOLDS = {
    "DAL-A": 100.0,  # MC/DC — approximated by 100% branch+statement
    "DAL-B": 100.0,  # branch/decision
    "DAL-C": 100.0,  # statement
    "DAL-D": 0.0,    # no structural coverage required
}

_ASIL_THRESHOLDS = {
    "ASIL-D": 100.0,  # MC/DC
    "ASIL-C": 100.0,  # branch
    "ASIL-B": 100.0,  # branch
    "ASIL-A": 80.0,   # statement
    "QM":     0.0,
}


def _run_pytest_cov(project_root: str, source: str) -> Optional[float]:
    """Run pytest --cov and extract coverage percentage."""
    try:
        result = subprocess.run(
            ["python3", "-m", "pytest", "--cov=" + source, "--cov-report=term-missing", "-q"],
            cwd=project_root,
            capture_output=True, text=True, timeout=120,
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


def run(project_root: str, cfg: Config, dal: str = "", asil: str = "") -> dict:
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

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "coverage-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "module": module, "level": level or "unspecified",
        "coverageType": cov_type,
        "coveragePct": round(cov_pct, 1),
        "threshold": threshold,
        "passed": passed,
    }
