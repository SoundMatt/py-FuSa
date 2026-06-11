"""Safety metrics tracking over time."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

import pyfusa
from pyfusa.config import Config

METRICS_FILE = ".fusa-metrics.json"


def load(project_root: str) -> dict:
    path = os.path.join(project_root, METRICS_FILE)
    if not os.path.exists(path):
        return {"project": os.path.basename(project_root), "snapshots": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, METRICS_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _load_json(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def collect(project_root: str, cfg: Config, version: str = "") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Check report
    check = _load_json(os.path.join(project_root, "check-report.json"))
    summary = check.get("summary", {}) if check else {}
    error_count = summary.get("errors", 0)
    warning_count = summary.get("warnings", 0)
    info_count = summary.get("infos", 0)

    # Requirements
    reqs = _load_json(os.path.join(project_root, ".fusa-reqs.json"))
    total_reqs = len(reqs.get("requirements", [])) if reqs else 0

    # Trace matrix
    trace = _load_json(os.path.join(project_root, "trace-matrix.json"))
    traced = 0
    tested = 0
    if trace:
        cov = trace.get("coverage", {})
        traced = cov.get("tracedRequirements", 0)
        tested = cov.get("testedRequirements", 0)

    # Coverage
    cov_report = _load_json(os.path.join(project_root, "coverage-report.json"))
    coverage_pct = cov_report.get("coveragePct", 0.0) if cov_report else 0.0

    return {
        "timestamp": now,
        "version": version or cfg.project.name or "",
        "errorCount": error_count,
        "warningCount": warning_count,
        "infoCount": info_count,
        "totalRequirements": total_reqs,
        "tracedRequirements": traced,
        "testedRequirements": tested,
        "coveragePct": coverage_pct,
        "untracedCount": max(0, total_reqs - traced),
        "annotationDensityPct": round(traced / total_reqs * 100, 1) if total_reqs > 0 else 0.0,
    }


def record(project_root: str, cfg: Config, version: str = "") -> dict:
    snapshot = collect(project_root, cfg, version)
    data = load(project_root)
    data.setdefault("snapshots", []).append(snapshot)
    save(project_root, data)
    return snapshot


def render_text(data: dict) -> str:
    snapshots = data.get("snapshots", [])
    if not snapshots:
        return "no metrics snapshots"
    lines = [f"project: {data.get('project','')}  snapshots: {len(snapshots)}", ""]
    header = f"{'timestamp':26s} {'errors':7s} {'warnings':9s} {'reqs':6s} {'traced':7s} {'cov%':6s}"
    lines.append(header)
    lines.append("-" * len(header))
    for s in snapshots[-10:]:
        lines.append(
            f"{s.get('timestamp',''):26s} {s.get('errorCount',0):7d} {s.get('warningCount',0):9d} "
            f"{s.get('totalRequirements',0):6d} {s.get('tracedRequirements',0):7d} "
            f"{s.get('coveragePct',0.0):5.1f}%"
        )
    return "\n".join(lines)
