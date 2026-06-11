"""Software Problem Reports (DO-178C §11.17)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

PR_FILE = ".fusa-problems.json"

PHASES = ["planning", "development", "verification", "integration", "operation"]
SEVERITIES = ["critical", "major", "minor"]
STATUSES = ["open", "in-work", "closed", "deferred"]


def load(project_root: str) -> dict:
    path = os.path.join(project_root, PR_FILE)
    if not os.path.exists(path):
        return {"project": os.path.basename(project_root), "reports": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, PR_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def add(project_root: str, title: str, description: str,
        phase_found: str = "development",
        severity: str = "minor",
        status: str = "open",
        resolution: str = "") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = load(project_root)
    reports = data.get("reports", [])
    pr_id = f"PR-{len(reports) + 1:03d}"
    entry = {
        "id": pr_id,
        "title": title,
        "description": description,
        "phaseFound": phase_found,
        "phaseFixed": "",
        "severity": severity,
        "status": status,
        "created": now,
        "updated": now,
        "resolution": resolution,
    }
    reports.append(entry)
    data["reports"] = reports
    save(project_root, data)
    return entry


def list_all(project_root: str, status_filter: Optional[str] = None) -> List[dict]:
    data = load(project_root)
    reports = data.get("reports", [])
    if status_filter:
        reports = [r for r in reports if r.get("status") == status_filter]
    return reports


def render_text(reports: List[dict]) -> str:
    if not reports:
        return "no problem reports"
    lines = []
    for r in reports:
        lines.append(f"{r['id']}  [{r['status'].upper()}]  {r['severity']}  {r['title']}")
        if r.get("description"):
            lines.append(f"    {r['description'][:120]}")
    return "\n".join(lines)
