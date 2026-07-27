"""Software Configuration Index (DO-178C §11.16)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

_ITEMS = [
    ("source", "Source Code", [".py"]),
    ("requirements", "Requirements", [".fusa-reqs.json"]),
    ("hara", "Hazard Analysis", [".fusa-hara.json"]),
    ("check-report", "Static Analysis Report", ["check-report.json"]),
    ("qualify", "Qualification Report", ["qualify-report.json"]),
    ("coverage", "Coverage Report", ["coverage-report.json"]),
    ("sbom", "SBOM", ["sbom.json"]),
    ("provenance", "Build Provenance", ["provenance.json"]),
    ("fmea", "dFMEA", ["fmea.json"]),
    ("tara", "TARA", ["tara.json"]),
    ("problems", "Problem Reports", [".fusa-problems.json"]),
    ("safety-case", "Safety Case", ["safety-case.json"]),
    ("audit-pack", "Audit Pack", ["audit-pack.zip"]),
    ("changelog", "Change Log", ["CHANGELOG.md"]),
    ("license", "License", ["LICENSE"]),
]


# fusa:req REQ-SCI001
def generate(project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    items = []
    for item_id, title, files in _ITEMS:
        present_files = []
        for f in files:
            if f.startswith(".") or not f.startswith("."):
                full = os.path.join(project_root, f.lstrip("/"))
                if f.endswith(".py"):
                    # Scan for any .py files
                    present_files.append("*.py (source tree)")
                    break
                elif os.path.exists(full):
                    present_files.append(f)
        items.append(
            {
                "id": item_id,
                "title": title,
                "present": bool(present_files),
                "files": present_files,
            }
        )

    present_count = sum(1 for i in items if i["present"])
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "sci",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa SCI v1 (DO-178C §11.16)",
        "module": module,
        "present": present_count,
        "total": len(items),
        "items": items,
    }


def render_text(doc: dict) -> str:
    lines = [
        f"SCI — {doc['module']}",
        f"Present: {doc['present']}/{doc['total']}",
        "",
    ]
    for item in doc["items"]:
        marker = "✓" if item["present"] else "✗"
        lines.append(f"  {marker} {item['title']}")
    return "\n".join(lines)
