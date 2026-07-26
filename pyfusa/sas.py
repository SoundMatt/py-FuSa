"""Software Accomplishment Summary (DO-178C §11.20)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

_SECTIONS = [
    ("planning",      "Software Planning",            ["SAFETY_PLAN.md", ".fusa.json"]),
    ("standards",     "Software Standards",           ["CONTRIBUTING.md", ".fusa.json"]),
    ("development",   "Software Development",         ["check-report.json"]),
    ("verification",  "Software Verification",        ["qualify-report.json", "coverage-report.json"]),
    ("configuration", "Configuration Management",     [".gitignore", "sci.json"]),
    ("qa",            "Software Quality Assurance",   ["qualify-report.json"]),
    ("sbom",          "Software Component List",      ["sbom.json"]),
    ("problems",      "Problem Reports",              [".fusa-problems.json"]),
]


def generate(project_root: str, cfg: Config, dal: str = "DAL-B") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    sections = []
    for sec_id, title, files in _SECTIONS:
        present = [f for f in files if os.path.exists(os.path.join(project_root, f))]
        missing = [f for f in files if not os.path.exists(os.path.join(project_root, f))]
        sections.append({
            "id": sec_id, "title": title,
            "status": "complete" if not missing else "incomplete",
            "present": present, "missing": missing,
        })

    complete = sum(1 for s in sections if s["status"] == "complete")

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "sas",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "format": "py-FuSa SAS v1 (DO-178C §11.20)",
        "module": module, "dal": dal,
        "completeSections": complete, "totalSections": len(sections),
        "sections": sections,
    }


def render_text(doc: dict) -> str:
    lines = [
        f"SAS — {doc['module']}  DAL={doc['dal']}",
        f"Sections: {doc['completeSections']}/{doc['totalSections']} complete", "",
    ]
    for s in doc["sections"]:
        marker = "✓" if s["status"] == "complete" else "✗"
        lines.append(f"  {marker} {s['title']}")
        for f in s.get("missing", []):
            lines.append(f"      missing: {f}")
    return "\n".join(lines)
