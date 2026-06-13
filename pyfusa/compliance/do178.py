"""DO-178C Annex A compliance gap report."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional

import pyfusa
from pyfusa.config import Config

DAL_LEVELS = ["DAL-A", "DAL-B", "DAL-C", "DAL-D"]

_OBJECTIVES = [
    # (id, table, section, description, dals_apply, evidence_file)
    ("A-1.1",  "A-1", "§4/§11.1",  "Software Planning Process: Software Development Plan",    ["DAL-A","DAL-B","DAL-C","DAL-D"], "SAFETY_PLAN.md"),
    ("A-1.2",  "A-1", "§4/§11.2",  "Software Development Standards defined",                  ["DAL-A","DAL-B","DAL-C","DAL-D"], "CONTRIBUTING.md"),
    ("A-2.1",  "A-2", "§5.1",      "Software requirements defined (HLR)",                     ["DAL-A","DAL-B","DAL-C","DAL-D"], ".fusa-reqs.json"),
    ("A-2.2",  "A-2", "§5.2",      "Software HLR comply with system requirements",             ["DAL-A","DAL-B","DAL-C"],         ".fusa-reqs.json"),
    ("A-2.3",  "A-2", "§5.3",      "Software HLR are verifiable",                              ["DAL-A","DAL-B","DAL-C"],         ".fusa-reqs.json"),
    ("A-3.1",  "A-3", "§11.9",     "Software Design Description (LLR/architecture)",           ["DAL-A","DAL-B","DAL-C"],         "boundary.json"),
    ("A-3.2",  "A-3", "§6.3",      "Data/control coupling documented",                         ["DAL-A","DAL-B","DAL-C"],         "coupling-report.json"),
    ("A-4.1",  "A-4", "§11.11",    "Source code complies with software design",                ["DAL-A","DAL-B","DAL-C","DAL-D"], "check-report.json"),
    ("A-4.2",  "A-4", "§11.11",    "Source code complies with software standards",             ["DAL-A","DAL-B","DAL-C","DAL-D"], "check-report.json"),
    ("A-5.1",  "A-5", "§6.3.3",    "Integration process: no unintended coupling",              ["DAL-A","DAL-B","DAL-C"],         "coupling-report.json"),
    ("A-6.1",  "A-6", "§6.4",      "Verification: HLR-based test cases exist",                 ["DAL-A","DAL-B","DAL-C","DAL-D"], "qualify-report.json"),
    ("A-6.2",  "A-6", "§6.4.2",    "Verification: LLR-based test cases exist",                 ["DAL-A","DAL-B","DAL-C"],         "qualify-report.json"),
    ("A-6.3",  "A-6", "§6.4.3",    "Structural coverage: statement coverage (DAL-C)",          ["DAL-A","DAL-B","DAL-C"],         "coverage-report.json"),
    ("A-6.4",  "A-6", "§6.4.4",    "Structural coverage: branch/decision coverage (DAL-B)",   ["DAL-A","DAL-B"],                 "coverage-report.json"),
    ("A-6.5",  "A-6", "§6.4.4.3",  "Structural coverage: MC/DC (DAL-A)",                      ["DAL-A"],                         "coverage-report.json"),
    ("A-7.1",  "A-7", "§7.2",      "Configuration management: all life cycle data under CM",  ["DAL-A","DAL-B","DAL-C","DAL-D"], ".gitignore"),
    ("A-7.2",  "A-7", "§7.2",      "Software Configuration Index (SCI)",                      ["DAL-A","DAL-B","DAL-C","DAL-D"], "sci.json"),
    ("A-8.1",  "A-8", "§8.1",      "Software Quality Assurance: reviews conducted",            ["DAL-A","DAL-B","DAL-C"],         "qualify-report.json"),
    ("A-9.1",  "A-9", "§9.1",      "Certification Liaison: PSAC prepared",                    ["DAL-A","DAL-B","DAL-C","DAL-D"], "sas.json"),
    ("A-10.1", "A-10","§11.20",    "Software Accomplishment Summary (SAS)",                    ["DAL-A","DAL-B","DAL-C","DAL-D"], "sas.json"),
    ("A-10.2", "A-10","§11.17",    "Problem Reports log present",                             ["DAL-A","DAL-B","DAL-C","DAL-D"], ".fusa-problems.json"),
    ("A-10.3", "A-10","§11.4",     "SBOM / software component list present",                  ["DAL-A","DAL-B","DAL-C","DAL-D"], "sbom.json"),
]


def _status(project_root: str, evidence_file: str, dal: str, dals_apply: List[str]) -> tuple:
    if dal not in dals_apply:
        return "partial", []
    path = os.path.join(project_root, evidence_file)
    if os.path.exists(path):
        return "satisfied", [evidence_file]
    return "gap", []


def run(project_root: str, cfg: Config, dal: str = "DAL-B") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    objectives = []
    counts = {"satisfied": 0, "gap": 0, "partial": 0}

    for obj_id, table, section, description, dals_apply, evidence_file in _OBJECTIVES:
        status, evidence = _status(project_root, evidence_file, dal, dals_apply)
        counts[status] = counts.get(status, 0) + 1
        obj = {
            "id": obj_id, "table": table, "section": section,
            "title": description, "dalsApply": dals_apply,
            "status": status, "evidence": evidence,
        }
        if status == "gap":
            obj["remediation"] = f"run 'pyfusa' to generate {evidence_file}"
        objectives.append(obj)

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "gap-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module, "standard": "do178c", "dal": dal,
        "summary": {"total": len(objectives), "satisfied": counts["satisfied"],
                    "partial": counts["partial"], "gaps": counts["gap"]},
        "objectives": objectives,
    }
    return doc


def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"DO-178C gap report  project={doc['project']}  dal={doc['dal']}",
        f"satisfied={s.get('satisfied',0)}  gaps={s.get('gaps',0)}  partial={s.get('partial',0)}",
        "",
    ]
    for obj in doc["objectives"]:
        marker = {"satisfied": "✓", "gap": "✗", "partial": "–"}.get(obj["status"], "?")
        lines.append(f"  {marker} {obj['id']:8s} {obj['status']:10s} {obj.get('title','')}")
        if obj.get("remediation"):
            lines.append(f"           → {obj['remediation']}")
    return "\n".join(lines)
