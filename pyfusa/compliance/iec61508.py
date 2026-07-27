"""IEC 61508 Parts 1-3 compliance gap report."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

SIL_LEVELS = ["SIL-1", "SIL-2", "SIL-3", "SIL-4"]
_SIL_RANK = {"SIL-1": 1, "SIL-2": 2, "SIL-3": 3, "SIL-4": 4}

_OBJECTIVES = [
    # (id, clause, title, sil_min, evidence_file)
    ("61508-1", "7.1", "Software safety requirements", "SIL-1", ".fusa-reqs.json"),
    (
        "61508-2",
        "7.2",
        "Software safety validation plan",
        "SIL-1",
        "qualify-report.json",
    ),
    ("61508-3", "7.3", "Software design and development", "SIL-1", "boundary.json"),
    (
        "61508-4",
        "7.3.2",
        "Data/control coupling analysis",
        "SIL-2",
        "coupling-report.json",
    ),
    ("61508-5", "7.3.3", "Software module design (FMEA)", "SIL-2", "fmea.json"),
    ("61508-6", "7.4", "Software code and unit testing", "SIL-1", "check-report.json"),
    (
        "61508-7",
        "7.4.3",
        "Structural coverage: statement (SIL-1)",
        "SIL-1",
        "coverage-report.json",
    ),
    (
        "61508-8",
        "7.4.3",
        "Structural coverage: branch (SIL-2)",
        "SIL-2",
        "coverage-report.json",
    ),
    (
        "61508-9",
        "7.4.3",
        "Structural coverage: MC/DC (SIL-3)",
        "SIL-3",
        "coverage-report.json",
    ),
    ("61508-10", "7.5", "Software integration testing", "SIL-1", "qualify-report.json"),
    ("61508-11", "7.6", "Software validation", "SIL-1", "qualify-report.json"),
    ("61508-12", "7.7", "Functional safety assessment", "SIL-2", "safety-case.json"),
    (
        "61508-13",
        "7.8",
        "Software modification (change management)",
        "SIL-1",
        ".fusa-problems.json",
    ),
    ("61508-14", "7.9", "SBOM / software component list", "SIL-2", "sbom.json"),
    ("61508-15", "7.10", "Software safety case", "SIL-2", "safety-case.json"),
]


def _status(
    project_root: str, evidence_file: str, sil_min: str, project_sil: str
) -> tuple:
    proj_rank = _SIL_RANK.get(project_sil, 1)
    req_rank = _SIL_RANK.get(sil_min, 1)
    if proj_rank < req_rank:
        return "partial", []
    if os.path.exists(os.path.join(project_root, evidence_file)):
        return "satisfied", [evidence_file]
    return "gap", []


def run(project_root: str, cfg: Config, sil: str = "SIL-2") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    objectives = []
    counts = {"satisfied": 0, "gap": 0, "partial": 0}
    for obj_id, clause, title, sil_min, evidence_file in _OBJECTIVES:
        status, evidence = _status(project_root, evidence_file, sil_min, sil)
        counts[status] = counts.get(status, 0) + 1
        obj = {
            "id": obj_id,
            "clause": clause,
            "title": title,
            "silMin": sil_min,
            "status": status,
            "evidence": evidence,
        }
        if status == "gap":
            obj["remediation"] = f"run 'pyfusa' to generate {evidence_file}"
        objectives.append(obj)

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "gap-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": "iec61508",
        "sil": sil,
        "summary": {
            "total": len(objectives),
            "satisfied": counts["satisfied"],
            "partial": counts["partial"],
            "gaps": counts["gap"],
        },
        "objectives": objectives,
    }
    return doc


def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"IEC 61508 gap report  project={doc['project']}  SIL={doc['sil']}",
        f"satisfied={s.get('satisfied', 0)}  gaps={s.get('gaps', 0)}  partial={s.get('partial', 0)}",
        "",
    ]
    for obj in doc["objectives"]:
        marker = {"satisfied": "✓", "gap": "✗", "partial": "–"}.get(obj["status"], "?")
        lines.append(
            f"  {marker} {obj['id']:10s} {obj['clause']:8s} {obj['status']:10s} {obj['title']}"
        )
    return "\n".join(lines)
