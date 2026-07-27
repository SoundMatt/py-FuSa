"""ISO 26262 Part 6 compliance gap report."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

ASIL_LEVELS = ["QM", "ASIL-A", "ASIL-B", "ASIL-C", "ASIL-D"]

_OBJECTIVES = [
    # (id, clause, title, asil_min, evidence_file)
    (
        "26262-6-1",
        "6.4.1",
        "Software requirements specification",
        "QM",
        ".fusa-reqs.json",
    ),
    (
        "26262-6-2",
        "6.4.2",
        "Software safety requirements allocation",
        "ASIL-A",
        ".fusa-reqs.json",
    ),
    ("26262-6-3", "6.4.3", "Software architectural design", "QM", "boundary.json"),
    (
        "26262-6-4",
        "6.4.3",
        "Data and control coupling analysis",
        "ASIL-B",
        "coupling-report.json",
    ),
    ("26262-6-5", "6.4.4", "Software unit design", "QM", "check-report.json"),
    (
        "26262-6-6",
        "6.4.4",
        "Formal notation for ASIL-D unit design",
        "ASIL-D",
        "check-report.json",
    ),
    ("26262-6-7", "6.4.5", "Software unit verification", "QM", "qualify-report.json"),
    (
        "26262-6-8",
        "6.4.5",
        "Structural coverage ≥ statement (ASIL-A)",
        "ASIL-A",
        "coverage-report.json",
    ),
    (
        "26262-6-9",
        "6.4.5",
        "Structural coverage: branch/decision (ASIL-B)",
        "ASIL-B",
        "coverage-report.json",
    ),
    (
        "26262-6-10",
        "6.4.5",
        "Structural coverage: MC/DC (ASIL-D)",
        "ASIL-D",
        "coverage-report.json",
    ),
    (
        "26262-6-11",
        "6.4.6",
        "Software integration testing",
        "QM",
        "qualify-report.json",
    ),
    (
        "26262-6-12",
        "6.4.7",
        "Verification of software architectural design",
        "ASIL-A",
        "boundary.json",
    ),
    ("26262-6-13", "6.4.8", "Software HARA review", "QM", ".fusa-hara.json"),
    ("26262-6-14", "6.4.9", "Requirements-based testing", "QM", "qualify-report.json"),
    ("26262-6-15", "6.4.11", "SBOM / software component list", "ASIL-B", "sbom.json"),
    ("26262-6-16", "6.4.12", "Software safety case", "ASIL-A", "safety-case.json"),
    (
        "26262-6-17",
        "6.4.13",
        "Problem reports / change management",
        "QM",
        ".fusa-problems.json",
    ),
    ("26262-6-18", "6.4.14", "dFMEA for software units", "ASIL-B", "fmea.json"),
    ("26262-6-19", "6.4.14", "TARA cybersecurity analysis", "ASIL-B", "tara.json"),
    (
        "26262-6-20",
        "6.4.15",
        "Software release (provenance/SBOM)",
        "ASIL-A",
        "provenance.json",
    ),
]

_ASIL_RANK = {"QM": 0, "ASIL-A": 1, "ASIL-B": 2, "ASIL-C": 3, "ASIL-D": 4}


def _status(
    project_root: str, evidence_file: str, asil_min: str, project_asil: str
) -> tuple:
    proj_rank = _ASIL_RANK.get(project_asil, 2)
    req_rank = _ASIL_RANK.get(asil_min, 0)
    if proj_rank < req_rank:
        return "partial", []
    path = os.path.join(project_root, evidence_file)
    if os.path.exists(path):
        return "satisfied", [evidence_file]
    return "gap", []


def run(project_root: str, cfg: Config, asil: str = "ASIL-B") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    project_asil = asil or cfg.asil or "ASIL-B"

    objectives = []
    counts = {"satisfied": 0, "gap": 0, "partial": 0}

    for obj_id, clause, title, asil_min, evidence_file in _OBJECTIVES:
        status, evidence = _status(project_root, evidence_file, asil_min, project_asil)
        counts[status] = counts.get(status, 0) + 1
        obj = {
            "id": obj_id,
            "clause": clause,
            "title": title,
            "asilMin": asil_min,
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
        "standard": "iso26262",
        "asil": project_asil,
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
        f"ISO 26262 gap report  project={doc['project']}  ASIL={doc['asil']}",
        f"satisfied={s.get('satisfied', 0)}  gaps={s.get('gaps', 0)}  partial={s.get('partial', 0)}",
        "",
    ]
    for obj in doc["objectives"]:
        marker = {"satisfied": "✓", "gap": "✗", "partial": "–"}.get(obj["status"], "?")
        lines.append(
            f"  {marker} {obj['id']:12s} {obj['clause']:10s} {obj['status']:10s} {obj['title']}"
        )
        if obj.get("remediation"):
            lines.append(f"              → {obj['remediation']}")
    return "\n".join(lines)
