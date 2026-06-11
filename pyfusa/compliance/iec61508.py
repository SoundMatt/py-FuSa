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
    ("61508-1",  "7.1",   "Software safety requirements",               "SIL-1", ".fusa-reqs.json"),
    ("61508-2",  "7.2",   "Software safety validation plan",            "SIL-1", "qualify-report.json"),
    ("61508-3",  "7.3",   "Software design and development",            "SIL-1", "boundary.json"),
    ("61508-4",  "7.3.2", "Data/control coupling analysis",             "SIL-2", "coupling-report.json"),
    ("61508-5",  "7.3.3", "Software module design (FMEA)",              "SIL-2", "fmea.json"),
    ("61508-6",  "7.4",   "Software code and unit testing",             "SIL-1", "check-report.json"),
    ("61508-7",  "7.4.3", "Structural coverage: statement (SIL-1)",     "SIL-1", "coverage-report.json"),
    ("61508-8",  "7.4.3", "Structural coverage: branch (SIL-2)",        "SIL-2", "coverage-report.json"),
    ("61508-9",  "7.4.3", "Structural coverage: MC/DC (SIL-3)",         "SIL-3", "coverage-report.json"),
    ("61508-10", "7.5",   "Software integration testing",               "SIL-1", "qualify-report.json"),
    ("61508-11", "7.6",   "Software validation",                        "SIL-1", "qualify-report.json"),
    ("61508-12", "7.7",   "Functional safety assessment",               "SIL-2", "safety-case.json"),
    ("61508-13", "7.8",   "Software modification (change management)",  "SIL-1", ".fusa-problems.json"),
    ("61508-14", "7.9",   "SBOM / software component list",             "SIL-2", "sbom.json"),
    ("61508-15", "7.10",  "Software safety case",                       "SIL-2", "safety-case.json"),
]


def _status(project_root: str, evidence_file: str, sil_min: str, project_sil: str) -> tuple:
    proj_rank = _SIL_RANK.get(project_sil, 1)
    req_rank = _SIL_RANK.get(sil_min, 1)
    if proj_rank < req_rank:
        return "N/A", ""
    if os.path.exists(os.path.join(project_root, evidence_file)):
        return "PASS", evidence_file
    return "GAP", f"{evidence_file} not found"


def run(project_root: str, cfg: Config, sil: str = "SIL-2") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    objectives = []
    counts = {"PASS": 0, "GAP": 0, "N/A": 0}
    for obj_id, clause, title, sil_min, evidence_file in _OBJECTIVES:
        status, evidence = _status(project_root, evidence_file, sil_min, sil)
        counts[status] = counts.get(status, 0) + 1
        objectives.append({
            "id": obj_id, "clause": clause, "title": title,
            "silMin": sil_min, "status": status, "evidence": evidence,
            "gap": f"generate {evidence_file}" if status == "GAP" else "",
        })

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "iec61508-gap-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "project": module, "sil": sil,
        "pass": counts["PASS"], "gap": counts["GAP"], "na": counts["N/A"],
        "objectives": objectives,
    }


def render_text(doc: dict) -> str:
    lines = [
        f"IEC 61508 gap report  project={doc['project']}  SIL={doc['sil']}",
        f"PASS={doc['pass']}  GAP={doc['gap']}  N/A={doc['na']}", "",
    ]
    for obj in doc["objectives"]:
        marker = {"PASS": "✓", "GAP": "✗", "N/A": "–"}.get(obj["status"], "?")
        lines.append(f"  {marker} {obj['id']:10s} {obj['clause']:8s} {obj['status']:5s} {obj['title']}")
    return "\n".join(lines)
