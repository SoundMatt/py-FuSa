"""ISO 21434 compliance gap report (automotive cybersecurity)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

CAL_LEVELS = ["CAL-1", "CAL-2", "CAL-3", "CAL-4"]
_CAL_RANK = {"CAL-1": 1, "CAL-2": 2, "CAL-3": 3, "CAL-4": 4}

_OBJECTIVES = [
    ("21434-1",  "5.4",   "Cybersecurity management",              "CAL-1", ".fusa.json"),
    ("21434-2",  "8.3",   "TARA (Threat Analysis & Risk Assessment)","CAL-1","tara.json"),
    ("21434-3",  "8.4",   "Cybersecurity goals",                   "CAL-1", ".fusa-hara.json"),
    ("21434-4",  "8.5",   "Cybersecurity requirements",            "CAL-1", ".fusa-reqs.json"),
    ("21434-5",  "9.3",   "Cybersecurity requirements for development","CAL-1","check-report.json"),
    ("21434-6",  "9.4",   "Software architectural design security review","CAL-2","boundary.json"),
    ("21434-7",  "9.5",   "Implementation (CYBER rule checks)",    "CAL-1", "check-report.json"),
    ("21434-8",  "10.1",  "Vulnerability management",              "CAL-1", "vuln.json"),
    ("21434-9",  "10.2",  "Penetration testing (evidence)",        "CAL-3", "qualify-report.json"),
    ("21434-10", "11.1",  "Cybersecurity validation",              "CAL-2", "qualify-report.json"),
    ("21434-11", "12.1",  "Production release: SBOM",              "CAL-1", "sbom.json"),
    ("21434-12", "13.1",  "Incident response plan",                "CAL-1", "SECURITY.md"),
]


def run(project_root: str, cfg: Config, cal: str = "CAL-2") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    cal_rank = _CAL_RANK.get(cal, 2)

    objectives = []
    counts = {"PASS": 0, "GAP": 0, "N/A": 0}
    for obj_id, clause, title, cal_min, evidence_file in _OBJECTIVES:
        req_rank = _CAL_RANK.get(cal_min, 1)
        if cal_rank < req_rank:
            status, evidence, gap = "N/A", "", ""
        elif os.path.exists(os.path.join(project_root, evidence_file)):
            status, evidence, gap = "PASS", evidence_file, ""
        else:
            status, evidence, gap = "GAP", "", f"generate {evidence_file}"
        counts[status] = counts.get(status, 0) + 1
        objectives.append({
            "id": obj_id, "clause": clause, "title": title,
            "calMin": cal_min, "status": status, "evidence": evidence, "gap": gap,
        })

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "iso21434-gap-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "project": module, "cal": cal,
        "pass": counts["PASS"], "gap": counts["GAP"], "na": counts["N/A"],
        "objectives": objectives,
    }


def render_text(doc: dict) -> str:
    lines = [
        f"ISO 21434 gap report  project={doc['project']}  CAL={doc['cal']}",
        f"PASS={doc['pass']}  GAP={doc['gap']}  N/A={doc['na']}", "",
    ]
    for obj in doc["objectives"]:
        marker = {"PASS": "✓", "GAP": "✗", "N/A": "–"}.get(obj["status"], "?")
        lines.append(f"  {marker} {obj['id']:10s} {obj['clause']:8s} {obj['status']:5s} {obj['title']}")
    return "\n".join(lines)
