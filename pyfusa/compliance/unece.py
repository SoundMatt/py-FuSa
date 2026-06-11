"""UN R.155 (UNECE) cybersecurity compliance gap report."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

_OBJECTIVES = [
    ("R155-1",  "7.2.1",  "Cybersecurity Management System (CSMS)",        ".fusa.json"),
    ("R155-2",  "7.2.2",  "TARA for production vehicle",                   "tara.json"),
    ("R155-3",  "7.2.3",  "Cybersecurity risk treatment measures",         ".fusa-reqs.json"),
    ("R155-4",  "7.2.4",  "Penetration testing / vulnerability scanning",  "vuln.json"),
    ("R155-5",  "7.2.5",  "Incident monitoring and response",              "SECURITY.md"),
    ("R155-6",  "7.3.1",  "Software update management (SBOM)",             "sbom.json"),
    ("R155-7",  "7.3.2",  "Provenance and supply chain integrity",         "provenance.json"),
    ("R155-8",  "7.3.3",  "Cryptographic protection of software updates",  "sign.key"),
    ("R155-9",  "Annex 5","Threat categories: network/remote attacks",      "tara.json"),
    ("R155-10", "Annex 5","Threat categories: physical attacks",            "tara.json"),
    ("R155-11", "Annex 5","Threat categories: software attacks",            "check-report.json"),
    ("R155-12", "Annex 5","Threat categories: unintended human actions",    ".fusa-hara.json"),
]


def run(project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    objectives = []
    counts = {"PASS": 0, "GAP": 0}
    for obj_id, clause, title, evidence_file in _OBJECTIVES:
        if os.path.exists(os.path.join(project_root, evidence_file)):
            status, evidence, gap = "PASS", evidence_file, ""
        else:
            status, evidence, gap = "GAP", "", f"generate {evidence_file}"
        counts[status] = counts.get(status, 0) + 1
        objectives.append({
            "id": obj_id, "clause": clause, "title": title,
            "status": status, "evidence": evidence, "gap": gap,
        })

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "unece-r155-gap-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "project": module,
        "pass": counts["PASS"], "gap": counts["GAP"],
        "objectives": objectives,
    }


def render_text(doc: dict) -> str:
    lines = [
        f"UN R.155 gap report  project={doc['project']}",
        f"PASS={doc['pass']}  GAP={doc['gap']}", "",
    ]
    for obj in doc["objectives"]:
        marker = "✓" if obj["status"] == "PASS" else "✗"
        lines.append(f"  {marker} {obj['id']:8s} {obj['clause']:8s} {obj['status']:5s} {obj['title']}")
    return "\n".join(lines)
