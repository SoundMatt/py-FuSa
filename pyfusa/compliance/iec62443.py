"""IEC 62443 IACS cybersecurity compliance gap report."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

SL_LEVELS = ["SL-1", "SL-2", "SL-3", "SL-4"]
_SL_RANK = {"SL-1": 1, "SL-2": 2, "SL-3": 3, "SL-4": 4}

_OBJECTIVES = [
    (
        "62443-1",
        "2-1 §4.3",
        "Security management policy",
        "SL-1",
        ".fusa-iec62443.json",
    ),
    ("62443-2", "2-3 §4.3", "Patch and vulnerability management", "SL-1", "vuln.json"),
    (
        "62443-3",
        "3-2 §9.4",
        "Cybersecurity risk assessment (TARA)",
        "SL-1",
        "tara.json",
    ),
    ("62443-4", "3-3 SR1", "System security requirements", "SL-2", "check-report.json"),
    (
        "62443-5",
        "4-1 §8.1",
        "Secure development lifecycle (SDL policy)",
        "SL-1",
        ".fusa.json",
    ),
    (
        "62443-6",
        "4-1 §8.2",
        "Security requirements specification",
        "SL-1",
        ".fusa-reqs.json",
    ),
    (
        "62443-7",
        "4-1 §8.4",
        "Secure design (component boundary diagram)",
        "SL-2",
        "boundary.json",
    ),
    (
        "62443-8",
        "4-2 CR6.2",
        "Security policy document (SECURITY.md)",
        "SL-1",
        "SECURITY.md",
    ),
    (
        "62443-9",
        "4-2 CR6.2.1",
        "Cyber incident response plan",
        "SL-2",
        "INCIDENT-RESPONSE.md",
    ),
    ("62443-10", "4-1 §8.6", "Supply-chain integrity (SBOM)", "SL-2", "sbom.json"),
    (
        "62443-11",
        "4-1 §8.8",
        "Tool qualification evidence",
        "SL-3",
        "qualify-report.json",
    ),
    ("62443-12", "4-1 §8.9", "Evidence bundle (audit pack)", "SL-3", "audit-pack.zip"),
]


# fusa:req REQ-COMPLY001
def run(project_root: str, cfg: Config, sl: str = "SL-2") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    sl_rank = _SL_RANK.get(sl, 2)

    objectives = []
    counts: dict[str, int] = {"satisfied": 0, "gap": 0, "partial": 0}
    for obj_id, clause, title, sl_min, evidence_file in _OBJECTIVES:
        req_rank = _SL_RANK.get(sl_min, 1)
        if sl_rank < req_rank:
            status, evidence = "partial", []
        elif os.path.exists(os.path.join(project_root, evidence_file)):
            status, evidence = "satisfied", [evidence_file]
        else:
            status, evidence = "gap", []
        counts[status] = counts.get(status, 0) + 1
        obj = {
            "id": obj_id,
            "clause": clause,
            "title": title,
            "slMin": sl_min,
            "status": status,
            "evidence": evidence,
        }
        if status == "gap":
            obj["remediation"] = f"run 'pyfusa' to generate {evidence_file}"
        objectives.append(obj)

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "gap-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": "iec62443",
        "sl": sl,
        "summary": {
            "total": len(objectives),
            "satisfied": counts["satisfied"],
            "partial": counts["partial"],
            "gaps": counts["gap"],
        },
        "objectives": objectives,
    }


# fusa:req REQ-COMPLY001
def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"IEC 62443 gap report  project={doc['project']}  SL={doc['sl']}",
        f"satisfied={s.get('satisfied', 0)}  gaps={s.get('gaps', 0)}  partial={s.get('partial', 0)}",
        "",
    ]
    for obj in doc["objectives"]:
        marker = {"satisfied": "✓", "gap": "✗", "partial": "–"}.get(obj["status"], "?")
        lines.append(
            f"  {marker} {obj['id']:10s} {obj['clause']:15s} {obj['status']:10s} {obj['title']}"
        )
    return "\n".join(lines)
