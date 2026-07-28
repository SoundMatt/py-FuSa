"""Software Accomplishment Summary — x-FuSa spec §9.3 `sas` (DO-178C §11.20)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config
from pyfusa import content_quality

SAS_FILE = "sas.json"
SAS_MD_FILE = "sas.md"

# (item, clause, candidate evidence files) — DO-178C §11 data items relevant
# to the project's DAL. `clause` is the informal §11.<n> reference; some
# mappings (sbom/problems) are this tool's own approximation where DO-178C
# doesn't define an exact equivalent artefact.
_CHECKLIST = [
    ("Plan for Software Aspects of Certification (PSAC)", "11.1", ["SAFETY_PLAN.md", ".fusa.json"]),
    ("Software Code Standards", "11.8", ["CONTRIBUTING.md"]),
    ("Software Design Description", "11.10", ["check-report.json"]),
    ("Software Verification Results", "11.14", ["qualify-report.json", "coverage-report.json"]),
    ("Software Configuration Index", "11.16", ["sci.json"]),
    ("Software Quality Assurance Records", "11.19", ["qualify-report.json"]),
    ("Software Component List", "11.11", ["sbom.json"]),
    ("Problem Reports", "11.17", [".fusa-problems.json"]),
]


# fusa:req REQ-CLI009
def generate(project_root: str, cfg: Config, dal: str = "DAL-B") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    checklist = []
    for item, clause, files in _CHECKLIST:
        evidence = ""
        present = False
        for f in files:
            if os.path.exists(os.path.join(project_root, f)):
                present = True
                evidence = f
                break
        entry = {"item": item, "clause": clause, "present": present}
        if evidence:
            entry["evidence"] = evidence
        checklist.append(entry)

    present_count = sum(1 for c in checklist if c["present"])

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "sas",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "dal": dal,
        "checklist": checklist,
        "summary": {"total": len(checklist), "present": present_count},
    }
    existing = content_quality.load_existing_attestation(project_root, SAS_FILE)
    if existing:
        doc["attestation"] = existing
    return doc


# fusa:req REQ-CLI009
def render_text(doc: dict) -> str:
    lines = [
        f"SAS — {doc['project']}  DAL={doc['dal']}",
        f"Checklist: {doc['summary']['present']}/{doc['summary']['total']} present",
        "",
    ]
    for c in doc["checklist"]:
        marker = "✓" if c["present"] else "✗"
        lines.append(f"  {marker} [{c['clause']}] {c['item']}")
        if not c["present"]:
            lines.append("      missing")
    return "\n".join(lines)


# fusa:req REQ-CLI009
def to_markdown(doc: dict) -> str:
    """The human-readable `sas.md` companion (x-FuSa spec §9.3 `sas` MUST) —
    `sas.json` is not a replacement for it, per the existing `sas.{json,md}`
    filename convention (§1.3)."""
    lines = [
        f"# Software Accomplishment Summary — {doc['project']}",
        "",
        f"DAL: {doc['dal']}  ",
        f"Generated: {doc['generatedAt']}",
        "",
        f"**Checklist: {doc['summary']['present']}/{doc['summary']['total']} present**",
        "",
        "| Clause | Item | Present | Evidence |",
        "|---|---|---|---|",
    ]
    for c in doc["checklist"]:
        present = "yes" if c["present"] else "no"
        evidence = c.get("evidence", "")
        lines.append(f"| {c['clause']} | {c['item']} | {present} | {evidence} |")
    return "\n".join(lines)


# fusa:req REQ-QUALBASE005
def quality_findings(doc: dict) -> list:
    """§1.6/§1.6.1 content-quality baseline over checklist[].item."""
    entries = doc.get("checklist", [])
    findings = content_quality.scan_placeholder(entries, ["item"], SAS_FILE)
    findings.extend(content_quality.scan_blanket_fallback(entries, ["item"], SAS_FILE))
    return findings
