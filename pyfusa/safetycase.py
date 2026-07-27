"""Safety Case assembly."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

_EVIDENCE_ITEMS = [
    ("check", "check-report.json", "Static analysis findings"),
    ("reqs", ".fusa-reqs.json", "Requirements traceability"),
    ("qualify", "qualify-report.json", "Tool qualification results"),
    ("sbom", "sbom.json", "Software Bill of Materials"),
    ("provenance", "provenance.json", "Build provenance"),
    ("hara", ".fusa-hara.json", "Hazard Analysis and Risk Assessment"),
    ("tara", "tara.json", "Threat Analysis and Risk Assessment"),
    ("fmea", "fmea.json", "Failure Mode and Effects Analysis"),
    ("boundary", "boundary.json", "Component boundary diagram"),
    ("coupling", "coupling-report.json", "Coupling analysis"),
    ("audit-pack", "audit-pack.zip", "Evidence bundle"),
]

_CLAUSES = [
    {
        "standard": "ISO 26262",
        "clause": "6.4.3",
        "title": "Software architectural design",
        "evidenceIds": ["boundary", "coupling"],
    },
    {
        "standard": "ISO 26262",
        "clause": "6.4.4",
        "title": "Software unit design and implementation",
        "evidenceIds": ["check", "fmea"],
    },
    {
        "standard": "ISO 26262",
        "clause": "6.4.5",
        "title": "Software integration",
        "evidenceIds": ["check", "coupling"],
    },
    {
        "standard": "ISO 26262",
        "clause": "6.4.9",
        "title": "Requirements-based testing",
        "evidenceIds": ["reqs", "qualify"],
    },
    {
        "standard": "ISO 21434",
        "clause": "8.3",
        "title": "TARA",
        "evidenceIds": ["tara", "hara"],
    },
    {
        "standard": "DO-178C",
        "clause": "§11.1",
        "title": "Software accomplishment summary",
        "evidenceIds": ["qualify", "check"],
    },
    {
        "standard": "IEC 61508",
        "clause": "7.4",
        "title": "Software architecture",
        "evidenceIds": ["boundary", "coupling", "fmea"],
    },
]


def assemble(project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    standard = cfg.standard or "iso26262"

    evidence = []
    present_ids: set = set()
    for ev_id, filename, description in _EVIDENCE_ITEMS:
        path = os.path.join(project_root, filename)
        present = os.path.exists(path)
        detail = ""
        if present:
            try:
                if filename.endswith(".json"):
                    with open(path, encoding="utf-8") as f:
                        doc = json.load(f)
                    if "summary" in doc:
                        s = doc["summary"]
                        detail = f"{s.get('errors', 0)} errors, {s.get('warnings', 0)} warnings"
                    elif "total" in doc and "passed" in doc:
                        detail = f"{doc.get('passed', 0)}/{doc.get('total', 0)} passed"
                    elif "findings" in doc:
                        detail = f"{len(doc.get('findings', []))} findings"
                    elif "requirements" in doc:
                        detail = f"{len(doc.get('requirements', []))} requirements"
            except Exception:
                pass
            present_ids.add(ev_id)

        evidence.append(
            {
                "id": ev_id,
                "description": description,
                "file": filename,
                "status": "present" if present else "absent",
                "detail": detail,
            }
        )

    gaps = [ev_id for ev_id, _, _ in _EVIDENCE_ITEMS if ev_id not in present_ids]

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "safety-case",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa Safety Case v1",
        "module": module,
        "standard": standard,
        "evidence": evidence,
        "clauses": _CLAUSES,
        "gaps": gaps,
    }


def to_markdown(doc: dict) -> str:
    lines = [
        f"# Safety Case — {doc['module']}",
        "",
        f"**Standard:** {doc['standard']}  **Generated:** {doc['generatedAt']}",
        "",
    ]
    lines.append("## Evidence")
    lines.append("")
    lines.append("| ID | Description | File | Status |")
    lines.append("|---|---|---|---|")
    for ev in doc["evidence"]:
        status = "✓" if ev["status"] == "present" else "✗"
        detail = f" ({ev['detail']})" if ev.get("detail") else ""
        lines.append(
            f"| {ev['id']} | {ev['description']} | `{ev['file']}` | {status}{detail} |"
        )
    lines.append("")
    if doc.get("gaps"):
        lines.append(f"## Gaps ({len(doc['gaps'])})")
        for g in doc["gaps"]:
            lines.append(f"- {g}")
        lines.append("")
    lines.append("## Clause Mapping")
    lines.append("")
    lines.append("| Standard | Clause | Title | Evidence |")
    lines.append("|---|---|---|---|")
    for c in doc.get("clauses", []):
        lines.append(
            f"| {c['standard']} | {c['clause']} | {c['title']} | {', '.join(c['evidenceIds'])} |"
        )
    return "\n".join(lines)


def to_mermaid(doc: dict) -> str:
    lines = ["graph LR", f'    safety_case["{doc["module"]} Safety Case"]']
    for ev in doc["evidence"]:
        style = ":::ok" if ev["status"] == "present" else ":::gap"
        lines.append(f'    {ev["id"]}["{ev["file"]}"{style}]')
        lines.append(f"    safety_case --> {ev['id']}")
    lines.append("    classDef ok fill:#4c1,color:#fff")
    lines.append("    classDef gap fill:#e05d44,color:#fff")
    return "\n".join(lines)
