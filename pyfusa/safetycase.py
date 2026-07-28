"""Safety Case assembly — x-FuSa spec §9.2 `safety-case`.

A GSN (Goal Structuring Notation) argument per the GSN Community Standard
(Assurance Case Working Group, v3, 2021): `nodes[]` typed goal/strategy/
solution/context/assumption/justification, `edges[]` typed supportedBy/
inContextOf, and a `completeness` roll-up of undeveloped goals.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config
from pyfusa import content_quality

SAFETY_CASE_FILE = "safety-case.json"

# (evidence id, filename, description) — the artefacts this argument cites as
# solutions. Kept as data so the GSN graph and its markdown/mermaid renderers
# stay in lock-step with what's actually on disk.
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

# (standard display, clause, title, evidence ids) — strategies supporting the
# top-level goal, each citing one or more evidence solutions.
_CLAUSES = [
    ("ISO 26262", "6.4.3", "Software architectural design", ["boundary", "coupling"]),
    ("ISO 26262", "6.4.4", "Software unit design and implementation", ["check", "fmea"]),
    ("ISO 26262", "6.4.5", "Software integration", ["check", "coupling"]),
    ("ISO 26262", "6.4.9", "Requirements-based testing", ["reqs", "qualify"]),
    ("ISO 21434", "8.3", "TARA", ["tara", "hara"]),
    ("DO-178C", "§11.1", "Software accomplishment summary", ["qualify", "check"]),
    ("IEC 61508", "7.4", "Software architecture", ["boundary", "coupling", "fmea"]),
]


# fusa:req REQ-SC006
def assemble(project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    standard = cfg.standard or "iso26262"

    present: dict = {}
    for ev_id, filename, _desc in _EVIDENCE_ITEMS:
        present[ev_id] = os.path.exists(os.path.join(project_root, filename))

    nodes = [
        {
            "id": "G1",
            "type": "goal",
            "text": f"{module} satisfies its {standard} software safety objectives",
        },
        {
            "id": "C1",
            "type": "context",
            "text": f"Item under analysis: {module}; target standard: {standard}",
        },
    ]
    edges = [{"from": "G1", "to": "C1", "type": "inContextOf"}]

    solution_ids: dict = {}
    for ev_id, filename, description in _EVIDENCE_ITEMS:
        sol_id = f"Sn-{ev_id}"
        solution_ids[ev_id] = sol_id
        node = {"id": sol_id, "type": "solution", "text": description}
        if present[ev_id]:
            node["evidence"] = filename
        nodes.append(node)

    undeveloped = 0
    for idx, (std_display, clause, title, ev_ids) in enumerate(_CLAUSES, start=1):
        strat_id = f"St{idx}"
        nodes.append(
            {
                "id": strat_id,
                "type": "strategy",
                "text": f"Argue via {title} ({std_display} {clause})",
            }
        )
        edges.append({"from": "G1", "to": strat_id, "type": "supportedBy"})
        strategy_has_evidence = False
        for ev_id in ev_ids:
            sol_id = solution_ids.get(ev_id)
            if not sol_id:
                continue
            edges.append({"from": strat_id, "to": sol_id, "type": "supportedBy"})
            if present.get(ev_id):
                strategy_has_evidence = True
        if not strategy_has_evidence:
            undeveloped += 1

    goals_with_evidence = 1 if undeveloped < len(_CLAUSES) else 0

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "safety-case",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": standard,
        "nodes": nodes,
        "edges": edges,
        "completeness": {
            "totalGoals": 1,
            "goalsWithEvidence": goals_with_evidence,
            "undeveloped": undeveloped,
        },
    }
    existing = content_quality.load_existing_attestation(project_root, SAFETY_CASE_FILE)
    if existing:
        doc["attestation"] = existing
    return doc


def _node(doc: dict, node_id: str) -> dict:
    for n in doc["nodes"]:
        if n["id"] == node_id:
            return n
    return {"id": node_id, "text": ""}


# fusa:req REQ-SC006
def to_markdown(doc: dict) -> str:
    lines = [
        f"# Safety Case — {doc['project']}",
        "",
        f"**Standard:** {doc['standard']}  **Generated:** {doc['generatedAt']}",
        "",
        "## GSN Nodes",
        "",
        "| ID | Type | Text | Evidence |",
        "|---|---|---|---|",
    ]
    for n in doc["nodes"]:
        lines.append(
            f"| {n['id']} | {n['type']} | {n['text']} | {n.get('evidence', '')} |"
        )
    lines.append("")
    comp = doc.get("completeness", {})
    lines.append(
        f"## Completeness — {comp.get('goalsWithEvidence', 0)}/"
        f"{comp.get('totalGoals', 0)} goals fully supported, "
        f"{comp.get('undeveloped', 0)} undeveloped strateg(y/ies)"
    )
    return "\n".join(lines)


# fusa:req REQ-SC006
def to_mermaid(doc: dict) -> str:
    lines = ["graph TB"]
    for n in doc["nodes"]:
        style = ":::ok" if n.get("evidence") else ""
        label = n["text"].replace('"', "'")[:60]
        lines.append(f'    {n["id"]}["{n["id"]}: {label}"{style}]')
    for e in doc["edges"]:
        arrow = "-->" if e["type"] == "supportedBy" else "-.->"
        lines.append(f'    {e["from"]} {arrow} {e["to"]}')
    lines.append("    classDef ok fill:#4c1,color:#fff")
    return "\n".join(lines)


# fusa:req REQ-QUALBASE005
def quality_findings(doc: dict) -> list:
    """§1.6/§1.6.1 content-quality baseline over nodes[].text."""
    entries = doc.get("nodes", [])
    findings = content_quality.scan_placeholder(entries, ["text"], SAFETY_CASE_FILE)
    findings.extend(
        content_quality.scan_blanket_fallback(entries, ["text"], SAFETY_CASE_FILE)
    )
    return findings
