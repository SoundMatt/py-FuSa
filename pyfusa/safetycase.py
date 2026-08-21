"""Safety Case assembly — x-FuSa spec §9.2 `safety-case`.

A GSN (Goal Structuring Notation) argument per the GSN Community Standard
(Assurance Case Working Group, v3, 2021): `nodes[]` typed goal/strategy/
solution/context/assumption/justification, `edges[]` typed supportedBy/
inContextOf, and a `completeness` roll-up of undeveloped goals.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pyfusa
from pyfusa import content_quality
from pyfusa.config import Config

SAFETY_CASE_FILE = "safety-case.json"

# ev_id -> (json key holding the countable list/dict, fact template).
# Used by _evidence_fact() below to make each strategy's argument text cite
# a real number pulled from the project's own evidence, rather than a
# fixed string identical for every project regardless of its actual
# hazards/findings/coverage -- see _evidence_fact()'s docstring.
_FACT_SPEC = {
    "check": ("check-report.json", "findings", "{n} static-analysis finding(s)"),
    "reqs": (".fusa-reqs.json", "requirements", "{n} requirement(s) traced"),
    "sbom": ("sbom.json", "components", "{n} SBOM component(s)"),
    "hara": (".fusa-hara.json", "hazards", "{n} hazard(s) identified"),
    "tara": ("tara.json", "threats", "{n} threat scenario(s) analysed"),
    "fmea": ("fmea.json", "entries", "{n} failure mode(s) analysed"),
    "boundary": ("boundary.json", "edges", "{n} component boundary edge(s)"),
}

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


def _load_json_or_none(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _coupling_fact(doc: dict) -> str:
    n = len(doc.get("dataCoupling", [])) + len(doc.get("controlCoupling", []))
    return f"{n} coupling issue(s) analysed"


def _qualify_fact(doc: dict) -> str:
    return f"{doc.get('passed', 0)}/{doc.get('total', 0)} qualification test(s) passed"


# ev_id -> (filename, doc -> fact string). Two evidence types need a
# bespoke fact rather than a simple "count this list" template.
_SPECIAL_FACTS = {
    "coupling": ("coupling-report.json", _coupling_fact),
    "qualify": ("qualify-report.json", _qualify_fact),
}


def _evidence_fact(project_root: str, ev_id: str) -> str:
    """A short, real fact pulled from one evidence file's actual content --
    e.g. "12 requirement(s) traced" -- or "" if the file is absent,
    unparseable, or (for "provenance"/"audit-pack") not the kind of
    evidence a single count summarizes well.

    x-FuSa spec §9.2 requires `nodes[].text` to be "specific to this
    tool's actual claims (§1.6.1 rule B)" -- "a generic goal ... with no
    tool-specific detail does not satisfy this." A prior version's
    strategy text was a fixed string per standard/clause, identical for
    every project regardless of whether it actually had any hazards,
    findings, or coverage -- verified: node text was identical between a
    project with real evidence files and one with none, except for the
    module-name substitution in the top-level goal. This closes that gap
    for the strategies where a real evidence file is present, without
    inventing a claim for evidence that doesn't exist yet (an absent file
    still contributes no fact, same as before).
    """
    if ev_id in _SPECIAL_FACTS:
        filename, fact_fn = _SPECIAL_FACTS[ev_id]
        doc = _load_json_or_none(os.path.join(project_root, filename))
        return fact_fn(doc) if doc is not None else ""

    spec = _FACT_SPEC.get(ev_id)
    if not spec:
        return ""
    filename, key, template = spec
    doc = _load_json_or_none(os.path.join(project_root, filename))
    if doc is None:
        return ""
    value = doc.get(key)
    if not isinstance(value, list):
        return ""
    return template.format(n=len(value))


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

    # Per-strategy evidence presence: whether at least one of a strategy's
    # cited solutions has real evidence on disk. This is *not* what §9.2's
    # `completeness.undeveloped` measures (that's goal argument structure,
    # below) — it only feeds `goalsWithEvidence`.
    strategies_without_evidence = 0
    for idx, (std_display, clause, title, ev_ids) in enumerate(_CLAUSES, start=1):
        strat_id = f"St{idx}"
        # Cite a real fact from the first cited evidence file that has one
        # (findings/hazards/requirements actually counted, not just
        # "the file exists") -- see _evidence_fact()'s docstring.
        fact = next(
            (f for f in (_evidence_fact(project_root, e) for e in ev_ids) if f), ""
        )
        text = f"Argue via {title} ({std_display} {clause})"
        if fact:
            text += f" — {fact}"
        nodes.append({"id": strat_id, "type": "strategy", "text": text})
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
            strategies_without_evidence += 1

    # x-FuSa spec §9.2 safety-case: `completeness.totalGoals`/`undeveloped`
    # describe the GSN argument *structure* — a goal with no supporting
    # strategy/solution chain at all is "undeveloped" (§9.2: "A goal with no
    # supporting strategy/solution chain ... is a silent gap"). This is
    # independent of whether the strategies it does have are backed by
    # evidence that happens to exist on disk yet (that's
    # `strategies_without_evidence`, folded into `goalsWithEvidence` below).
    goal_ids = [n["id"] for n in nodes if n["type"] == "goal"]
    supported_goal_ids = {
        e["from"]
        for e in edges
        if e["type"] == "supportedBy" and e["from"] in goal_ids
    }
    undeveloped = sum(1 for gid in goal_ids if gid not in supported_goal_ids)
    goals_with_evidence = sum(
        1
        for gid in goal_ids
        if gid in supported_goal_ids
        and strategies_without_evidence < len(_CLAUSES)
    )

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
            "totalGoals": len(goal_ids),
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
