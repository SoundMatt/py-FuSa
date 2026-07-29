"""HARA — Hazard Analysis and Risk Assessment, x-FuSa spec §1.2.5 / §9.2 `hara`.

`.fusa-hara.json` is an *input* file (like `.fusa-reqs.json`): a project
author writes/maintains it, and this module validates and normalises it. The
`hara` command reports on it, never fabricates it — `init_template` always
scaffolds **empty** arrays (§1.6 rule 1: an empty section is honestly
incomplete; placeholder text asserts a false completeness).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional, Set

import pyfusa
from pyfusa import content_quality

HARA_FILE = ".fusa-hara.json"

# ISO 26262-3:2018 Table 4 ASIL determination
# Key: (severity S, exposure E, controllability C)
_ASIL_TABLE: dict = {
    # S0 → always QM
    ("S0", "E0", "C0"): "QM",
    ("S0", "E0", "C1"): "QM",
    ("S0", "E0", "C2"): "QM",
    ("S0", "E0", "C3"): "QM",
    ("S0", "E1", "C0"): "QM",
    ("S0", "E1", "C1"): "QM",
    ("S0", "E1", "C2"): "QM",
    ("S0", "E1", "C3"): "QM",
    ("S0", "E2", "C0"): "QM",
    ("S0", "E2", "C1"): "QM",
    ("S0", "E2", "C2"): "QM",
    ("S0", "E2", "C3"): "QM",
    ("S0", "E3", "C0"): "QM",
    ("S0", "E3", "C1"): "QM",
    ("S0", "E3", "C2"): "QM",
    ("S0", "E3", "C3"): "QM",
    ("S0", "E4", "C0"): "QM",
    ("S0", "E4", "C1"): "QM",
    ("S0", "E4", "C2"): "QM",
    ("S0", "E4", "C3"): "QM",
    # S1
    ("S1", "E0", "C0"): "QM",
    ("S1", "E0", "C1"): "QM",
    ("S1", "E0", "C2"): "QM",
    ("S1", "E0", "C3"): "QM",
    ("S1", "E1", "C0"): "QM",
    ("S1", "E1", "C1"): "QM",
    ("S1", "E1", "C2"): "QM",
    ("S1", "E1", "C3"): "QM",
    ("S1", "E2", "C0"): "QM",
    ("S1", "E2", "C1"): "QM",
    ("S1", "E2", "C2"): "QM",
    ("S1", "E2", "C3"): "QM",
    ("S1", "E3", "C0"): "QM",
    ("S1", "E3", "C1"): "QM",
    ("S1", "E3", "C2"): "QM",
    ("S1", "E3", "C3"): "ASIL-A",
    ("S1", "E4", "C0"): "QM",
    ("S1", "E4", "C1"): "QM",
    ("S1", "E4", "C2"): "ASIL-A",
    ("S1", "E4", "C3"): "ASIL-B",
    # S2
    ("S2", "E0", "C0"): "QM",
    ("S2", "E0", "C1"): "QM",
    ("S2", "E0", "C2"): "QM",
    ("S2", "E0", "C3"): "QM",
    ("S2", "E1", "C0"): "QM",
    ("S2", "E1", "C1"): "QM",
    ("S2", "E1", "C2"): "QM",
    ("S2", "E1", "C3"): "QM",
    ("S2", "E2", "C0"): "QM",
    ("S2", "E2", "C1"): "QM",
    ("S2", "E2", "C2"): "ASIL-A",
    ("S2", "E2", "C3"): "ASIL-B",
    ("S2", "E3", "C0"): "QM",
    ("S2", "E3", "C1"): "ASIL-A",
    ("S2", "E3", "C2"): "ASIL-B",
    ("S2", "E3", "C3"): "ASIL-C",
    ("S2", "E4", "C0"): "ASIL-A",
    ("S2", "E4", "C1"): "ASIL-B",
    ("S2", "E4", "C2"): "ASIL-C",
    ("S2", "E4", "C3"): "ASIL-D",
    # S3
    ("S3", "E0", "C0"): "QM",
    ("S3", "E0", "C1"): "QM",
    ("S3", "E0", "C2"): "QM",
    ("S3", "E0", "C3"): "QM",
    ("S3", "E1", "C0"): "QM",
    ("S3", "E1", "C1"): "ASIL-A",
    ("S3", "E1", "C2"): "ASIL-B",
    ("S3", "E1", "C3"): "ASIL-C",
    ("S3", "E2", "C0"): "ASIL-A",
    ("S3", "E2", "C1"): "ASIL-B",
    ("S3", "E2", "C2"): "ASIL-C",
    ("S3", "E2", "C3"): "ASIL-D",
    ("S3", "E3", "C0"): "ASIL-B",
    ("S3", "E3", "C1"): "ASIL-C",
    ("S3", "E3", "C2"): "ASIL-D",
    ("S3", "E3", "C3"): "ASIL-D",
    ("S3", "E4", "C0"): "ASIL-C",
    ("S3", "E4", "C1"): "ASIL-D",
    ("S3", "E4", "C2"): "ASIL-D",
    ("S3", "E4", "C3"): "ASIL-D",
}

_ASIL_RANK = {"QM": 0, "ASIL-A": 1, "ASIL-B": 2, "ASIL-C": 3, "ASIL-D": 4}


# fusa:req REQ-CLI009
def determine_asil(severity: str, exposure: str, controllability: str) -> str:
    return _ASIL_TABLE.get((severity, exposure, controllability), "QM")


# fusa:req REQ-CLI009
def load(project_root: str) -> Optional[dict]:
    path = os.path.join(project_root, HARA_FILE)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# fusa:req REQ-CLI009
def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, HARA_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


# fusa:req REQ-CLI009
def init_template(project_name: str, standard: str = "iso26262") -> dict:
    """§1.2.5 / §1.6 rule 1 — scaffold **empty** collections, never dummy rows.
    A project author fills these in; a placeholder row would assert a false
    completeness and would itself be flagged by FUSA-STUB001."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "project": project_name,
        "standard": standard,
        "createdAt": now,
        "operationalSituations": [],
        "hazards": [],
        "safetyGoals": [],
    }


def _finding(rule_id: str, severity: str, message: str, category: str = pyfusa.CATEGORY_SAFETY) -> pyfusa.Finding:
    return pyfusa.Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=pyfusa.Location(file=HARA_FILE),
        category=category,
    )


# fusa:req REQ-HARA006
def validate_findings(
    data: dict, project_asil: str, req_ids: Optional[Set[str]] = None
) -> List[pyfusa.Finding]:
    """§1.2.5 referential-integrity + MUST-field validation, as proper
    `Finding`s (fingerprint/disposition-compatible) rather than bare strings.

    `req_ids`, when given, is the set of ids from `.fusa-reqs.json` (§1.2.2)
    against which `safetyGoals[].fssrRefs` is checked for dangling
    references (§1.2.5 MUST)."""
    findings: List[pyfusa.Finding] = []
    situation_ids = {s.get("id") for s in data.get("operationalSituations", [])}
    hazards = data.get("hazards", [])
    safety_goals = data.get("safetyGoals", [])
    safety_goal_ids = {sg.get("id") for sg in safety_goals}
    project_rank = _ASIL_RANK.get(project_asil, 2)

    for h in hazards:
        hid = h.get("id", "")
        risk = h.get("risk", {})
        s, e, c = risk.get("severity", ""), risk.get("exposure", ""), risk.get(
            "controllability", ""
        )
        if not (s and e and c):
            findings.append(
                _finding(
                    "HARA002",
                    pyfusa.SEVERITY_ERROR,
                    f"hazard {hid} has incomplete risk rating (severity/exposure/controllability)",
                )
            )
        else:
            computed = determine_asil(s, e, c)
            risk["asil"] = computed
            if _ASIL_RANK.get(computed, 0) > project_rank:
                findings.append(
                    _finding(
                        "HARA005",
                        pyfusa.SEVERITY_ERROR,
                        f"hazard {hid} ASIL {computed} exceeds project ASIL {project_asil}",
                    )
                )

        if not h.get("safetyGoals"):
            findings.append(
                _finding(
                    "HARA003",
                    pyfusa.SEVERITY_ERROR,
                    f"hazard {hid} has no linked safety goals",
                    category=pyfusa.CATEGORY_REQUIREMENT,
                )
            )
        else:
            for sg_id in h.get("safetyGoals", []):
                if sg_id not in safety_goal_ids:
                    findings.append(
                        _finding(
                            "HARA003",
                            pyfusa.SEVERITY_ERROR,
                            f"hazard {hid} references unknown safety goal {sg_id}",
                            category=pyfusa.CATEGORY_REQUIREMENT,
                        )
                    )

        for os_id in h.get("situations", []):
            if os_id not in situation_ids:
                findings.append(
                    _finding(
                        "HARA008",
                        pyfusa.SEVERITY_WARNING,
                        f"hazard {hid} references unknown operational situation {os_id}",
                        category=pyfusa.CATEGORY_REQUIREMENT,
                    )
                )

    for sg in safety_goals:
        sgid = sg.get("id", "")
        if not sg.get("asil"):
            findings.append(
                _finding(
                    "HARA004", pyfusa.SEVERITY_ERROR, f"safety goal {sgid} has no ASIL set"
                )
            )

        fssr_refs = sg.get("fssrRefs") or []
        if not fssr_refs:
            findings.append(
                _finding(
                    "HARA006",
                    pyfusa.SEVERITY_ERROR,
                    f"safety goal {sgid} has no fssrRefs — a safety goal MUST "
                    f"decompose into >=1 functional safety requirement (§1.2.5)",
                    category=pyfusa.CATEGORY_REQUIREMENT,
                )
            )
        elif req_ids is not None:
            for rid in fssr_refs:
                if rid not in req_ids:
                    findings.append(
                        _finding(
                            "HARA007",
                            pyfusa.SEVERITY_WARNING,
                            f"safety goal {sgid} fssrRefs references unknown "
                            f"requirement {rid} in .fusa-reqs.json",
                            category=pyfusa.CATEGORY_REQUIREMENT,
                        )
                    )

    return findings


# fusa:req REQ-CLI009
def validate(data: dict, project_asil: str, req_ids: Optional[Set[str]] = None) -> List[str]:
    """Back-compat string-message wrapper over validate_findings()."""
    return [
        f"{f.rule_id}: {f.message}" for f in validate_findings(data, project_asil, req_ids)
    ]


# fusa:req REQ-HARA009
def completeness(data: dict, req_ids: Optional[Set[str]] = None) -> dict:
    """§9.2 hara `completeness` block."""
    hazards = data.get("hazards", [])
    safety_goals = data.get("safetyGoals", [])
    situation_ids = {s.get("id") for s in data.get("operationalSituations", [])}
    safety_goal_ids = {sg.get("id") for sg in safety_goals}

    hazards_with_asil = sum(1 for h in hazards if h.get("risk", {}).get("asil"))
    hazards_with_sg = sum(1 for h in hazards if h.get("safetyGoals"))
    sg_with_fssr = sum(1 for sg in safety_goals if sg.get("fssrRefs"))

    dangling = 0
    for h in hazards:
        for sid in h.get("situations", []):
            if sid not in situation_ids:
                dangling += 1
        for gid in h.get("safetyGoals", []):
            if gid not in safety_goal_ids:
                dangling += 1
    for sg in safety_goals:
        for rid in sg.get("fssrRefs", []):
            if req_ids is not None and rid not in req_ids:
                dangling += 1

    return {
        "totalHazards": len(hazards),
        "hazardsWithAsil": hazards_with_asil,
        "hazardsWithSafetyGoal": hazards_with_sg,
        "safetyGoalsWithFssrRefs": sg_with_fssr,
        "danglingReferences": dangling,
    }


# fusa:req REQ-HARA009
def to_report_dict(data: dict, project_root: str, cfg) -> dict:
    """§9.2 hara `--format json` — the §3.1 header plus the `.fusa-hara.json`
    content verbatim plus a `completeness` roll-up."""
    from pyfusa.config import load_requirements, REQS_FILE

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    reqs, _ = load_requirements(os.path.join(project_root, REQS_FILE))
    req_ids = {r.get("id") for r in reqs}

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "hara-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": data.get("standard", cfg.standard),
        "operationalSituations": data.get("operationalSituations", []),
        "hazards": data.get("hazards", []),
        "safetyGoals": data.get("safetyGoals", []),
        "completeness": completeness(data, req_ids),
    }
    if data.get("attestation"):
        doc["attestation"] = data["attestation"]
    return doc


# fusa:req REQ-QUALBASE005
def quality_findings(data: dict) -> List[pyfusa.Finding]:
    """§1.6/§1.6.1 content-quality baseline over hazards[].description and
    safetyGoals[].description."""
    findings = content_quality.scan_placeholder(
        data.get("hazards", []), ["description"], HARA_FILE
    )
    findings.extend(
        content_quality.scan_placeholder(
            data.get("safetyGoals", []), ["description"], HARA_FILE
        )
    )
    findings.extend(
        content_quality.scan_blanket_fallback(
            data.get("hazards", []), ["description"], HARA_FILE
        )
    )
    findings.extend(
        content_quality.scan_blanket_fallback(
            data.get("safetyGoals", []), ["description"], HARA_FILE
        )
    )
    return findings
