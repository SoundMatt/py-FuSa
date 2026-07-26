"""HARA — Hazard Analysis and Risk Assessment (ISO 26262 §3)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

HARA_FILE = ".fusa-hara.json"

# ISO 26262-3:2018 Table 4 ASIL determination
# Key: (severity S, exposure E, controllability C)
_ASIL_TABLE: dict = {
    # S0 → always QM
    ("S0", "E0", "C0"): "QM", ("S0", "E0", "C1"): "QM", ("S0", "E0", "C2"): "QM", ("S0", "E0", "C3"): "QM",
    ("S0", "E1", "C0"): "QM", ("S0", "E1", "C1"): "QM", ("S0", "E1", "C2"): "QM", ("S0", "E1", "C3"): "QM",
    ("S0", "E2", "C0"): "QM", ("S0", "E2", "C1"): "QM", ("S0", "E2", "C2"): "QM", ("S0", "E2", "C3"): "QM",
    ("S0", "E3", "C0"): "QM", ("S0", "E3", "C1"): "QM", ("S0", "E3", "C2"): "QM", ("S0", "E3", "C3"): "QM",
    ("S0", "E4", "C0"): "QM", ("S0", "E4", "C1"): "QM", ("S0", "E4", "C2"): "QM", ("S0", "E4", "C3"): "QM",
    # S1
    ("S1", "E0", "C0"): "QM", ("S1", "E0", "C1"): "QM", ("S1", "E0", "C2"): "QM", ("S1", "E0", "C3"): "QM",
    ("S1", "E1", "C0"): "QM", ("S1", "E1", "C1"): "QM", ("S1", "E1", "C2"): "QM", ("S1", "E1", "C3"): "ASIL-A",
    ("S1", "E2", "C0"): "QM", ("S1", "E2", "C1"): "QM", ("S1", "E2", "C2"): "ASIL-A", ("S1", "E2", "C3"): "ASIL-B",
    ("S1", "E3", "C0"): "QM", ("S1", "E3", "C1"): "ASIL-A", ("S1", "E3", "C2"): "ASIL-B", ("S1", "E3", "C3"): "ASIL-C",
    ("S1", "E4", "C0"): "ASIL-A", ("S1", "E4", "C1"): "ASIL-B", ("S1", "E4", "C2"): "ASIL-C", ("S1", "E4", "C3"): "ASIL-C",
    # S2
    ("S2", "E0", "C0"): "QM", ("S2", "E0", "C1"): "QM", ("S2", "E0", "C2"): "QM", ("S2", "E0", "C3"): "QM",
    ("S2", "E1", "C0"): "QM", ("S2", "E1", "C1"): "QM", ("S2", "E1", "C2"): "ASIL-A", ("S2", "E1", "C3"): "ASIL-B",
    ("S2", "E2", "C0"): "QM", ("S2", "E2", "C1"): "ASIL-A", ("S2", "E2", "C2"): "ASIL-B", ("S2", "E2", "C3"): "ASIL-C",
    ("S2", "E3", "C0"): "ASIL-A", ("S2", "E3", "C1"): "ASIL-B", ("S2", "E3", "C2"): "ASIL-C", ("S2", "E3", "C3"): "ASIL-D",
    ("S2", "E4", "C0"): "ASIL-B", ("S2", "E4", "C1"): "ASIL-C", ("S2", "E4", "C2"): "ASIL-D", ("S2", "E4", "C3"): "ASIL-D",
    # S3
    ("S3", "E0", "C0"): "QM", ("S3", "E0", "C1"): "QM", ("S3", "E0", "C2"): "QM", ("S3", "E0", "C3"): "ASIL-A",
    ("S3", "E1", "C0"): "QM", ("S3", "E1", "C1"): "ASIL-A", ("S3", "E1", "C2"): "ASIL-B", ("S3", "E1", "C3"): "ASIL-C",
    ("S3", "E2", "C0"): "ASIL-A", ("S3", "E2", "C1"): "ASIL-B", ("S3", "E2", "C2"): "ASIL-C", ("S3", "E2", "C3"): "ASIL-D",
    ("S3", "E3", "C0"): "ASIL-B", ("S3", "E3", "C1"): "ASIL-C", ("S3", "E3", "C2"): "ASIL-D", ("S3", "E3", "C3"): "ASIL-D",
    ("S3", "E4", "C0"): "ASIL-C", ("S3", "E4", "C1"): "ASIL-D", ("S3", "E4", "C2"): "ASIL-D", ("S3", "E4", "C3"): "ASIL-D",
}

_ASIL_RANK = {"QM": 0, "ASIL-A": 1, "ASIL-B": 2, "ASIL-C": 3, "ASIL-D": 4}


def determine_asil(severity: str, exposure: str, controllability: str) -> str:
    return _ASIL_TABLE.get((severity, exposure, controllability), "QM")


def load(project_root: str) -> Optional[dict]:
    path = os.path.join(project_root, HARA_FILE)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, HARA_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def init_template(project_name: str, standard: str = "ISO 26262") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "project": project_name,
        "standard": standard,
        "createdAt": now,
        "operationalSituations": [
            {"id": "OS-001", "description": "Normal operation"},
            {"id": "OS-002", "description": "Degraded mode"},
        ],
        "hazards": [
            {
                "id": "H-001",
                "description": "Example hazard — replace with actual",
                "source": "",
                "situations": ["OS-001"],
                "risk": {
                    "severity": "S2",
                    "exposure": "E2",
                    "controllability": "C2",
                    "asil": "ASIL-B",
                },
                "safetyGoals": ["SG-001"],
            }
        ],
        "safetyGoals": [
            {
                "id": "SG-001",
                "description": "Example safety goal — replace with actual",
                "hazards": ["H-001"],
                "asil": "ASIL-B",
                "safeState": "System enters safe state within 100ms",
                "fssrRef": "",
            }
        ],
    }


def validate(data: dict, project_asil: str) -> List[str]:
    """Return list of validation error strings."""
    errors: List[str] = []
    hazards = data.get("hazards", [])
    safety_goals = {sg["id"] for sg in data.get("safetyGoals", [])}
    project_rank = _ASIL_RANK.get(project_asil, 2)

    for h in hazards:
        risk = h.get("risk", {})
        s = risk.get("severity", "")
        e = risk.get("exposure", "")
        c = risk.get("controllability", "")
        if not (s and e and c):
            errors.append(f"HARA002: hazard {h.get('id','')} has incomplete risk rating (S/E/C)")
        else:
            computed = determine_asil(s, e, c)
            risk["asil"] = computed
            if _ASIL_RANK.get(computed, 0) > project_rank:
                errors.append(
                    f"HARA005: hazard {h.get('id','')} ASIL {computed} exceeds project ASIL {project_asil}"
                )

        if not h.get("safetyGoals"):
            errors.append(f"HARA003: hazard {h.get('id','')} has no linked safety goals")
        else:
            for sg_id in h.get("safetyGoals", []):
                if sg_id not in safety_goals:
                    errors.append(f"HARA003: hazard {h.get('id','')} references unknown safety goal {sg_id}")

    for sg in data.get("safetyGoals", []):
        if not sg.get("asil"):
            errors.append(f"HARA004: safety goal {sg.get('id','')} has no ASIL set")

    return errors
