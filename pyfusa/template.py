"""Generate safety documentation templates."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config

_TEMPLATES = {
    "safety-plan": {
        "filename": "SAFETY_PLAN.md",
        "description": "Software Development Plan (ISO 26262 §6.4.1 / DO-178C §11.1)",
        "content": lambda module, standard: (
            f"""# Software Development Plan — {module}

## 1. Purpose and Scope

This document defines the software development plan for {module} in conformance
with {standard}.

## 2. Software Level

<!-- Specify ASIL (ISO 26262) or DAL (DO-178C) -->
- Safety Integrity Level: TODO

## 3. Development Standards

- Coding standard: See CONTRIBUTING.md
- Safety rule set: py-FuSa {pyfusa.VERSION} (x-FuSa spec v{pyfusa.SPEC_VERSION})

## 4. Tool Qualification

py-FuSa is qualified via `pyfusa qualify`. See qualify-report.json.

## 5. Verification Strategy

- Static analysis: `pyfusa check`
- Requirements traceability: `pyfusa trace`
- Structural coverage: `pyfusa coverage`
- Qualification: `pyfusa qualify`

## 6. Configuration Management

All artefacts are under version control (git). See SCI (sci.json).

## 7. Approval

| Role | Name | Date |
|---|---|---|
| Software Manager | | |
| Safety Manager | | |
"""
        ),
    },
    "hara": {
        "filename": ".fusa-hara.json",
        "description": "HARA template (ISO 26262 §3)",
        "content": lambda module, standard: (
            json.dumps(
                {
                    "project": module,
                    "standard": standard,
                    "createdAt": datetime.now(tz=timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    "operationalSituations": [
                        {"id": "OS-001", "description": "Normal operation"},
                    ],
                    "hazards": [
                        {
                            "id": "H-001",
                            "description": "TODO: describe hazard",
                            "source": "",
                            "situations": ["OS-001"],
                            "risk": {
                                "severity": "S2",
                                "exposure": "E3",
                                "controllability": "C2",
                                "asil": "ASIL-C",
                            },
                            "safetyGoals": ["SG-001"],
                        }
                    ],
                    "safetyGoals": [
                        {
                            "id": "SG-001",
                            "description": "TODO: describe safety goal",
                            "hazards": ["H-001"],
                            "asil": "ASIL-C",
                            "safeState": "TODO: describe safe state",
                            "fssrRefs": [],
                        }
                    ],
                },
                indent=2,
            )
            + "\n"
        ),
    },
    "requirements": {
        "filename": ".fusa-reqs.json",
        "description": "Requirements template",
        "content": lambda module, standard: (
            json.dumps(
                {
                    "requirements": [
                        {
                            "id": "REQ-001",
                            "title": "TODO: requirement title",
                            "text": "TODO: detailed requirement text",
                            "standard": standard,
                            "level": "HLR",
                            "asil": "ASIL-B",
                        }
                    ]
                },
                indent=2,
            )
            + "\n"
        ),
    },
    "evidence": {
        "filename": ".fusa-evidence.json",
        "description": "Evidence suite template",
        "content": lambda module, standard: (
            json.dumps(
                {
                    "project": module,
                    "standard": standard,
                    "testSuites": [
                        {
                            "name": "unit",
                            "command": "python3 -m pytest tests/ -v",
                            "passed": 0,
                            "failed": 0,
                            "runAt": "",
                        }
                    ],
                },
                indent=2,
            )
            + "\n"
        ),
    },
}


# fusa:req REQ-CLI009
def list_templates() -> List[str]:
    return list(_TEMPLATES.keys())


# fusa:req REQ-CLI009
def generate(name: str, project_root: str, cfg: Config, force: bool = False) -> str:
    if name not in _TEMPLATES:
        raise ValueError(
            f"unknown template '{name}'; available: {', '.join(list_templates())}"
        )
    tmpl = _TEMPLATES[name]
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    standard = cfg.standard or "iso26262"
    content = tmpl["content"](module, standard)
    out_path = os.path.join(project_root, tmpl["filename"])
    if os.path.exists(out_path) and not force:
        raise FileExistsError(
            f"{tmpl['filename']} already exists; use --force to overwrite"
        )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path
