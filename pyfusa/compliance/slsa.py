"""SLSA (Supply-chain Levels for Software Artifacts) compliance gap report."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

SLSA_LEVELS = ["L1", "L2", "L3", "L4"]
_L_RANK = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}

_CODEOWNERS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
_BRANCH_PROT = [".github/branch-protection.json", ".github/rulesets.json"]
_CI_CONFIGS = [".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml"]

_OBJECTIVES = [
    ("SLSA-1",  "L1", "Source in version control (.git)",           "L1", ".git"),
    ("SLSA-2",  "L1", "Build process scripted (pyproject.toml)",    "L1", "pyproject.toml"),
    ("SLSA-3",  "L1", "Provenance document generated",              "L1", "provenance.json"),
    ("SLSA-4",  "L2", "CI-hosted build (workflow evidence)",        "L2", ".github/workflows"),
    ("SLSA-5",  "L2", "Builder identity in provenance",             "L2", "provenance.json"),
    ("SLSA-6",  "L2", "SBOM generated at build time",               "L2", "sbom.json"),
    ("SLSA-7",  "L3", "Source code review (CODEOWNERS)",            "L3", "CODEOWNERS"),
    ("SLSA-8",  "L3", "Hermetic build (no network at build time)",  "L3", "qualify-report.json"),
    ("SLSA-9",  "L4", "Two-party review policy (branch protection)","L4", ".github/branch-protection.json"),
    ("SLSA-10", "L4", "Tool qualification audit pack",              "L4", "audit-pack.zip"),
]


def _provenance_has_builder(project_root: str) -> bool:
    try:
        with open(os.path.join(project_root, "provenance.json"), encoding="utf-8") as f:
            return bool(json.load(f).get("builder"))
    except (OSError, json.JSONDecodeError):
        return False


def _codeowners_present(project_root: str) -> bool:
    return any(os.path.exists(os.path.join(project_root, p)) for p in _CODEOWNERS)


def _branch_prot_present(project_root: str) -> bool:
    return any(os.path.exists(os.path.join(project_root, p)) for p in _BRANCH_PROT)


def run(project_root: str, cfg: Config, level: str = "L2") -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    l_rank = _L_RANK.get(level, 2)

    objectives = []
    counts: dict[str, int] = {"satisfied": 0, "gap": 0, "partial": 0}
    for obj_id, min_level, title, _, evidence_file in _OBJECTIVES:
        req_rank = _L_RANK.get(min_level, 1)
        if l_rank < req_rank:
            status, evidence = "partial", []
        elif obj_id == "SLSA-5":
            satisfied = _provenance_has_builder(project_root)
            status = "satisfied" if satisfied else "gap"
            evidence = [evidence_file] if satisfied else []
        elif obj_id == "SLSA-7":
            satisfied = _codeowners_present(project_root)
            status = "satisfied" if satisfied else "gap"
            evidence = [evidence_file] if satisfied else []
        elif obj_id == "SLSA-9":
            satisfied = _branch_prot_present(project_root)
            status = "satisfied" if satisfied else "gap"
            evidence = [evidence_file] if satisfied else []
        elif os.path.exists(os.path.join(project_root, evidence_file)):
            status, evidence = "satisfied", [evidence_file]
        else:
            status, evidence = "gap", []
        counts[status] = counts.get(status, 0) + 1
        obj = {"id": obj_id, "level": min_level, "title": title,
               "status": status, "evidence": evidence}
        if status == "gap":
            obj["remediation"] = f"run 'pyfusa' to generate {evidence_file}"
        objectives.append(obj)

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "gap-report",
        "tool": pyfusa.TOOL, "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE, "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module, "standard": "slsa", "level": level,
        "summary": {"total": len(objectives), "satisfied": counts["satisfied"],
                    "partial": counts["partial"], "gaps": counts["gap"]},
        "objectives": objectives,
    }


def render_text(doc: dict) -> str:
    s = doc.get("summary", {})
    lines = [
        f"SLSA gap report  project={doc['project']}  level={doc['level']}",
        f"satisfied={s.get('satisfied',0)}  gaps={s.get('gaps',0)}  partial={s.get('partial',0)}", "",
    ]
    for obj in doc["objectives"]:
        marker = {"satisfied": "✓", "gap": "✗", "partial": "–"}.get(obj["status"], "?")
        lines.append(f"  {marker} {obj['id']:8s} {obj['level']:4s} {obj['status']:10s} {obj['title']}")
    return "\n".join(lines)
