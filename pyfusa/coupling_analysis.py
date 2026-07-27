"""Coupling analysis (COUP001-003) — generate coupling-report.json."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config


# fusa:req REQ-COUPLING001
def run(project_root: str, cfg: Config) -> dict:
    """Run coupling-specific rules and return coupling-report.json payload."""
    from pyfusa.rules.coupling import COUP001, COUP002

    findings = _run_rules([COUP001(), COUP002()], project_root, cfg)

    data = []
    control = []
    for f in findings:
        entry = {
            "ruleId": f.rule_id,
            "severity": f.severity,
            "message": f.message,
            "location": f.location.to_dict(),
        }
        if f.rule_id == "COUP001":
            data.append(entry)
        else:
            control.append(entry)

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "coupling-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": project_root,
        "dataCoupling": data,
        "controlCoupling": control,
    }


def _run_rules(rules, project_root: str, cfg: Config) -> List:
    findings = []
    for rule in rules:
        try:
            findings.extend(rule.run(project_root, cfg))
        except Exception:
            pass
    return findings
