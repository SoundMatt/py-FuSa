"""Rule registry and execution engine."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import pyfusa
from pyfusa.config import Config, load_dispositions, load_requirements
from pyfusa.rules import Rule
from pyfusa.rules import project as _project_rules
from pyfusa.rules import lint as _lint_rules
from pyfusa.rules import security as _sec_rules
from pyfusa.rules import concurrency as _conc_rules


@dataclass
class RunResult:
    findings: list[pyfusa.Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def has_errors(self) -> bool:
        return any(
            f.severity == pyfusa.SEVERITY_ERROR
            and f.disposition not in (pyfusa.DISPOSITION_ACCEPTED, pyfusa.DISPOSITION_DEFERRED)
            for f in self.findings
        )

    def has_warnings(self) -> bool:
        return any(
            f.severity == pyfusa.SEVERITY_WARNING
            and f.disposition not in (pyfusa.DISPOSITION_ACCEPTED, pyfusa.DISPOSITION_DEFERRED)
            for f in self.findings
        )

    def summary(self) -> dict:
        errors = sum(1 for f in self.findings if f.severity == pyfusa.SEVERITY_ERROR)
        warnings = sum(1 for f in self.findings if f.severity == pyfusa.SEVERITY_WARNING)
        infos = sum(1 for f in self.findings if f.severity == pyfusa.SEVERITY_INFO)
        return {
            "total": len(self.findings),
            "errors": errors,
            "warnings": warnings,
            "infos": infos,
        }


class Engine:
    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def must_register(self, rule: Rule) -> None:
        self.register(rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def run(self, project_root: str, cfg: Config) -> RunResult:
        result = RunResult()

        # Load dispositions (§4.1)
        disp_path = os.path.join(project_root, ".fusa-dispositions.json")
        dispositions = load_dispositions(disp_path)

        # Load requirements and validate duplicates (§1.2.2)
        reqs_path = os.path.join(project_root, ".fusa-reqs.json")
        _, req_errors = load_requirements(reqs_path)
        result.findings.extend(req_errors)

        # Run all rules
        for rule in self._rules:
            try:
                findings = rule.run(project_root, cfg)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"rule {rule.rule_id}: {e}")

        # Apply dispositions (§4.1)
        _apply_dispositions(result.findings, dispositions, project_root, result)

        return result


def _apply_dispositions(
    findings: list[pyfusa.Finding],
    dispositions: list[dict],
    project_root: str,
    result: RunResult,
) -> None:
    """Match dispositions to findings and annotate; warn on orphaned accepted/deferred."""
    matched: set[int] = set()  # indices into dispositions

    for finding in findings:
        for idx, disp in enumerate(dispositions):
            status = disp.get("status", "")
            if not status:
                continue
            # Match by fingerprint (primary)
            fp = disp.get("fingerprint", "")
            if fp and fp == finding.fingerprint:
                finding.disposition = status
                matched.add(idx)
                break
            # Fallback: ruleId + file + line
            if (disp.get("ruleId") == finding.rule_id
                    and disp.get("file") == finding.location.file):
                line = disp.get("line")
                if line is None or line == finding.location.line:
                    finding.disposition = status
                    matched.add(idx)
                    break
            # Rule-level accept (ruleId only)
            if disp.get("ruleId") == finding.rule_id and not disp.get("file"):
                finding.disposition = status
                matched.add(idx)
                break

    # Orphaned accepted/deferred dispositions → WARNING (§4.1)
    for idx, disp in enumerate(dispositions):
        if idx in matched:
            continue
        status = disp.get("status", "")
        if status in (pyfusa.DISPOSITION_ACCEPTED, pyfusa.DISPOSITION_DEFERRED):
            fp = disp.get("fingerprint") or disp.get("ruleId") or "?"
            result.findings.append(pyfusa.Finding(
                rule_id="CFG001",
                severity=pyfusa.SEVERITY_WARNING,
                message=f"orphaned disposition entry for '{fp}' matches no current finding",
                location=pyfusa.Location(file=".fusa-dispositions.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="remove the stale disposition entry from .fusa-dispositions.json",
            ))


def _build_default() -> Engine:
    eng = Engine()
    for r in _project_rules.ALL:
        eng.must_register(r)
    for r in _lint_rules.ALL:
        eng.must_register(r)
    for r in _sec_rules.ALL:
        eng.must_register(r)
    for r in _conc_rules.ALL:
        eng.must_register(r)
    return eng


Default = _build_default()
