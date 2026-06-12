"""SLSA supply-chain integrity engine rules."""

from __future__ import annotations

import json
import os
from typing import List

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule

_PROVENANCE = "provenance.json"
_CODEOWNERS = ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
_BRANCH_PROT = [".github/branch-protection.json", ".github/rulesets.json", "docs/branch-protection.md"]


class SLSA001(Rule):
    rule_id = "SLSA001"
    standard = "slsa"
    clause = "2.1"
    description = "provenance.json must record vcsRevision to satisfy SLSA L1."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, _PROVENANCE)
        try:
            with open(path, encoding="utf-8") as f:
                prov = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        if prov.get("vcsRevision"):
            return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="provenance.json missing vcsRevision — SLSA L1 requires the source revision to be recorded",
            location=pyfusa.Location(file=_PROVENANCE),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="run 'pyfusa release' from a git repository so vcsRevision is populated",
        )]


class SLSA002(Rule):
    rule_id = "SLSA002"
    standard = "slsa"
    clause = "2.2"
    description = "provenance.json must include a builder field to satisfy SLSA L2."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, _PROVENANCE)
        try:
            with open(path, encoding="utf-8") as f:
                prov = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        if prov.get("builder"):
            return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="provenance.json missing builder field — SLSA L2 requires the build system to be identified",
            location=pyfusa.Location(file=_PROVENANCE),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="add a builder field to provenance.json and regenerate with 'pyfusa release'",
        )]


class SLSA003(Rule):
    rule_id = "SLSA003"
    standard = "slsa"
    clause = "2.3"
    description = "CODEOWNERS and branch-protection policy required for SLSA L3 two-party review."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        for name in _CODEOWNERS + _BRANCH_PROT:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="no CODEOWNERS file or branch-protection policy found — SLSA L3 requires two-party review",
            location=pyfusa.Location(file=".github/CODEOWNERS"),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="create .github/CODEOWNERS and enable branch protection requiring at least one reviewer",
        )]


ALL = [SLSA001(), SLSA002(), SLSA003()]
