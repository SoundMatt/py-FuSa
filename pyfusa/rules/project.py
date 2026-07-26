"""Project-structure rules: FUSA001–FUSA006."""

from __future__ import annotations

import os

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule


#fusa:req REQ-FUSA001
class RuleConfigPresent(Rule):
    rule_id = "FUSA001"
    standard = "iso26262"
    clause = "4.6"
    description = "Project must have a .fusa.json configuration file."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa.json")
        if not os.path.exists(path):
            return [pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_ERROR,
                message="no .fusa.json found in project root",
                location=pyfusa.Location(file=".fusa.json"),
                remediation="run 'pyfusa init' to create a starter configuration",
            )]
        return []


#fusa:req REQ-FUSA002
class RulePythonProjectPresent(Rule):
    rule_id = "FUSA002"
    standard = "iso26262"
    clause = "4.6"
    description = "Project must have a Python packaging file (pyproject.toml, setup.py, or setup.cfg)."

    _CANDIDATES = ["pyproject.toml", "setup.py", "setup.cfg"]

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        for name in self._CANDIDATES:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id,
            severity=pyfusa.SEVERITY_ERROR,
            message="no Python packaging file found (pyproject.toml, setup.py, or setup.cfg)",
            location=pyfusa.Location(file="pyproject.toml"),
            remediation="add a pyproject.toml to define package metadata and dependencies",
        )]


#fusa:req REQ-FUSA003
class RuleLicensePresent(Rule):
    rule_id = "FUSA003"
    standard = "iso26262"
    clause = "4.6"
    description = "Project must have a LICENSE file for IP clarity in safety cases."

    _CANDIDATES = ["LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE"]

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        for name in self._CANDIDATES:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id,
            severity=pyfusa.SEVERITY_WARNING,
            message="no LICENSE file found",
            location=pyfusa.Location(file="LICENSE"),
            remediation="add a LICENSE file to clarify IP ownership for assessors",
        )]


#fusa:req REQ-FUSA004
class RuleReadmePresent(Rule):
    rule_id = "FUSA004"
    standard = "iso26262"
    clause = "4.6"
    description = "Project must have a README for assessor orientation."

    _CANDIDATES = ["README.md", "README.txt", "README.rst", "README"]

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        for name in self._CANDIDATES:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id,
            severity=pyfusa.SEVERITY_WARNING,
            message="no README file found",
            location=pyfusa.Location(file="README.md"),
            remediation="add a README.md describing the project's safety context",
        )]


#fusa:req REQ-FUSA005
class RuleCIPresent(Rule):
    rule_id = "FUSA005"
    standard = "iso26262"
    clause = "4.6"
    description = "Project must have CI configuration for automated evidence generation."

    _CANDIDATES = [
        os.path.join(".github", "workflows"),
        ".gitlab-ci.yml",
        "Jenkinsfile",
        ".circleci",
        ".travis.yml",
        "azure-pipelines.yml",
    ]

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        for rel in self._CANDIDATES:
            if os.path.exists(os.path.join(project_root, rel)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id,
            severity=pyfusa.SEVERITY_WARNING,
            message="no CI configuration found",
            location=pyfusa.Location(file=".github/workflows/"),
            remediation="add CI configuration to automate safety evidence generation",
        )]


#fusa:req REQ-FUSA006
class RuleRequirementsPresent(Rule):
    rule_id = "FUSA006"
    standard = "iso26262"
    clause = "5.4.6"
    description = "Project must have a .fusa-reqs.json requirements registry."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-reqs.json")
        if not os.path.exists(path):
            return [pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_WARNING,
                message="no .fusa-reqs.json found; requirement traceability is not configured",
                location=pyfusa.Location(file=".fusa-reqs.json"),
                remediation="run 'pyfusa init' to create .fusa-reqs.json",
            )]
        return []


ALL: list[Rule] = [
    RuleConfigPresent(),
    RulePythonProjectPresent(),
    RuleLicensePresent(),
    RuleReadmePresent(),
    RuleCIPresent(),
    RuleRequirementsPresent(),
]
