"""Configuration loading for .fusa.json (§1.2.1)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import pyfusa

CONFIG_FILE = ".fusa.json"
REQS_FILE = ".fusa-reqs.json"
DISPOSITIONS_FILE = ".fusa-dispositions.json"
HARA_FILE = ".fusa-hara.json"
EVIDENCE_FILE = ".fusa-evidence.json"
# Not part of the x-FuSa spec — a py-FuSa/c-FuSa workflow-parity feature.
# See pyfusa/baseline.py for the rationale.
BASELINE_FILE = ".fusa-baseline.json"

CONFIG_VERSION = "1.0"

_VALID_STANDARDS = {
    "iso26262",
    "iec61508",
    "do178c",
    "iso21434",
    "iec62443-4-1",
    "iec62443-4-2",
    "misra-c",
    "misra-cpp",
    "autosar-cpp14",
    "cert-c",
    "cert-cpp",
    "unece-r155",
    "unece-r156",
}


@dataclass
class ProjectConfig:
    name: str
    version: str = "0.1.0"


# fusa:req REQ-CONFIG001
@dataclass
class Config:
    config_version: str = CONFIG_VERSION
    project: ProjectConfig = field(default_factory=lambda: ProjectConfig(name=""))
    standard: str = "iso26262"
    asil: str = ""
    sil: str = ""
    dal: str = ""
    source_dirs: list[str] = field(default_factory=lambda: ["."])
    exclude_patterns: list[str] = field(default_factory=list)
    strict: bool = False
    report_format: str = "text"
    report_output: str = ""

    def integrity_label(self) -> str:
        if self.asil:
            return self.asil
        if self.sil:
            return self.sil
        if self.dal:
            return self.dal
        return ""


# fusa:req REQ-CONFIG001
def default(project_name: str = "", standard: str = "iso26262") -> Config:
    return Config(project=ProjectConfig(name=project_name), standard=standard)


# fusa:req REQ-CONFIG001
def load(path: str) -> Config:
    """Load and validate .fusa.json. Raises pyfusa.ErrNoConfig / ErrInvalidConfig."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"fusa: no configuration file found: {path}")

    with open(path, encoding="utf-8") as f:
        try:
            data: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"fusa: invalid configuration: {e}") from e

    cfg = Config()
    cfg.config_version = data.get("configVersion", CONFIG_VERSION)

    # §1.2.1 — accept legacy flat "project": "name" string
    proj = data.get("project", {})
    if isinstance(proj, str):
        cfg.project = ProjectConfig(name=proj)
    elif isinstance(proj, dict):
        cfg.project = ProjectConfig(
            name=proj.get("name", ""),
            version=proj.get("version", "0.1.0"),
        )

    cfg.standard = data.get("standard", "iso26262").lower()
    cfg.asil = data.get("asil", "")
    cfg.sil = data.get("sil", "")
    cfg.dal = data.get("dal", "")
    cfg.source_dirs = data.get("sourceDirs", ["."])
    cfg.exclude_patterns = data.get("excludePatterns", [])
    cfg.strict = data.get("strict", False)

    report = data.get("report", {})
    if isinstance(report, dict):
        cfg.report_format = report.get("format", "text")
        cfg.report_output = report.get("output", "")

    return cfg


# fusa:req REQ-CONFIG001
def load_dispositions(path: str) -> list[dict]:
    """Load .fusa-dispositions.json (§1.2.3). Returns empty list if absent."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []
    return data.get("dispositions", [])


# fusa:req REQ-CONFIG001
def load_baseline(path: str) -> set[str]:
    """Load the fingerprint set from .fusa-baseline.json. Not an x-FuSa spec
    file (see pyfusa/baseline.py) — returns an empty set if absent/invalid."""
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return set()
    return {
        e.get("fingerprint", "")
        for e in data.get("baseline", [])
        if e.get("fingerprint")
    }


# fusa:req REQ-CONFIG001
def load_requirements(path: str) -> tuple[list[dict], list[pyfusa.Finding]]:
    """Load .fusa-reqs.json (§1.2.2). Returns (requirements, error_findings)."""
    if not os.path.exists(path):
        return [], []
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return [], []
    reqs = data.get("requirements", [])

    # §1.2.2 — validate for duplicate ids
    seen: set[str] = set()
    errors: list[pyfusa.Finding] = []
    for req in reqs:
        rid = req.get("id", "")
        if rid in seen:
            errors.append(
                pyfusa.Finding(
                    rule_id="REQ001",
                    severity=pyfusa.SEVERITY_ERROR,
                    message=f"duplicate requirement id '{rid}' in {REQS_FILE}",
                    location=pyfusa.Location(file=REQS_FILE),
                    category=pyfusa.CATEGORY_REQUIREMENT,
                    remediation=f"remove or rename the duplicate requirement '{rid}'",
                )
            )
        seen.add(rid)

    return reqs, errors
