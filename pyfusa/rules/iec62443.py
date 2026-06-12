"""IEC 62443 cybersecurity engine rules (Industrial Automation and Control Systems)."""

from __future__ import annotations

import json
import os
from typing import List, Optional

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule

_CONFIG_FILE = ".fusa-iec62443.json"
_SEC_POLICY_FILES = ["SECURITY.md", "SECURITY_POLICY.md", "security-policy.md", "docs/SECURITY.md"]
_INCIDENT_RESP_FILES = ["INCIDENT-RESPONSE.md", "INCIDENT_RESPONSE.md", "docs/INCIDENT-RESPONSE.md",
                         "incident-response.md", ".github/INCIDENT-RESPONSE.md"]


def _load_config(project_root: str) -> Optional[dict]:
    try:
        with open(os.path.join(project_root, _CONFIG_FILE), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


class IEC62443_001(Rule):
    rule_id = "IEC62443-001"
    standard = "iec62443"
    clause = "4-1 §8"
    description = "IEC 62443 Security Level must be declared in .fusa-iec62443.json."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, _CONFIG_FILE)):
            return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="no .fusa-iec62443.json found — IEC 62443 Security Level not declared",
            location=pyfusa.Location(file=_CONFIG_FILE),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="create .fusa-iec62443.json with target_sl (1-4) and component_type",
        )]


class IEC62443_002(Rule):
    rule_id = "IEC62443-002"
    standard = "iec62443"
    clause = "4-1 §8"
    description = "IEC 62443 target_sl must be an integer in the range 1–4."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        doc = _load_config(project_root)
        if doc is None:
            return []  # IEC62443-001 handles missing file
        sl = doc.get("target_sl", 0)
        if isinstance(sl, int) and 1 <= sl <= 4:
            return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_WARNING,
            message="IEC 62443 target_sl is not in range 1–4; Security Level not meaningfully declared",
            location=pyfusa.Location(file=_CONFIG_FILE),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="set target_sl to 1 (casual), 2 (intentional low-resource), 3 (organised), or 4 (state-sponsored)",
        )]


class IEC62443_003(Rule):
    rule_id = "IEC62443-003"
    standard = "iec62443"
    clause = "4-2 CR 6.2"
    description = "A security policy document (SECURITY.md) is required by IEC 62443-4-2 CR 6.2."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        for name in _SEC_POLICY_FILES:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="no security policy document found — IEC 62443-4-2 CR 6.2 requires a security audit log policy",
            location=pyfusa.Location(file="SECURITY.md"),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="create SECURITY.md describing the security policy and vulnerability reporting process",
        )]


class IEC62443_004(Rule):
    rule_id = "IEC62443-004"
    standard = "iec62443"
    clause = "4-2 CR 6.2.1"
    description = "A cyber incident response plan is required by IEC 62443-4-2 CR 6.2.1."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        # Check config doc first
        doc = _load_config(project_root)
        if doc and doc.get("incident_resp_doc"):
            resp_path = doc["incident_resp_doc"]
            if os.path.exists(os.path.join(project_root, resp_path)):
                return []
        # Check well-known paths
        for name in _INCIDENT_RESP_FILES:
            if os.path.exists(os.path.join(project_root, name)):
                return []
        return [pyfusa.Finding(
            rule_id=self.rule_id, severity=pyfusa.SEVERITY_INFO,
            message="no cyber incident response plan found — IEC 62443-4-2 CR 6.2.1 requires one",
            location=pyfusa.Location(file="INCIDENT-RESPONSE.md"),
            category=pyfusa.CATEGORY_SECURITY,
            remediation="create INCIDENT-RESPONSE.md describing the incident response process",
        )]


ALL = [IEC62443_001(), IEC62443_002(), IEC62443_003(), IEC62443_004()]
