"""Evidence presence engine rules — checks that generated artefacts exist."""

from __future__ import annotations

import json
import os
from typing import List

import pyfusa
from pyfusa.config import Config, load_dispositions
from pyfusa.rules import Rule

# NOTE (x-FuSa spec §1.6.1 "Who runs this" — MUST): the §1.6/§1.6.1
# content-quality baseline (FUSA-STUB001/002, placeholder-text and
# blanket-qualitative-fallback detection) intentionally has NO rule here.
# Detection runs *inside* each artifact-producing command (fmea/hara/tara/
# safety-case/sas — see pyfusa/content_quality.py, wired into each of those
# modules' own `quality_findings()`), gating that command's own exit code —
# never `check`'s. `check` analyzes source/config; it does not read sibling
# evidence artifacts (fmea.json, tara.json, etc.) as part of this section.
# An earlier revision added FUSASTUB001/002 Rule classes here that scanned
# those committed sibling files and fed `check`'s own exit code — that
# contradicted the spec and has been removed.


# ── Release artefacts ─────────────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE001
class RELEASE001(Rule):
    rule_id = "RELEASE001"
    standard = "iso26262"
    clause = "13.3"
    description = "Project should have an sbom.json Software Bill of Materials."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "sbom.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_WARNING,
                message="no sbom.json Software Bill of Materials found",
                location=pyfusa.Location(file="sbom.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa release' to generate the SBOM",
            )
        ]


# fusa:req REQ-EVIDENCE002
class RELEASE002(Rule):
    rule_id = "RELEASE002"
    standard = "iso26262"
    clause = "13.3"
    description = "Project should have a provenance.json build provenance record."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "provenance.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_WARNING,
                message="no provenance.json build provenance record found",
                location=pyfusa.Location(file="provenance.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa release' to generate the provenance record",
            )
        ]


# ── Tool qualification ────────────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE003
class QUALIFY001(Rule):
    rule_id = "QUALIFY001"
    standard = "iso26262"
    clause = "8.4"
    description = "Tool qualification evidence (qualify-report.json) should be present."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "qualify-report.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="qualify-report.json not found — tool qualification evidence is absent",
                location=pyfusa.Location(file="qualify-report.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa qualify' to generate tool qualification evidence",
            )
        ]


# ── Safety analysis artefacts ─────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE004
class FMEA001(Rule):
    rule_id = "FMEA001"
    standard = "iso26262"
    clause = "7.5"
    description = "FMEA analysis (fmea.json) should be present."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "fmea.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="fmea.json not found — run 'pyfusa fmea' to generate the dFMEA table",
                location=pyfusa.Location(file="fmea.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa fmea'",
            )
        ]


# fusa:req REQ-EVIDENCE005
class TARA001(Rule):
    rule_id = "TARA001"
    standard = "iso21434"
    clause = "8"
    description = "TARA cybersecurity risk assessment (tara.json) should be present."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "tara.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="no tara.json found — run 'pyfusa tara' to generate the TARA",
                location=pyfusa.Location(file="tara.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa tara' to generate tara.json from CYBER findings",
            )
        ]


# fusa:req REQ-EVIDENCE006
class BOUNDARY001(Rule):
    rule_id = "BOUNDARY001"
    standard = "iso26262"
    clause = "7.2"
    description = (
        "System boundary diagram (boundary.json / .mermaid / .dot) should be present."
    )

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        for f in ("boundary.json", "boundary.mermaid", "boundary.dot"):
            if os.path.exists(os.path.join(project_root, f)):
                return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="boundary diagram not found — run 'pyfusa boundary' to generate one",
                location=pyfusa.Location(file="boundary.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa boundary'",
            )
        ]


# fusa:req REQ-EVIDENCE007
class SAFETYCASE001(Rule):
    rule_id = "SAFETYCASE001"
    standard = "iec61508"
    clause = "7.4"
    description = "Safety case (safety-case.json) should be assembled."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "safety-case.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="no safety-case.json found — safety case not yet assembled",
                location=pyfusa.Location(file="safety-case.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa safety-case'",
            )
        ]


# fusa:req REQ-EVIDENCE008
class AUDITPACK001(Rule):
    rule_id = "AUDITPACK001"
    standard = "iso26262"
    clause = "13.3"
    description = "Audit pack bundle (audit-pack.zip) should be present."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, "audit-pack.zip")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="audit-pack.zip not found — run 'pyfusa audit-pack' to bundle all evidence",
                location=pyfusa.Location(file="audit-pack.zip"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa audit-pack'",
            )
        ]


# ── Test evidence ─────────────────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE009
class VERIFY001(Rule):
    rule_id = "VERIFY001"
    standard = "do178c"
    clause = "11.4"
    description = "Test evidence bundle (.fusa-evidence.json) should be present."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        if os.path.exists(os.path.join(project_root, ".fusa-evidence.json")):
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_INFO,
                message="no .fusa-evidence.json test evidence bundle found",
                location=pyfusa.Location(file=".fusa-evidence.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa verify' to generate the test evidence bundle",
            )
        ]


# fusa:req REQ-EVIDENCE010
class VERIFY002(Rule):
    rule_id = "VERIFY002"
    standard = "do178c"
    clause = "11.4"
    description = "Test evidence bundle must report zero failed tests."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-evidence.json")
        if not os.path.exists(path):
            return []  # VERIFY001 handles missing bundle
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        s = doc.get("summary", {})
        failed = s.get("failed", 0) + s.get("errored", 0)
        total = s.get("total", 0)
        if failed == 0:
            return []
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=pyfusa.SEVERITY_WARNING,
                message=f"evidence bundle reports {failed} failed test(s) out of {total} total",
                location=pyfusa.Location(file=".fusa-evidence.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="fix failing tests and regenerate with 'pyfusa verify'",
            )
        ]


# ── HARA engine rules ─────────────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE011
class HARA001(Rule):
    rule_id = "HARA001"
    standard = "iso26262"
    clause = "7.4"
    description = (
        "HARA file (.fusa-hara.json) should be present for functional-safety standards."
    )

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-hara.json")
        if os.path.exists(path):
            return []
        sev = (
            pyfusa.SEVERITY_WARNING
            if cfg.standard in ("iso26262", "iec61508")
            else pyfusa.SEVERITY_INFO
        )
        return [
            pyfusa.Finding(
                rule_id=self.rule_id,
                severity=sev,
                message=".fusa-hara.json not found — hazard analysis evidence is absent",
                location=pyfusa.Location(file=".fusa-hara.json"),
                category=pyfusa.CATEGORY_CONFIG,
                remediation="run 'pyfusa hara init' to create a HARA template",
            )
        ]


# fusa:req REQ-EVIDENCE012
class HARA002(Rule):
    standard = "iso26262"
    clause = "7.4"
    rule_id = "HARA002"
    description = "Every hazard must have a complete risk rating (severity, exposure, controllability)."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-hara.json")
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        findings = []
        for h in doc.get("hazards", []):
            risk = h.get("risk", {})
            if not (
                risk.get("severity")
                and risk.get("exposure")
                and risk.get("controllability")
            ):
                findings.append(
                    pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message=f"hazard {h.get('id', '')} has incomplete risk rating — S, E, and C must all be set",
                        location=pyfusa.Location(file=".fusa-hara.json"),
                        category=pyfusa.CATEGORY_CONFIG,
                        remediation="set severity, exposure, and controllability for every hazard",
                    )
                )
        return findings


# fusa:req REQ-EVIDENCE013
class HARA003(Rule):
    standard = "iso26262"
    clause = "7.4"
    rule_id = "HARA003"
    description = "Every hazard must be linked to at least one safety goal."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-hara.json")
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        goal_ids = {g["id"] for g in doc.get("safetyGoals", [])}
        findings = []
        for h in doc.get("hazards", []):
            if not h.get("safetyGoals"):
                findings.append(
                    pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message=f"hazard {h.get('id', '')} has no linked safety goal",
                        location=pyfusa.Location(file=".fusa-hara.json"),
                        category=pyfusa.CATEGORY_CONFIG,
                        remediation="link every hazard to at least one safety goal",
                    )
                )
            for gid in h.get("safetyGoals", []):
                if gid not in goal_ids:
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message=f"hazard {h.get('id', '')} references unknown safety goal {gid}",
                            location=pyfusa.Location(file=".fusa-hara.json"),
                            category=pyfusa.CATEGORY_CONFIG,
                            remediation=f"add safety goal {gid} to safetyGoals list",
                        )
                    )
        return findings


# fusa:req REQ-EVIDENCE014
class HARA004(Rule):
    standard = "iso26262"
    clause = "7.4"
    rule_id = "HARA004"
    description = "Every safety goal must have an ASIL assigned."

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-hara.json")
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        findings = []
        for g in doc.get("safetyGoals", []):
            if not g.get("asil"):
                findings.append(
                    pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message=f"safety goal {g.get('id', '')} has no ASIL assigned",
                        location=pyfusa.Location(file=".fusa-hara.json"),
                        category=pyfusa.CATEGORY_CONFIG,
                        remediation="assign an ASIL (QM, ASIL-A … ASIL-D) to every safety goal",
                    )
                )
        return findings


# fusa:req REQ-EVIDENCE015
class HARA005(Rule):
    standard = "iso26262"
    clause = "7.4"
    rule_id = "HARA005"
    description = "Safety goal ASIL must not exceed the project ASIL ceiling."

    _RANK = {"QM": 0, "ASIL-A": 1, "ASIL-B": 2, "ASIL-C": 3, "ASIL-D": 4}

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        path = os.path.join(project_root, ".fusa-hara.json")
        project_asil = cfg.asil or "ASIL-B"
        project_rank = self._RANK.get(project_asil, 2)
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        findings = []
        for g in doc.get("safetyGoals", []):
            asil = g.get("asil", "")
            if self._RANK.get(asil, 0) > project_rank:
                findings.append(
                    pyfusa.Finding(
                        rule_id=self.rule_id,
                        severity=pyfusa.SEVERITY_WARNING,
                        message=f"safety goal {g.get('id', '')} ASIL {asil} exceeds project ASIL {project_asil}",
                        location=pyfusa.Location(file=".fusa-hara.json"),
                        category=pyfusa.CATEGORY_CONFIG,
                        remediation="increase project ASIL in .fusa.json or lower the safety goal ASIL",
                    )
                )
        return findings


# ── Disposition rule ──────────────────────────────────────────────────────────


# fusa:req REQ-EVIDENCE016
class DISP001(Rule):
    standard = "iso26262"
    clause = "4.1"
    rule_id = "DISP001"
    description = (
        "Every ERROR finding in check-report.json must have a disposition entry."
    )

    def run(self, project_root: str, cfg: Config) -> List[pyfusa.Finding]:
        check_path = os.path.join(project_root, "check-report.json")
        if not os.path.exists(check_path):
            return [
                pyfusa.Finding(
                    rule_id=self.rule_id,
                    severity=pyfusa.SEVERITY_INFO,
                    message="check-report.json not found — run 'pyfusa check' first",
                    location=pyfusa.Location(file="check-report.json"),
                    category=pyfusa.CATEGORY_CONFIG,
                    remediation="run 'pyfusa check --output check-report.json'",
                )
            ]
        try:
            with open(check_path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

        findings_list = doc.get("findings", [])
        # Use the shared §1.2.3 reader — it already knows the canonical
        # {"dispositions": [...]} shape. Reading this file "raw" here used to
        # crash (the parsed document is an object, not a list) whenever a
        # real .fusa-dispositions.json was present; the crash was silently
        # swallowed by engine.py's per-rule try/except.
        disp_path = os.path.join(project_root, ".fusa-dispositions.json")
        dispositions = load_dispositions(disp_path)

        disposed_fps = {
            d.get("fingerprint", "") for d in dispositions if d.get("fingerprint")
        }
        disposed_rules = {
            d.get("ruleId", "")
            for d in dispositions
            if not d.get("fingerprint") and d.get("ruleId")
        }

        result = []
        for f in findings_list:
            if f.get("severity") != "ERROR":
                continue
            disp = f.get("disposition", "")
            if disp in ("accepted", "deferred"):
                continue
            fp = f.get("fingerprint", "")
            rule_id = f.get("ruleId", "")
            if fp and fp in disposed_fps:
                continue
            if rule_id and rule_id in disposed_rules:
                continue
            result.append(
                pyfusa.Finding(
                    rule_id=self.rule_id,
                    severity=pyfusa.SEVERITY_WARNING,
                    message=f"ERROR finding {rule_id} has no disposition entry in .fusa-dispositions.json",
                    location=pyfusa.Location(
                        file="check-report.json", line=f.get("location", {}).get("line")
                    ),
                    category=pyfusa.CATEGORY_CONFIG,
                    remediation="run 'pyfusa disposition add' to accept or defer this finding",
                )
            )
        return result


ALL = [
    RELEASE001(),
    RELEASE002(),
    QUALIFY001(),
    FMEA001(),
    TARA001(),
    BOUNDARY001(),
    SAFETYCASE001(),
    AUDITPACK001(),
    VERIFY001(),
    VERIFY002(),
    HARA001(),
    HARA002(),
    HARA003(),
    HARA004(),
    HARA005(),
    DISP001(),
]
