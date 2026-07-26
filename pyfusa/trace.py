"""Requirements traceability engine (§5)."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

# §1.4 annotation patterns for Python
_REQ_RE = re.compile(r"#\s*fusa:req\s+(\S+)")
_TEST_RE = re.compile(r"#\s*fusa:test\s+(\S+)")
_SEC_TEST_RE = re.compile(r"#\s*fusa:sec-test\s+(\S+)")

# Tag kinds
KIND_IMPL = "impl"
KIND_TEST = "test"
KIND_SEC_TEST = "sec-test"

# Integrity levels that require HLR/LLR error (vs warn)
_ERROR_LEVELS = {"DAL-A", "ASIL-D"}
_WARN_LEVELS = {"DAL-B", "DAL-C", "ASIL-A", "ASIL-B", "ASIL-C"}


@dataclass
class Tag:
    requirement_id: str
    file: str
    line: int
    kind: str  # impl | test | sec-test

    def to_dict(self) -> dict:
        return {
            "requirementId": self.requirement_id,
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
        }


@dataclass
class Coverage:
    total_requirements: int = 0
    traced_requirements: int = 0
    tested_requirements: int = 0
    sec_tested_requirements: int = 0
    hlr_count: int = 0
    llr_count: int = 0
    hlr_with_llr: int = 0

    def to_dict(self) -> dict:
        d: dict = {
            "totalRequirements": self.total_requirements,
            "tracedRequirements": self.traced_requirements,
            "testedRequirements": self.tested_requirements,
            "secTestedRequirements": self.sec_tested_requirements,
        }
        if self.hlr_count or self.llr_count:
            d["hlrCount"] = self.hlr_count
            d["llrCount"] = self.llr_count
            d["hlrWithLlr"] = self.hlr_with_llr
        return d


@dataclass
class HLRViolation:
    """An HLR/LLR hierarchy violation."""
    kind: str   # "orphan-llr" | "empty-hlr"
    req_id: str
    detail: str


@dataclass
class Matrix:
    requirements: list[dict] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    findings: list[pyfusa.Finding] = field(default_factory=list)
    hlr_violations: list[HLRViolation] = field(default_factory=list)


def _is_excluded(rel_path: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_path, pat):
            return True
        if fnmatch.fnmatch(os.path.basename(rel_path), pat):
            return True
    return False


def _scan_annotations(project_root: str, source_dirs: list[str], exclude_patterns: list[str]) -> tuple[list[Tag], list[pyfusa.Finding]]:
    tags: list[Tag] = []
    findings: list[pyfusa.Finding] = []

    for src_dir in source_dirs:
        abs_src = os.path.normpath(os.path.join(project_root, src_dir))
        for dirpath, dirnames, filenames in os.walk(abs_src):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("__pycache__", "build", "dist")]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                abs_path = os.path.join(dirpath, fname)
                try:
                    rel_path = os.path.relpath(abs_path, project_root).replace("\\", "/")
                except ValueError:
                    rel_path = abs_path
                if _is_excluded(rel_path, exclude_patterns):
                    continue
                try:
                    with open(abs_path, encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                except OSError:
                    continue
                for lineno, line in enumerate(lines, 1):
                    for pattern, kind in ((_REQ_RE, KIND_IMPL), (_TEST_RE, KIND_TEST), (_SEC_TEST_RE, KIND_SEC_TEST)):
                        for m in pattern.finditer(line):
                            req_id = m.group(1)
                            # §1.4 — malformed annotation if multiple tokens after tag keyword
                            rest = line[m.end():].strip()
                            if rest and not rest.startswith("#"):
                                findings.append(pyfusa.Finding(
                                    rule_id="REQ002",
                                    severity=pyfusa.SEVERITY_WARNING,
                                    message=f"malformed annotation: extra tokens after requirement id '{req_id}'",
                                    location=pyfusa.Location(file=rel_path, line=lineno),
                                    category=pyfusa.CATEGORY_REQUIREMENT,
                                    remediation="put exactly one requirement id per annotation line",
                                ))
                            tags.append(Tag(requirement_id=req_id, file=rel_path, line=lineno, kind=kind))

    return tags, findings


def _validate_hlr_llr(requirements: list[dict]) -> list[HLRViolation]:
    """Validate HLR/LLR hierarchy: every LLR needs a valid parent, every HLR needs a child."""
    violations: list[HLRViolation] = []
    hlr_ids = {r.get("id", "") for r in requirements if r.get("level", "").upper() == "HLR"}
    llr_by_parent: dict[str, list[str]] = {hid: [] for hid in hlr_ids}

    for req in requirements:
        level = req.get("level", "").upper()
        rid = req.get("id", "")
        if level == "LLR":
            parent = req.get("parent_id", "")
            if not parent:
                violations.append(HLRViolation(
                    kind="orphan-llr",
                    req_id=rid,
                    detail=f"LLR '{rid}' has no parent_id",
                ))
            elif parent not in hlr_ids:
                violations.append(HLRViolation(
                    kind="orphan-llr",
                    req_id=rid,
                    detail=f"LLR '{rid}' references unknown HLR '{parent}'",
                ))
            else:
                llr_by_parent[parent].append(rid)

    for hlr_id, children in llr_by_parent.items():
        if not children:
            violations.append(HLRViolation(
                kind="empty-hlr",
                req_id=hlr_id,
                detail=f"HLR '{hlr_id}' has no LLR children",
            ))

    return violations


def build(project_root: str, cfg: Config | None = None, strict_hlr_llr: bool = False) -> Matrix:  # fusa:req REQ-TRACE001
    if cfg is None:
        from pyfusa.config import default
        cfg = default()

    # Load requirements
    reqs_path = os.path.join(project_root, ".fusa-reqs.json")
    requirements: list[dict] = []
    if os.path.exists(reqs_path):
        try:
            with open(reqs_path, encoding="utf-8") as f:
                data = json.load(f)
            requirements = data.get("requirements", [])
        except (json.JSONDecodeError, OSError):
            pass

    # Scan annotations
    tags, ann_findings = _scan_annotations(project_root, cfg.source_dirs, cfg.exclude_patterns)

    # Compute coverage (§5)
    req_ids = {r.get("id", "") for r in requirements}
    req_tags: dict[str, set[str]] = {rid: set() for rid in req_ids}
    for tag in tags:
        if tag.requirement_id in req_tags:
            req_tags[tag.requirement_id].add(tag.kind)

    total = len(requirements)
    traced = sum(1 for kinds in req_tags.values() if kinds)
    tested = sum(1 for kinds in req_tags.values() if KIND_TEST in kinds or KIND_SEC_TEST in kinds)
    sec_tested = sum(1 for kinds in req_tags.values() if KIND_SEC_TEST in kinds)

    # HLR/LLR metrics
    hlr_count = sum(1 for r in requirements if r.get("level", "").upper() == "HLR")
    llr_count = sum(1 for r in requirements if r.get("level", "").upper() == "LLR")
    # Count HLRs that have at least one LLR child
    llr_parents = {r.get("parent_id", "") for r in requirements if r.get("level", "").upper() == "LLR"}
    hlr_with_llr = sum(1 for r in requirements if r.get("level", "").upper() == "HLR" and r.get("id", "") in llr_parents)

    cov = Coverage(
        total_requirements=total,
        traced_requirements=traced,
        tested_requirements=tested,
        sec_tested_requirements=sec_tested,
        hlr_count=hlr_count,
        llr_count=llr_count,
        hlr_with_llr=hlr_with_llr,
    )

    # Validate HLR/LLR hierarchy (only when there are both HLRs and LLRs)
    violations: list[HLRViolation] = []
    if hlr_count > 0 and llr_count > 0:
        violations = _validate_hlr_llr(requirements)

    # Emit findings for violations based on integrity level
    integrity_level = cfg.asil or cfg.dal or ""
    hlr_findings: list[pyfusa.Finding] = []
    if violations:
        sev = pyfusa.SEVERITY_ERROR if (strict_hlr_llr or integrity_level in _ERROR_LEVELS) else pyfusa.SEVERITY_WARNING
        for v in violations:
            hlr_findings.append(pyfusa.Finding(
                rule_id="REQ003",
                severity=sev,
                message=v.detail,
                location=pyfusa.Location(file=".fusa-reqs.json"),
                category=pyfusa.CATEGORY_REQUIREMENT,
                remediation="ensure every LLR has a valid parent_id referencing an HLR, and every HLR has at least one LLR child",
            ))

    return Matrix(
        requirements=requirements,
        tags=tags,
        coverage=cov,
        findings=ann_findings + hlr_findings,
        hlr_violations=violations,
    )


def to_dict(matrix: Matrix, project_root: str, cfg: Config, gaps_only: bool = False) -> dict:  # fusa:req REQ-TRACE001
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    reqs = matrix.requirements
    tags = matrix.tags
    cov = matrix.coverage

    if gaps_only:
        # Filter to requirements with no test or sec-test tag
        tested_ids = {t.requirement_id for t in tags if t.kind in (KIND_TEST, KIND_SEC_TEST)}
        reqs = [r for r in reqs if r.get("id", "") not in tested_ids]
        tags = [t for t in tags if t.requirement_id in {r.get("id") for r in reqs}]

    doc: dict = {
        "schemaVersion": SPEC_VERSION,
        "kind": "trace-matrix",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": cfg.project.name,
        "standard": cfg.standard,
        "requirements": reqs,
        "tags": [t.to_dict() for t in tags],
        "coverage": cov.to_dict(),
    }
    if matrix.hlr_violations:
        doc["hlrViolations"] = [
            {"kind": v.kind, "reqId": v.req_id, "detail": v.detail}
            for v in matrix.hlr_violations
        ]
    return doc


def render_text(matrix: Matrix, gaps_only: bool = False) -> str:  # fusa:req REQ-TRACE001
    lines: list[str] = []
    cov = matrix.coverage

    tags_by_req: dict[str, list[Tag]] = {}
    for tag in matrix.tags:
        tags_by_req.setdefault(tag.requirement_id, []).append(tag)

    if gaps_only:
        tested_ids = {t.requirement_id for t in matrix.tags if t.kind in (KIND_TEST, KIND_SEC_TEST)}
        reqs = [r for r in matrix.requirements if r.get("id", "") not in tested_ids]
        lines.append("Requirements with no test coverage (gaps):")
    else:
        reqs = matrix.requirements
        lines.append("Requirements Traceability Matrix")
        lines.append("=" * 40)

    # Group by HLR/LLR hierarchy for rendering
    hlr_ids = {r.get("id", "") for r in reqs if r.get("level", "").upper() == "HLR"}
    llrs_by_parent: dict[str, list[dict]] = {}
    standalone: list[dict] = []
    for req in reqs:
        level = req.get("level", "").upper()
        parent = req.get("parent_id", "")
        if level == "LLR" and parent in hlr_ids:
            llrs_by_parent.setdefault(parent, []).append(req)
        elif level != "LLR" or not parent:
            standalone.append(req)

    def _req_line(req: dict, indent: str = "  ") -> str:
        rid = req.get("id", "?")
        title = req.get("title", "")
        rtags = tags_by_req.get(rid, [])
        impl_count = sum(1 for t in rtags if t.kind == KIND_IMPL)
        test_count = sum(1 for t in rtags if t.kind in (KIND_TEST, KIND_SEC_TEST))
        status = "TESTED" if test_count else ("IMPL" if impl_count else "GAP")
        level_tag = req.get("level", "")
        level_str = f"[{level_tag}] " if level_tag else ""
        return f"{indent}{rid:30s} {status:8s}  {level_str}{title}"

    for req in standalone:
        rid = req.get("id", "?")
        lines.append(_req_line(req))
        # Emit children under this HLR
        for child in llrs_by_parent.get(rid, []):
            lines.append(_req_line(child, indent="    "))

    if not gaps_only:
        lines.append("")
        lines.append(f"Coverage: {cov.traced_requirements}/{cov.total_requirements} traced, "
                     f"{cov.tested_requirements}/{cov.total_requirements} tested")
        if cov.hlr_count:
            lines.append(f"Hierarchy: {cov.hlr_count} HLRs, {cov.llr_count} LLRs, "
                         f"{cov.hlr_with_llr}/{cov.hlr_count} HLRs have LLR children")
        if matrix.hlr_violations:
            lines.append("")
            lines.append(f"HLR/LLR violations ({len(matrix.hlr_violations)}):")
            for v in matrix.hlr_violations:
                lines.append(f"  [{v.kind}] {v.detail}")

    return "\n".join(lines)
