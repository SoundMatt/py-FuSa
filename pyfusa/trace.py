"""Requirements traceability engine (§5)."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from datetime import timezone, datetime

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

    def to_dict(self) -> dict:
        return {
            "totalRequirements": self.total_requirements,
            "tracedRequirements": self.traced_requirements,
            "testedRequirements": self.tested_requirements,
            "secTestedRequirements": self.sec_tested_requirements,
        }


@dataclass
class Matrix:
    requirements: list[dict] = field(default_factory=list)
    tags: list[Tag] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    findings: list[pyfusa.Finding] = field(default_factory=list)


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


def build(project_root: str, cfg: Config | None = None) -> Matrix:
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

    cov = Coverage(
        total_requirements=total,
        traced_requirements=traced,
        tested_requirements=tested,
        sec_tested_requirements=sec_tested,
    )

    return Matrix(
        requirements=requirements,
        tags=tags,
        coverage=cov,
        findings=ann_findings,
    )


def to_dict(matrix: Matrix, project_root: str, cfg: Config, gaps_only: bool = False) -> dict:
    from pyfusa import VERSION, SPEC_VERSION, LANGUAGE, TOOL
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    reqs = matrix.requirements
    tags = matrix.tags
    cov = matrix.coverage

    if gaps_only:
        # Filter to requirements with no test or sec-test tag
        tested_ids = {t.requirement_id for t in tags if t.kind in (KIND_TEST, KIND_SEC_TEST)}
        reqs = [r for r in reqs if r.get("id", "") not in tested_ids]
        tags = [t for t in tags if t.requirement_id in {r.get("id") for r in reqs}]

    return {
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


def render_text(matrix: Matrix, gaps_only: bool = False) -> str:
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

    for req in reqs:
        rid = req.get("id", "?")
        title = req.get("title", "")
        rtags = tags_by_req.get(rid, [])
        impl_count = sum(1 for t in rtags if t.kind == KIND_IMPL)
        test_count = sum(1 for t in rtags if t.kind in (KIND_TEST, KIND_SEC_TEST))
        status = "TESTED" if test_count else ("IMPL" if impl_count else "GAP")
        lines.append(f"  {rid:30s} {status:8s}  {title}")

    if not gaps_only:
        lines.append("")
        lines.append(f"Coverage: {cov.traced_requirements}/{cov.total_requirements} traced, "
                     f"{cov.tested_requirements}/{cov.total_requirements} tested")

    return "\n".join(lines)
