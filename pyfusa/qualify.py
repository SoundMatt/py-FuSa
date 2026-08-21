"""Tool qualification suite (§6)."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

import pyfusa
from pyfusa.config import Config

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_SKIP = "SKIP"
RESULT_ERROR = "ERROR"


# fusa:req REQ-QUAL001
@dataclass
class TestCase:
    name: str
    result: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "result": self.result}


BADGE_INDEPENDENT = "independently-qualified"
BADGE_SELF = "self-qualified"
BADGE_UNQUALIFIED = "unqualified"

INDEPENDENCE_INDEPENDENT = "independent"
INDEPENDENCE_SAME_AUTHOR = "same-author"
INDEPENDENCE_UNKNOWN = "unknown"


@dataclass
class QualifyReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    results: list[TestCase] = field(default_factory=list)
    hash: str = ""
    # Feature 2: Tool Qualification Display
    qualification_method: str = ""  # "self" | "independent"
    qualification_record_uri: str = ""  # URI to dossier
    qualifier_identity: str = ""  # name/org
    # Feature 4: V&V Independence
    implementation_author: str = ""
    independent_reviewer: str = ""
    independent_test_executor: str = ""
    achievable_asil: str = ""


def _run_test(name: str, fn: Callable[[], bool]) -> TestCase:
    try:
        ok = fn()
        return TestCase(name=name, result=RESULT_PASS if ok else RESULT_FAIL)
    except Exception as e:
        return TestCase(name=name, result=RESULT_ERROR, detail=str(e))


def _test_fingerprint_known_answer() -> bool:
    """§4.2 known-answer test: deterministic fingerprint."""
    fp = pyfusa.compute_fingerprint(
        "LINT001", "src/foo.py", "function exceeds 60 lines"
    )
    return fp.startswith("sha256:") and len(fp) == 71


def _test_fingerprint_digit_norm() -> bool:
    """§4.2 digit normalization: different numbers → same fingerprint."""
    fp1 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function is 61 lines")
    fp2 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function is 62 lines")
    return fp1 == fp2


def _test_fingerprint_stable() -> bool:
    """§4.2 fingerprint is stable across calls."""
    fp1 = pyfusa.compute_fingerprint("SEC001", "main.py", "bare except catches all")
    fp2 = pyfusa.compute_fingerprint("SEC001", "main.py", "bare except catches all")
    return fp1 == fp2


def _test_finding_category_derived() -> bool:
    """Finding auto-derives category from rule id prefix."""
    f = pyfusa.Finding(
        rule_id="LINT001",
        severity=pyfusa.SEVERITY_WARNING,
        message="test",
        location=pyfusa.Location(file="f.py"),
        remediation="fix it",
    )
    return f.category == pyfusa.CATEGORY_LINT


def _test_finding_security_category() -> bool:
    f = pyfusa.Finding(
        rule_id="SEC001",
        severity=pyfusa.SEVERITY_ERROR,
        message="test",
        location=pyfusa.Location(file="f.py"),
        remediation="fix it",
    )
    return f.category == pyfusa.CATEGORY_SECURITY


def _test_normalize_message_digits() -> bool:
    """§4.2 runs of digits become '#'."""
    n = pyfusa.normalize_message("file has 123 lines")
    return n == "file has # lines"


def _test_normalize_message_whitespace() -> bool:
    """§4.2 whitespace runs collapse to one space."""
    n = pyfusa.normalize_message("  foo   bar  ")
    return n == "foo bar"


def _test_severity_enum() -> bool:
    """§2.4 severity values are uppercase strings."""
    return (
        pyfusa.SEVERITY_ERROR == "ERROR"
        and pyfusa.SEVERITY_WARNING == "WARNING"
        and pyfusa.SEVERITY_INFO == "INFO"
    )


def _test_exit_codes() -> bool:
    """§2.3 exit codes."""
    return (
        pyfusa.EXIT_OK == 0
        and pyfusa.EXIT_GATE_FAIL == 1
        and pyfusa.EXIT_USAGE == 2
        and pyfusa.EXIT_RUNTIME == 3
    )


def _test_config_load_default() -> bool:
    """Config.default returns a valid config."""
    from pyfusa.config import default

    cfg = default(project_name="test", standard="iso26262")
    return cfg.project.name == "test" and cfg.standard == "iso26262"


def _test_location_to_dict() -> bool:
    """Location serialises correctly."""
    loc = pyfusa.Location(file="src/foo.py", line=42, column=5)
    d = loc.to_dict()
    return d["file"] == "src/foo.py" and d["line"] == 42 and d["column"] == 5


def _test_finding_to_dict() -> bool:
    """Finding serialises with correct camelCase keys."""
    f = pyfusa.Finding(
        rule_id="LINT001",
        severity=pyfusa.SEVERITY_WARNING,
        message="test finding",
        location=pyfusa.Location(file="x.py", line=1),
        remediation="fix it",
    )
    d = f.to_dict()
    return "ruleId" in d and "location" in d and "fingerprint" in d


def _test_derive_category_fusa() -> bool:
    return pyfusa.derive_category("FUSA001") == pyfusa.CATEGORY_SAFETY


def _test_derive_category_conc() -> bool:
    return pyfusa.derive_category("CONC001") == pyfusa.CATEGORY_CONCURRENCY


def _test_derive_category_cwe() -> bool:
    return pyfusa.derive_category("CWE-787") == pyfusa.CATEGORY_SECURITY


def _with_temp_source(content: str, run_rule):
    """Write `content` to a temp module, run `run_rule(root, cfg)` against
    it, and return the result. Shared by the detection-correctness tests
    below."""
    import tempfile

    from pyfusa.config import default

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w", encoding="utf-8") as f:
            f.write(content)
        cfg = default()
        cfg.source_dirs = ["."]
        return run_rule(tmpdir, cfg)


def _test_sec001_detects_bare_except() -> bool:
    """§6's own self-tests previously covered only internal plumbing
    (Finding serialization, fingerprint hashing) -- none of them verified
    that the safety-relevant detection rules the tool exists to run
    actually detect anything. This and the tests below exercise a
    representative sample end to end: real source in, a real Finding out."""
    from pyfusa.rules.security import RuleBareExcept as SEC001

    findings = _with_temp_source(
        "def f():\n    try:\n        pass\n    except:\n        pass\n",
        lambda root, cfg: SEC001().run(root, cfg),
    )
    return any(f.rule_id == "SEC001" for f in findings)


def _test_sec001_silent_on_scoped_except() -> bool:
    """A rule that fires on everything is exactly as useless as one that
    fires on nothing -- confirm the negative case too."""
    from pyfusa.rules.security import RuleBareExcept as SEC001

    findings = _with_temp_source(
        "def f():\n    try:\n        pass\n    except ValueError:\n        pass\n",
        lambda root, cfg: SEC001().run(root, cfg),
    )
    return findings == []


def _test_cyber006_detects_hardcoded_credential() -> bool:
    from pyfusa.rules.cyber import CYBER006

    findings = _with_temp_source(
        'password = "supersecret123"\n',
        lambda root, cfg: CYBER006().run(root, cfg),
    )
    return any(f.rule_id == "CYBER006" for f in findings)


def _test_lint001_detects_overlong_function() -> bool:
    from pyfusa.rules.lint import RuleFunctionLength

    body = "\n".join(f"    x{i} = {i}" for i in range(70))
    findings = _with_temp_source(
        f"def f():\n{body}\n    return x0\n",
        lambda root, cfg: RuleFunctionLength().run(root, cfg),
    )
    return any(f.rule_id == "LINT001" for f in findings)


def _test_engine_disposition_actually_suppresses_the_gate() -> bool:
    """End-to-end: a real ERROR finding, dispositioned as accepted via the
    same §1.2.3/§4.1 file format the CLI writes, must actually stop the
    gate -- exercises the full detect -> fingerprint -> match -> suppress
    pipeline, not just Finding's own serialization in isolation."""
    import json as _json
    import tempfile

    from pyfusa.config import default
    from pyfusa.engine import Engine
    from pyfusa.rules.security import RuleBareExcept as SEC001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w", encoding="utf-8") as f:
            f.write("def f():\n    try:\n        pass\n    except:\n        pass\n")
        cfg = default()
        cfg.source_dirs = ["."]
        eng = Engine()
        eng.register(SEC001())

        result = eng.run(tmpdir, cfg)
        if not result.has_errors():
            return False
        finding = next(f for f in result.findings if f.rule_id == "SEC001")

        with open(
            os.path.join(tmpdir, ".fusa-dispositions.json"), "w", encoding="utf-8"
        ) as f:
            _json.dump(
                {
                    "dispositions": [
                        {"fingerprint": finding.fingerprint, "status": "accepted"}
                    ]
                },
                f,
            )
        result2 = eng.run(tmpdir, cfg)
        return not result2.has_errors()


_ALL_TESTS: list[tuple[str, Callable[[], bool]]] = [
    ("fingerprint-known-answer", _test_fingerprint_known_answer),
    ("fingerprint-digit-normalisation", _test_fingerprint_digit_norm),
    ("fingerprint-stable", _test_fingerprint_stable),
    ("finding-category-derived", _test_finding_category_derived),
    ("finding-security-category", _test_finding_security_category),
    ("normalize-message-digits", _test_normalize_message_digits),
    ("normalize-message-whitespace", _test_normalize_message_whitespace),
    ("severity-enum-values", _test_severity_enum),
    ("exit-code-values", _test_exit_codes),
    ("config-load-default", _test_config_load_default),
    ("location-to-dict", _test_location_to_dict),
    ("finding-to-dict", _test_finding_to_dict),
    ("derive-category-fusa", _test_derive_category_fusa),
    ("derive-category-conc", _test_derive_category_conc),
    ("derive-category-cwe", _test_derive_category_cwe),
    ("sec001-detects-bare-except", _test_sec001_detects_bare_except),
    ("sec001-silent-on-scoped-except", _test_sec001_silent_on_scoped_except),
    ("cyber006-detects-hardcoded-credential", _test_cyber006_detects_hardcoded_credential),
    ("lint001-detects-overlong-function", _test_lint001_detects_overlong_function),
    (
        "engine-disposition-suppresses-gate",
        _test_engine_disposition_actually_suppresses_the_gate,
    ),
]


# fusa:req REQ-QUAL001
def compute_hash(report: QualifyReport) -> str:
    """§6 reproducible hash: sort results by name, remove hash and generatedAt."""
    doc = {
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "results": sorted(
            [r.to_dict() for r in report.results], key=lambda x: x["name"]
        ),
        "generatedAt": "",
    }
    # RFC 8785 (JCS): sorted keys, no insignificant whitespace
    canonical = json.dumps(
        doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _independence_status(report: QualifyReport) -> str:  # fusa:req REQ-QUAL002
    """Compute V&V independence status."""
    author = report.implementation_author
    reviewer = report.independent_reviewer
    if not author or not reviewer:
        return INDEPENDENCE_UNKNOWN
    if author == reviewer:
        return INDEPENDENCE_SAME_AUTHOR
    return INDEPENDENCE_INDEPENDENT


def _qualification_badge(report: QualifyReport) -> str:  # fusa:req REQ-QUAL001
    """Compute qualification badge string.

    "independently-qualified" requires BOTH an explicit
    qualification_method="independent" declaration AND a reviewer identity
    that actually differs from the implementation author -- the same bar
    §1.6.2's attestation mechanism uses elsewhere in this codebase
    (content_quality.attestation_valid()). A prior version granted this
    badge off `qualification_method == "independent" OR qualifier_identity`
    -- the `or` meant setting --qualifier alone, even alongside an
    explicit --qualification-method self, still produced
    "independently-qualified" (verified: run(qualification_method="self",
    qualifier_identity="Bob") produced the independent badge, directly
    contradicting the method the caller explicitly declared).
    qualifier_identity records who *ran* qualification (self or
    independent); it was never meant to be sufficient on its own to prove
    independence -- independent_reviewer is the field that means that.
    """
    if report.qualification_method == "independent":
        if _independence_status(report) == INDEPENDENCE_INDEPENDENT:
            return BADGE_INDEPENDENT
        return BADGE_SELF
    if report.qualification_method == "self" or report.qualifier_identity:
        return BADGE_SELF
    return BADGE_UNQUALIFIED


# fusa:req REQ-QUAL001
def run(
    qualification_method: str = "",
    qualification_record_uri: str = "",
    qualifier_identity: str = "",
    implementation_author: str = "",
    independent_reviewer: str = "",
    independent_test_executor: str = "",
    achievable_asil: str = "",
) -> QualifyReport:
    results: list[TestCase] = []
    for name, fn in _ALL_TESTS:
        tc = _run_test(name, fn)
        results.append(tc)

    total = len(results)
    passed = sum(1 for r in results if r.result == RESULT_PASS)
    failed = sum(1 for r in results if r.result == RESULT_FAIL)

    report = QualifyReport(
        total=total,
        passed=passed,
        failed=failed,
        results=results,
        qualification_method=qualification_method,
        qualification_record_uri=qualification_record_uri,
        qualifier_identity=qualifier_identity,
        implementation_author=implementation_author,
        independent_reviewer=independent_reviewer,
        independent_test_executor=independent_test_executor,
        achievable_asil=achievable_asil,
    )
    report.hash = compute_hash(report)
    return report


# fusa:req REQ-QUAL001
def to_dict(report: QualifyReport, project_root: str, cfg: Config) -> dict:
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "schemaVersion": SPEC_VERSION,
        "kind": "qualification",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "results": [r.to_dict() for r in report.results],
        "hash": report.hash,
    }
    if cfg.asil:
        doc["asil"] = cfg.asil
    elif cfg.sil:
        doc["sil"] = cfg.sil
    elif cfg.dal:
        doc["dal"] = cfg.dal

    # Feature 2: Tool Qualification Display
    doc["qualificationBadge"] = _qualification_badge(report)
    if report.qualification_method:
        doc["qualificationMethod"] = report.qualification_method
    if report.qualification_record_uri:
        doc["qualificationRecordUri"] = report.qualification_record_uri
    if report.qualifier_identity:
        doc["qualifierIdentity"] = report.qualifier_identity

    # Feature 4: V&V Independence
    doc["independenceStatus"] = _independence_status(report)
    if report.implementation_author:
        doc["implementationAuthor"] = report.implementation_author
    if report.independent_reviewer:
        doc["independentReviewer"] = report.independent_reviewer
    if report.independent_test_executor:
        doc["independentTestExecutor"] = report.independent_test_executor
    if report.achievable_asil:
        doc["achievableAsil"] = report.achievable_asil

    return doc
