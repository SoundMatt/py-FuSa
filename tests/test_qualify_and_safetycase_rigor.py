"""Regression tests for two findings from a follow-up authenticity/quality
audit of py-FuSa's own evidence-generation code:

- qualify's "independently-qualified" badge was granted off
  `qualification_method == "independent" OR qualifier_identity` -- the `or`
  meant declaring qualification_method="self" while also setting
  --qualifier still produced the independent badge, directly contradicting
  the method the caller explicitly chose. Now requires BOTH an explicit
  "independent" declaration AND a reviewer identity that actually differs
  from the implementation author.
- safety-case's strategy argument text was a fixed template per
  standard/clause, identical for every project regardless of whether it
  had any real hazards/findings/coverage. Strategy text now cites a real
  count pulled from the evidence it references, when that evidence exists
  and parses.
"""

from __future__ import annotations

import json
import os
import tempfile

from pyfusa.config import default

# ---------------------------------------------------------------------------
# qualify badge
# ---------------------------------------------------------------------------


def test_declared_self_with_qualifier_set_is_not_independent():
    from pyfusa import qualify

    report = qualify.run(qualification_method="self", qualifier_identity="Bob")
    assert qualify._qualification_badge(report) == qualify.BADGE_SELF


def test_declared_independent_without_distinct_reviewer_is_not_independent():
    from pyfusa import qualify

    report = qualify.run(
        qualification_method="independent",
        qualifier_identity="Totally Real Auditors Inc",
        achievable_asil="ASIL-D",
    )
    assert qualify._qualification_badge(report) == qualify.BADGE_SELF


def test_declared_independent_with_same_author_and_reviewer_is_not_independent():
    from pyfusa import qualify

    report = qualify.run(
        qualification_method="independent",
        implementation_author="Alice",
        independent_reviewer="Alice",
    )
    assert qualify._qualification_badge(report) == qualify.BADGE_SELF


def test_declared_independent_with_real_distinct_reviewer_is_independent():
    from pyfusa import qualify

    report = qualify.run(
        qualification_method="independent",
        implementation_author="Alice",
        independent_reviewer="Jane Doe <jane@example.com>",
    )
    assert qualify._qualification_badge(report) == qualify.BADGE_INDEPENDENT


def test_qualify_self_tests_exercise_real_detection_not_just_plumbing():
    """§6's self-tests must include at least one that runs a real
    detection rule against real source and checks the actual finding, not
    only Finding/fingerprint serialization plumbing."""
    from pyfusa import qualify

    names = {name for name, _fn in qualify._ALL_TESTS}
    assert any("sec001" in n or "cyber" in n or "lint001" in n for n in names)
    report = qualify.run()
    assert report.failed == 0, [
        r.detail for r in report.results if r.result != "PASS"
    ]


# ---------------------------------------------------------------------------
# safety-case strategy text specificity
# ---------------------------------------------------------------------------


def test_strategy_text_varies_with_real_evidence_content():
    from pyfusa import safetycase

    with tempfile.TemporaryDirectory() as tmpdir_empty:
        cfg = default(project_name="p")
        doc_empty = safetycase.assemble(tmpdir_empty, cfg)

    with tempfile.TemporaryDirectory() as tmpdir_real:
        cfg = default(project_name="p")
        with open(os.path.join(tmpdir_real, "check-report.json"), "w") as f:
            json.dump(
                {"findings": [{"ruleId": "SEC001"}, {"ruleId": "SEC002"}]}, f
            )
        doc_real = safetycase.assemble(tmpdir_real, cfg)

    empty_texts = [n["text"] for n in doc_empty["nodes"] if n["type"] == "strategy"]
    real_texts = [n["text"] for n in doc_real["nodes"] if n["type"] == "strategy"]
    assert empty_texts != real_texts
    assert any("2 static-analysis finding" in t for t in real_texts)


def test_strategy_text_stays_generic_when_no_evidence_exists():
    """No evidence -> no fabricated claim; the strategy text falls back to
    the standard/clause description only (never invents a count for
    evidence that isn't actually there)."""
    from pyfusa import safetycase

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = safetycase.assemble(tmpdir, cfg)
    for n in doc["nodes"]:
        if n["type"] == "strategy":
            assert "—" not in n["text"]


def test_evidence_fact_handles_malformed_json_gracefully():
    from pyfusa import safetycase

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "check-report.json"), "w") as f:
            f.write("not valid json")
        assert safetycase._evidence_fact(tmpdir, "check") == ""
