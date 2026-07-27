"""Targeted tests to boost coverage on low-coverage modules."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pytest
import pyfusa
from pyfusa.cli.main import run
from pyfusa.config import (
    Config,
    ProjectConfig,
    default,
    load,
    load_dispositions,
    load_requirements,
)


# ---------------------------------------------------------------------------
# verify.py
# ---------------------------------------------------------------------------


def _make_verify_doc():
    return {
        "kind": "verify",
        "module": "testmod",
        "pythonVersion": "3.12.0",
        "summary": {"total": 5, "passed": 4, "failed": 1, "errored": 0, "skipped": 0},
        "results": [
            {"name": "tests/test_a.py::test_ok", "status": "pass"},
            {"name": "tests/test_b.py::test_fail", "status": "fail"},
        ],
        "exitCode": 1,
    }


def test_verify_render_text():
    import pyfusa.verify as verify

    doc = _make_verify_doc()
    text = verify.render_text(doc)
    assert "testmod" in text
    assert "total=5" in text
    assert "failed=1" in text
    assert "✓" in text or "✗" in text


def test_verify_save_and_load():
    import pyfusa.verify as verify

    with tempfile.TemporaryDirectory() as tmpdir:
        doc = _make_verify_doc()
        path = verify.save(doc, tmpdir)
        assert os.path.exists(path)
        loaded = verify.load(tmpdir)
        assert loaded["kind"] == "verify"
        assert loaded["module"] == "testmod"


def test_verify_load_missing_returns_none():
    import pyfusa.verify as verify

    with tempfile.TemporaryDirectory() as tmpdir:
        result = verify.load(tmpdir)
        assert result is None


def test_verify_parse_pytest_output_passed():
    from pyfusa.verify import _parse_pytest_output

    output = "PASSED tests/test_foo.py::test_bar\n1 passed in 0.1s"
    result = _parse_pytest_output(output, 0)
    assert result["summary"]["passed"] >= 1


def test_verify_parse_pytest_output_failed():
    from pyfusa.verify import _parse_pytest_output

    output = "FAILED tests/test_foo.py::test_bad\n1 failed in 0.1s"
    result = _parse_pytest_output(output, 1)
    assert result["summary"]["failed"] >= 1


def test_verify_parse_pytest_output_summary_only():
    from pyfusa.verify import _parse_pytest_output

    output = "3 passed, 2 failed in 0.5s"
    result = _parse_pytest_output(output, 1)
    assert result["summary"]["passed"] == 3
    assert result["summary"]["failed"] == 2


def test_verify_parse_pytest_output_errors():
    from pyfusa.verify import _parse_pytest_output

    output = "ERROR tests/test_foo.py::test_bad\n"
    result = _parse_pytest_output(output, 2)
    assert result["summary"]["errored"] >= 1


def test_verify_run_no_tests():
    import pyfusa.verify as verify

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="testproj")
        doc = verify.run(tmpdir, cfg, timeout=10)
        assert doc["kind"] == "verify"
        assert "summary" in doc
        assert "pythonVersion" in doc


def test_verify_cli_text():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["verify", "--dir", tmpdir, "--timeout", "5"], stdout=out)
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)
        assert "verify" in out.getvalue() or "total=" in out.getvalue()


def test_verify_cli_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "verify.json")
        run(
            [
                "verify",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--output",
                out_path,
                "--timeout",
                "5",
            ],
            stdout=io.StringIO(),
        )
        with open(out_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "verify"


def test_verify_render_text_many_results():
    import pyfusa.verify as verify

    doc = {
        "module": "big",
        "pythonVersion": "3.12",
        "summary": {"total": 25, "passed": 25, "failed": 0, "errored": 0, "skipped": 0},
        "results": [{"name": f"test_{i}", "status": "pass"} for i in range(25)],
    }
    text = verify.render_text(doc)
    assert "more" in text


# ---------------------------------------------------------------------------
# impact.py
# ---------------------------------------------------------------------------


def test_impact_run_no_git():
    import pyfusa.impact as impact

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = impact.run(tmpdir, cfg)
        assert doc["kind"] == "impact-report"
        assert doc["changedFiles"] == []


def test_impact_load_reqs_missing():
    from pyfusa.impact import _load_reqs

    with tempfile.TemporaryDirectory() as tmpdir:
        assert _load_reqs(tmpdir) == []


def test_impact_load_reqs_present():
    from pyfusa.impact import _load_reqs

    with tempfile.TemporaryDirectory() as tmpdir:
        data = {"requirements": [{"id": "REQ-001", "title": "test"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(data, f)
        reqs = _load_reqs(tmpdir)
        assert len(reqs) == 1


def test_impact_load_trace_matrix_missing():
    from pyfusa.impact import _load_trace_matrix

    with tempfile.TemporaryDirectory() as tmpdir:
        assert _load_trace_matrix(tmpdir) == {}


def test_impact_load_trace_matrix_present():
    from pyfusa.impact import _load_trace_matrix

    with tempfile.TemporaryDirectory() as tmpdir:
        data = {"requirements": [{"id": "REQ-001", "tags": [{"file": "src/a.py"}]}]}
        with open(os.path.join(tmpdir, "trace-matrix.json"), "w") as f:
            json.dump(data, f)
        matrix = _load_trace_matrix(tmpdir)
        assert "REQ-001" in matrix


def test_impact_check_stale_no_artifacts():
    from pyfusa.impact import _check_stale

    with tempfile.TemporaryDirectory() as tmpdir:
        stale = _check_stale(tmpdir, [{"path": "src/x.py"}])
        assert stale == []


def test_impact_cli():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["impact", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# vuln.py
# ---------------------------------------------------------------------------


def test_vuln_installed_packages():
    from pyfusa.vuln import _installed_packages

    pkgs = _installed_packages()
    assert isinstance(pkgs, list)
    # pytest must be installed
    names = [p["name"] for p in pkgs]
    assert any("pytest" in n.lower() for n in names)


def test_vuln_query_osv_empty():
    from pyfusa.vuln import _query_osv

    result = _query_osv([], timeout=5)
    assert result == []


def test_vuln_scan_returns_report():
    import pyfusa.vuln as vuln

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        doc = vuln.scan(tmpdir, cfg, timeout=1)
        assert doc["kind"] == "vuln-report"
        assert "scanned" in doc
        assert "findings" in doc


def test_vuln_cli():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["vuln", "--dir", tmpdir], stdout=out)
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)


# ---------------------------------------------------------------------------
# safetycase.py
# ---------------------------------------------------------------------------


def test_safetycase_assemble_empty():
    import pyfusa.safetycase as sc

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = sc.assemble(tmpdir, cfg)
        assert doc["kind"] == "safety-case"
        assert len(doc["evidence"]) > 0
        assert all(e["status"] == "absent" for e in doc["evidence"])


def test_safetycase_assemble_with_files():
    import pyfusa.safetycase as sc

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create some evidence files
        with open(os.path.join(tmpdir, "check-report.json"), "w") as f:
            json.dump(
                {
                    "kind": "check-report",
                    "summary": {"errors": 0, "warnings": 2},
                    "findings": [],
                },
                f,
            )
        with open(os.path.join(tmpdir, "qualify-report.json"), "w") as f:
            json.dump({"kind": "qualify", "total": 5, "passed": 5, "failed": 0}, f)
        with open(os.path.join(tmpdir, "sbom.json"), "w") as f:
            json.dump({"kind": "sbom", "components": [{"name": "pytest"}]}, f)
        cfg = default(project_name="proj")
        doc = sc.assemble(tmpdir, cfg)
        present = [e for e in doc["evidence"] if e["status"] == "present"]
        assert len(present) >= 3


def test_safetycase_to_markdown():
    import pyfusa.safetycase as sc

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = sc.assemble(tmpdir, cfg)
        md = sc.to_markdown(doc)
        assert "# Safety Case" in md
        assert "Evidence" in md
        assert "Gaps" in md


def test_safetycase_to_mermaid():
    import pyfusa.safetycase as sc

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = sc.assemble(tmpdir, cfg)
        mm = sc.to_mermaid(doc)
        assert "graph LR" in mm
        assert "safety_case" in mm


def test_safetycase_cli_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["safety-case", "--dir", tmpdir, "--format", "md", "--output", ""],
            stdout=out,
        )
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)
        assert "Safety Case" in out.getvalue()


# ---------------------------------------------------------------------------
# badge.py
# ---------------------------------------------------------------------------


def test_badge_status_errors():
    from pyfusa.badge import _status

    label, msg, color = _status(3, 0)
    assert label == "fail"
    assert "error" in msg
    assert color == "#e05d44"


def test_badge_status_warnings():
    from pyfusa.badge import _status

    label, msg, color = _status(0, 5)
    assert label == "warn"
    assert color == "#dfb317"


def test_badge_generate_with_errors():
    from pyfusa.badge import generate

    svg = generate(errors=2, warnings=0)
    assert "<svg" in svg
    assert "#e05d44" in svg


def test_badge_generate_custom_label():
    from pyfusa.badge import generate

    svg = generate(errors=0, warnings=1, label="myproject")
    assert "myproject" in svg
    assert "#dfb317" in svg


def test_badge_from_report():
    from pyfusa.badge import from_report

    with tempfile.TemporaryDirectory() as tmpdir:
        rpt = os.path.join(tmpdir, "check-report.json")
        with open(rpt, "w") as f:
            json.dump({"summary": {"errors": 1, "warnings": 0}}, f)
        svg = from_report(rpt)
        assert "<svg" in svg
        assert "#e05d44" in svg


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------


def test_config_load_full():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = {
            "configVersion": "1.0",
            "project": {"name": "myproj", "version": "1.2.3"},
            "standard": "iec61508",
            "asil": "ASIL-C",
            "sil": "SIL-2",
            "dal": "DAL-C",
            "sourceDirs": ["src", "lib"],
            "excludePatterns": ["tests/*"],
            "strict": True,
            "report": {"format": "html", "output": "report.html"},
        }
        cfg_path = os.path.join(tmpdir, ".fusa.json")
        with open(cfg_path, "w") as f:
            json.dump(data, f)
        cfg = load(cfg_path)
        assert cfg.project.name == "myproj"
        assert cfg.project.version == "1.2.3"
        assert cfg.standard == "iec61508"
        assert cfg.asil == "ASIL-C"
        assert cfg.sil == "SIL-2"
        assert cfg.dal == "DAL-C"
        assert cfg.source_dirs == ["src", "lib"]
        assert cfg.exclude_patterns == ["tests/*"]
        assert cfg.strict is True
        assert cfg.report_format == "html"
        assert cfg.report_output == "report.html"


def test_config_load_legacy_project_string():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = {"project": "myprojname"}
        cfg_path = os.path.join(tmpdir, ".fusa.json")
        with open(cfg_path, "w") as f:
            json.dump(data, f)
        cfg = load(cfg_path)
        assert cfg.project.name == "myprojname"


def test_config_load_missing_raises():
    with pytest.raises(FileNotFoundError):
        load("/nonexistent/.fusa.json")


def test_config_load_invalid_json_raises():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, ".fusa.json")
        with open(cfg_path, "w") as f:
            f.write("NOT JSON {{{")
        with pytest.raises(ValueError):
            load(cfg_path)


def test_config_integrity_label_asil():
    cfg = default()
    cfg.asil = "ASIL-B"
    assert cfg.integrity_label() == "ASIL-B"


def test_config_integrity_label_sil():
    cfg = default()
    cfg.sil = "SIL-2"
    assert cfg.integrity_label() == "SIL-2"


def test_config_integrity_label_dal():
    cfg = default()
    cfg.dal = "DAL-B"
    assert cfg.integrity_label() == "DAL-B"


def test_config_integrity_label_empty():
    cfg = default()
    assert cfg.integrity_label() == ""


def test_load_dispositions_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = load_dispositions(os.path.join(tmpdir, ".fusa-dispositions.json"))
        assert result == []


def test_load_dispositions_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = {"dispositions": [{"ruleId": "LINT001", "rationale": "ok"}]}
        path = os.path.join(tmpdir, ".fusa-dispositions.json")
        with open(path, "w") as f:
            json.dump(data, f)
        result = load_dispositions(path)
        assert len(result) == 1


def test_load_dispositions_invalid_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, ".fusa-dispositions.json")
        with open(path, "w") as f:
            f.write("INVALID")
        result = load_dispositions(path)
        assert result == []


def test_load_requirements_missing():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs, errors = load_requirements(os.path.join(tmpdir, ".fusa-reqs.json"))
        assert reqs == []
        assert errors == []


def test_load_requirements_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = {
            "requirements": [
                {"id": "REQ-001", "title": "first"},
                {"id": "REQ-002", "title": "second"},
            ]
        }
        path = os.path.join(tmpdir, ".fusa-reqs.json")
        with open(path, "w") as f:
            json.dump(data, f)
        reqs, errors = load_requirements(path)
        assert len(reqs) == 2
        assert errors == []


def test_load_requirements_duplicate_id():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = {
            "requirements": [
                {"id": "REQ-001", "title": "first"},
                {"id": "REQ-001", "title": "duplicate"},
            ]
        }
        path = os.path.join(tmpdir, ".fusa-reqs.json")
        with open(path, "w") as f:
            json.dump(data, f)
        reqs, errors = load_requirements(path)
        assert len(errors) == 1
        assert errors[0].rule_id == "REQ001"


def test_load_requirements_invalid_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, ".fusa-reqs.json")
        with open(path, "w") as f:
            f.write("NOT JSON")
        reqs, errors = load_requirements(path)
        assert reqs == []
        assert errors == []


# ---------------------------------------------------------------------------
# rules/comp.py
# ---------------------------------------------------------------------------


def test_comp001_high_complexity():
    from pyfusa.rules.comp import COMP001

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a function with many decision points (complexity > 10)
        code = (
            "def complex_func(a, b, c, d, e, f):\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d:\n"
            "                    if e:\n"
            "                        if f:\n"
            "                            return 1\n"
            "                        elif not f:\n"
            "                            return 2\n"
            "                    elif not e:\n"
            "                        return 3\n"
            "                elif not d:\n"
            "                    return 4\n"
            "    elif not a:\n"
            "        return 5\n"
            "    return 0\n"
        )
        with open(os.path.join(tmpdir, "complex.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        rule = COMP001()
        findings = rule.run(tmpdir, cfg)
        assert any(f.rule_id == "COMP001" for f in findings)


def test_comp001_low_complexity_no_findings():
    from pyfusa.rules.comp import COMP001

    with tempfile.TemporaryDirectory() as tmpdir:
        code = "def simple(x):\n    return x + 1\n"
        with open(os.path.join(tmpdir, "simple.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        rule = COMP001()
        findings = rule.run(tmpdir, cfg)
        assert findings == []


def test_comp001_skips_private():
    from pyfusa.rules.comp import COMP001

    with tempfile.TemporaryDirectory() as tmpdir:
        code = (
            "def _private_complex(a, b, c, d, e, f, g, h, i, j):\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d:\n"
            "                    if e: return 1\n"
            "                    elif not e: return 2\n"
            "    elif b:\n"
            "        if c: return 3\n"
            "        elif not c: return 4\n"
            "    return 0\n"
        )
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        rule = COMP001()
        findings = rule.run(tmpdir, cfg)
        assert findings == []  # private functions are skipped


def test_comp001_dal_threshold():
    from pyfusa.rules.comp import COMP001

    with tempfile.TemporaryDirectory() as tmpdir:
        # complexity=5, DAL-A threshold=4 → should flag
        code = (
            "def func(a, b, c, d):\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d: return 1\n"
            "    return 0\n"
        )
        with open(os.path.join(tmpdir, "m.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        cfg.dal = "DAL-A"
        rule = COMP001()
        findings = rule.run(tmpdir, cfg)
        assert any(f.rule_id == "COMP001" for f in findings)


# ---------------------------------------------------------------------------
# rules/evidence.py
# ---------------------------------------------------------------------------


def test_verify001_missing_bundle():
    from pyfusa.rules.evidence import VERIFY001

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        findings = VERIFY001().run(tmpdir, cfg)
        assert any(f.rule_id == "VERIFY001" for f in findings)


def test_verify001_bundle_present():
    from pyfusa.rules.evidence import VERIFY001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-evidence.json"), "w") as f:
            json.dump({"kind": "verify"}, f)
        cfg = default()
        assert VERIFY001().run(tmpdir, cfg) == []


def test_verify002_failed_tests():
    from pyfusa.rules.evidence import VERIFY002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-evidence.json"), "w") as f:
            json.dump(
                {"summary": {"total": 5, "passed": 3, "failed": 2, "errored": 0}}, f
            )
        cfg = default()
        findings = VERIFY002().run(tmpdir, cfg)
        assert any(f.rule_id == "VERIFY002" for f in findings)


def test_verify002_all_pass():
    from pyfusa.rules.evidence import VERIFY002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-evidence.json"), "w") as f:
            json.dump(
                {"summary": {"total": 5, "passed": 5, "failed": 0, "errored": 0}}, f
            )
        cfg = default()
        assert VERIFY002().run(tmpdir, cfg) == []


def test_hara001_missing():
    from pyfusa.rules.evidence import HARA001

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        cfg.standard = "iso26262"
        findings = HARA001().run(tmpdir, cfg)
        assert any(f.rule_id == "HARA001" for f in findings)
        assert findings[0].severity == pyfusa.SEVERITY_WARNING


def test_hara001_present():
    from pyfusa.rules.evidence import HARA001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump({}, f)
        cfg = default()
        assert HARA001().run(tmpdir, cfg) == []


def test_hara002_incomplete_risk():
    from pyfusa.rules.evidence import HARA002

    with tempfile.TemporaryDirectory() as tmpdir:
        hara = {"hazards": [{"id": "HZ-001", "risk": {"severity": "S2"}}]}
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump(hara, f)
        cfg = default()
        findings = HARA002().run(tmpdir, cfg)
        assert any(f.rule_id == "HARA002" for f in findings)


def test_hara002_complete_risk():
    from pyfusa.rules.evidence import HARA002

    with tempfile.TemporaryDirectory() as tmpdir:
        hara = {
            "hazards": [
                {
                    "id": "HZ-001",
                    "risk": {
                        "severity": "S2",
                        "exposure": "E3",
                        "controllability": "C2",
                    },
                }
            ]
        }
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump(hara, f)
        cfg = default()
        assert HARA002().run(tmpdir, cfg) == []


def test_hara003_no_safety_goal():
    from pyfusa.rules.evidence import HARA003

    with tempfile.TemporaryDirectory() as tmpdir:
        hara = {"hazards": [{"id": "HZ-001", "safetyGoals": []}], "safetyGoals": []}
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump(hara, f)
        cfg = default()
        findings = HARA003().run(tmpdir, cfg)
        assert any(f.rule_id == "HARA003" for f in findings)


def test_hara004_no_asil():
    from pyfusa.rules.evidence import HARA004

    with tempfile.TemporaryDirectory() as tmpdir:
        hara = {"safetyGoals": [{"id": "SG-001"}]}
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump(hara, f)
        cfg = default()
        findings = HARA004().run(tmpdir, cfg)
        assert any(f.rule_id == "HARA004" for f in findings)


def test_hara005_asil_exceeds_project():
    from pyfusa.rules.evidence import HARA005

    with tempfile.TemporaryDirectory() as tmpdir:
        hara = {"safetyGoals": [{"id": "SG-001", "asil": "ASIL-D"}]}
        with open(os.path.join(tmpdir, ".fusa-hara.json"), "w") as f:
            json.dump(hara, f)
        cfg = default()
        cfg.asil = "ASIL-B"
        findings = HARA005().run(tmpdir, cfg)
        assert any(f.rule_id == "HARA005" for f in findings)


def test_release001_missing():
    from pyfusa.rules.evidence import RELEASE001

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = RELEASE001().run(tmpdir, default())
        assert any(f.rule_id == "RELEASE001" for f in findings)


def test_release001_present():
    from pyfusa.rules.evidence import RELEASE001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "sbom.json"), "w") as f:
            json.dump({}, f)
        assert RELEASE001().run(tmpdir, default()) == []


def test_disp001_no_check_report():
    from pyfusa.rules.evidence import DISP001

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = DISP001().run(tmpdir, default())
        assert any(f.rule_id == "DISP001" for f in findings)


def test_disp001_no_unresolved():
    from pyfusa.rules.evidence import DISP001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "check-report.json"), "w") as f:
            json.dump({"findings": [{"severity": "WARNING", "ruleId": "LINT001"}]}, f)
        assert DISP001().run(tmpdir, default()) == []


# ---------------------------------------------------------------------------
# rules/slsa.py  and  rules/iec62443.py
# ---------------------------------------------------------------------------


def test_slsa001_no_provenance():
    from pyfusa.rules.slsa import SLSA001

    with tempfile.TemporaryDirectory() as tmpdir:
        assert SLSA001().run(tmpdir, default()) == []  # no file → no finding


def test_slsa001_missing_vcs_revision():
    from pyfusa.rules.slsa import SLSA001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "provenance.json"), "w") as f:
            json.dump({"builder": "github-actions"}, f)
        findings = SLSA001().run(tmpdir, default())
        assert any(f.rule_id == "SLSA001" for f in findings)


def test_slsa002_missing_builder():
    from pyfusa.rules.slsa import SLSA002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "provenance.json"), "w") as f:
            json.dump({"vcsRevision": "abc123"}, f)
        findings = SLSA002().run(tmpdir, default())
        assert any(f.rule_id == "SLSA002" for f in findings)


def test_slsa003_no_codeowners():
    from pyfusa.rules.slsa import SLSA003

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = SLSA003().run(tmpdir, default())
        assert any(f.rule_id == "SLSA003" for f in findings)


def test_iec62443_001_no_config():
    from pyfusa.rules.iec62443 import IEC62443_001

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = IEC62443_001().run(tmpdir, default())
        assert any(f.rule_id == "IEC62443-001" for f in findings)


def test_iec62443_002_invalid_sl():
    from pyfusa.rules.iec62443 import IEC62443_002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-iec62443.json"), "w") as f:
            json.dump({"target_sl": 5}, f)
        findings = IEC62443_002().run(tmpdir, default())
        assert any(f.rule_id == "IEC62443-002" for f in findings)


def test_iec62443_002_valid_sl():
    from pyfusa.rules.iec62443 import IEC62443_002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-iec62443.json"), "w") as f:
            json.dump({"target_sl": 2}, f)
        assert IEC62443_002().run(tmpdir, default()) == []


def test_iec62443_003_no_security_md():
    from pyfusa.rules.iec62443 import IEC62443_003

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = IEC62443_003().run(tmpdir, default())
        assert any(f.rule_id == "IEC62443-003" for f in findings)


def test_iec62443_004_no_incident_response():
    from pyfusa.rules.iec62443 import IEC62443_004

    with tempfile.TemporaryDirectory() as tmpdir:
        findings = IEC62443_004().run(tmpdir, default())
        assert any(f.rule_id == "IEC62443-004" for f in findings)


# ---------------------------------------------------------------------------
# gap report render_text functions
# ---------------------------------------------------------------------------


def test_iso26262_render_text():
    from pyfusa.compliance.iso26262 import run, render_text

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = run(tmpdir, cfg)
        text = render_text(doc)
        assert "ISO 26262" in text


def test_iec61508_render_text():
    from pyfusa.compliance.iec61508 import run, render_text

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = run(tmpdir, cfg)
        text = render_text(doc)
        assert "IEC 61508" in text


def test_do178_render_text():
    from pyfusa.compliance.do178 import run, render_text

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = run(tmpdir, cfg)
        text = render_text(doc)
        assert "DO-178C" in text


def test_iso21434_render_text():
    from pyfusa.compliance.iso21434 import run, render_text

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = run(tmpdir, cfg)
        text = render_text(doc)
        assert "ISO 21434" in text


def test_unece_render_text():
    from pyfusa.compliance.unece import run, render_text

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = run(tmpdir, cfg)
        text = render_text(doc)
        assert "R.155" in text or "unece" in text.lower()


# ---------------------------------------------------------------------------
# boundary render_text
# ---------------------------------------------------------------------------


def test_boundary_render_mermaid():
    import pyfusa.boundary as boundary

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        graph = boundary.scan(tmpdir, cfg)
        doc = boundary.to_dict(graph, tmpdir, cfg)
        mm = boundary.to_mermaid(graph, cfg.project.name or "proj")
        assert isinstance(mm, str)


def test_boundary_render_dot():
    import pyfusa.boundary as boundary

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        graph = boundary.scan(tmpdir, cfg)
        dot = boundary.to_dot(graph, cfg.project.name or "proj")
        assert isinstance(dot, str)


def test_boundary_cli_mermaid():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["boundary", "--dir", tmpdir, "--format", "mermaid", "--output", ""],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK


def test_boundary_cli_dot():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["boundary", "--dir", tmpdir, "--format", "dot", "--output", ""], stdout=out
        )
        assert code == pyfusa.EXIT_OK
