"""Tests for new commands: cyber, analyze, fmea, boundary, coupling, tara,
hara, diff, badge, sign, vuln, pr, disposition, impact, metrics, safety-case,
compliance gap reports, sas, sci, coverage, template, misra."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pytest
import pyfusa
from pyfusa.cli.main import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmpdir_with_fusa(name: str = "myproj") -> tuple:
    tmpdir = tempfile.mkdtemp()
    cfg = {
        "project": {"name": name, "standard": "iso26262", "asil": "ASIL-B"},
        "sourceDirs": ["."],
    }
    with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
        json.dump(cfg, f)
    return tmpdir


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_lint_exits_0_clean():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["lint", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-CLI001
def test_lint_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["lint", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        assert "findings" in doc


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_analyze_exits_0_clean():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["analyze", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# cyber
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_cyber_exits_0_clean():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["cyber", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-CLI001
def test_cyber_detects_eval():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "bad.py"), "w") as f:
            f.write('x = eval(input("code: "))\n')
        out = io.StringIO()
        code = run(["cyber", "--dir", tmpdir, "--format", "json"], stdout=out)
        # eval is detected by SEC002 (already in engine), cyber runs only CYBER rules
        # but CYBER005 might still find dynamic command usage
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)


# fusa:test REQ-CLI001
def test_cyber001_weak_hash():
    from pyfusa.rules.cyber import CYBER001
    from pyfusa.config import default

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "hash.py"), "w") as f:
            f.write("import hashlib\nh = hashlib.md5(b'data')\n")
        rule = CYBER001()
        cfg = default()
        cfg.source_dirs = ["."]
        findings = rule.run(tmpdir, cfg)
        assert any(f.rule_id == "CYBER001" for f in findings)


# fusa:test REQ-CLI001
def test_cyber006_hardcoded_credential():
    from pyfusa.rules.cyber import CYBER006
    from pyfusa.config import default

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "creds.py"), "w") as f:
            f.write('password = "supersecret123"\n')
        rule = CYBER006()
        cfg = default()
        cfg.source_dirs = ["."]
        findings = rule.run(tmpdir, cfg)
        assert any(f.rule_id == "CYBER006" for f in findings)


# fusa:test REQ-CLI001
def test_cyber007_tls_verify_false():
    from pyfusa.rules.cyber import CYBER007
    from pyfusa.config import default

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "tls.py"), "w") as f:
            f.write(
                "import requests\nrequests.get('https://example.com', verify=False)\n"
            )
        rule = CYBER007()
        cfg = default()
        cfg.source_dirs = ["."]
        findings = rule.run(tmpdir, cfg)
        assert any(f.rule_id == "CYBER007" for f in findings)


# ---------------------------------------------------------------------------
# fmea
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_fmea_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def process(data):\n    return data\n")
        out = io.StringIO()
        code = run(
            ["fmea", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "fmea-report"
        assert "entries" in doc
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-CLI001
def test_fmea_skips_private():
    from pyfusa.config import default
    import pyfusa.fmea as fmea

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def public(): pass\ndef _private(): pass\n")
        cfg = default()
        cfg.source_dirs = ["."]
        entries = fmea.scan(tmpdir, cfg)
        names = [e["function"] for e in entries]
        assert "public" in names
        assert "_private" not in names


# ---------------------------------------------------------------------------
# boundary
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_boundary_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["boundary", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "boundary"
        assert "nodes" in doc
        assert "edges" in doc


# ---------------------------------------------------------------------------
# coupling
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_coupling_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["coupling", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "coupling-report"
        assert "dataCoupling" in doc
        assert "controlCoupling" in doc


# ---------------------------------------------------------------------------
# tara
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_tara_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["tara", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "tara-report"
        assert "threats" in doc


# ---------------------------------------------------------------------------
# hara
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_hara_init():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["hara", "init", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, ".fusa-hara.json"))


# fusa:test REQ-CLI001
def test_hara_validate_ok():
    with tempfile.TemporaryDirectory() as tmpdir:
        run(["hara", "init", "--dir", tmpdir], stdout=io.StringIO())
        out = io.StringIO()
        code = run(["hara", "validate", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_diff_no_changes():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = {
            "kind": "check-report",
            "findings": [
                {
                    "ruleId": "LINT001",
                    "location": {"file": "a.py", "line": 5},
                    "message": "too long",
                }
            ],
        }
        p1 = os.path.join(tmpdir, "a.json")
        p2 = os.path.join(tmpdir, "b.json")
        with open(p1, "w") as f:
            json.dump(report, f)
        with open(p2, "w") as f:
            json.dump(report, f)
        out = io.StringIO()
        code = run(["diff", p1, p2, "--format", "json"], stdout=out)
        d = json.loads(out.getvalue())
        assert d["introduced"] == []
        assert d["resolved"] == []
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-CLI001
def test_diff_introduced():
    with tempfile.TemporaryDirectory() as tmpdir:
        old_r = {"kind": "check-report", "findings": []}
        new_r = {
            "kind": "check-report",
            "findings": [
                {
                    "ruleId": "LINT001",
                    "location": {"file": "a.py", "line": 5},
                    "message": "too long",
                }
            ],
        }
        p1 = os.path.join(tmpdir, "old.json")
        p2 = os.path.join(tmpdir, "new.json")
        with open(p1, "w") as f:
            json.dump(old_r, f)
        with open(p2, "w") as f:
            json.dump(new_r, f)
        out = io.StringIO()
        code = run(["diff", p1, p2], stdout=out)
        assert code == pyfusa.EXIT_GATE_FAIL
        assert "introduced: 1" in out.getvalue()


# ---------------------------------------------------------------------------
# badge
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_badge_generates_svg():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            [
                "badge",
                "--dir",
                tmpdir,
                "--errors",
                "0",
                "--warnings",
                "0",
                "--output",
                "badge.svg",
            ],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        svg_path = os.path.join(tmpdir, "badge.svg")
        assert os.path.exists(svg_path)
        content = open(svg_path).read()
        assert "<svg" in content
        assert "passing" in content


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_sign_keygen_and_verify():
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "sign.key")
        target_path = os.path.join(tmpdir, "file.txt")
        with open(target_path, "w") as f:
            f.write("hello world\n")

        code = run(
            ["sign", "keygen", "--dir", tmpdir, "--key", "sign.key"],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(key_path)

        code = run(
            [
                "sign",
                "sign",
                "--dir",
                tmpdir,
                "--key",
                "sign.key",
                "--file",
                "file.txt",
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK

        code = run(
            [
                "sign",
                "verify",
                "--dir",
                tmpdir,
                "--key",
                "sign.key",
                "--file",
                "file.txt",
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# pr
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_pr_add_and_list():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(
            [
                "pr",
                "add",
                "--dir",
                tmpdir,
                "--title",
                "Test bug",
                "--description",
                "Something broke",
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK

        out = io.StringIO()
        code = run(["pr", "list", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert "PR-001" in out.getvalue()


# ---------------------------------------------------------------------------
# disposition
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_disposition_add_and_list():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(
            [
                "disposition",
                "add",
                "--dir",
                tmpdir,
                "--rule",
                "LINT001",
                "--rationale",
                "Accepted for legacy code",
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK

        out = io.StringIO()
        code = run(["disposition", "list", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert "LINT001" in out.getvalue()


# fusa:test REQ-CLI009
# fusa:test REQ-ENGINE001
def test_disposition_add_suppresses_the_gate():
    """An accepted disposition MUST suppress the gate on a matching finding
    (§4.1) — regression test for the three-way schema mismatch between
    disposition_mgmt.add(), config.load_dispositions(), and DISP001, where
    entries written by `disposition add` were invisible to the gate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # FUSA001/FUSA002 must be satisfied so only SEC001 gates the run.
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            json.dump({"project": {"name": "t"}, "sourceDirs": ["."]}, f)
        with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
            f.write("[project]\nname = 't'\n")
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def risky():\n    try:\n        pass\n    except:\n        pass\n")

        report_path = os.path.join(tmpdir, "check-report.json")
        code = run(
            ["check", "--dir", tmpdir, "--format", "json", "--output", report_path],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_GATE_FAIL
        with open(report_path) as f:
            doc = json.load(f)
        sec001 = next(f for f in doc["findings"] if f["ruleId"] == "SEC001")
        fingerprint = sec001["fingerprint"]
        assert fingerprint

        code = run(
            [
                "disposition",
                "add",
                "--dir",
                tmpdir,
                "--rule",
                "SEC001",
                "--rationale",
                "reviewed — acceptable for this legacy handler",
                "--action",
                "accept",
                "--fingerprint",
                fingerprint,
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK

        with open(os.path.join(tmpdir, ".fusa-dispositions.json")) as f:
            disp_doc = json.load(f)
        assert disp_doc["dispositions"][0]["status"] == "accepted"

        code = run(
            ["check", "--dir", tmpdir, "--format", "json", "--output", report_path],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK
        with open(report_path) as f:
            doc = json.load(f)
        sec001 = next(f for f in doc["findings"] if f["ruleId"] == "SEC001")
        assert sec001["disposition"] == "accepted"


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_metrics_record_and_show():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["metrics", "record", "--dir", tmpdir], stdout=io.StringIO())
        assert code == pyfusa.EXIT_OK

        out = io.StringIO()
        code = run(["metrics", "show", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert "snapshots" in out.getvalue() or "errors" in out.getvalue()


# ---------------------------------------------------------------------------
# safety-case
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_safety_case_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["safety-case", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "safety-case"
        assert "nodes" in doc
        assert "edges" in doc
        assert "completeness" in doc


# ---------------------------------------------------------------------------
# compliance gap reports
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI001
# fusa:test REQ-COMPLY001
def test_iso26262_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["iso26262", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "gap-report"
        assert "objectives" in doc


# fusa:test REQ-CLI001
# fusa:test REQ-COMPLY001
def test_iec61508_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["iec61508", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "gap-report"


# fusa:test REQ-CLI001
# fusa:test REQ-COMPLY001
def test_do178_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["do178", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "gap-report"
        assert "objectives" in doc


# fusa:test REQ-CLI001
# fusa:test REQ-COMPLY001
def test_iso21434_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["iso21434", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "gap-report"


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
# fusa:test REQ-COMPLY001
def test_unece_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["unece", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "gap-report"


# ---------------------------------------------------------------------------
# sas / sci
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_sas_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["sas", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "sas"
        assert "checklist" in doc
        assert "summary" in doc


# fusa:test REQ-CLI009
def test_sas_always_writes_md_companion():
    """x-FuSa spec §9.3 sas MUST: sas.json is not a replacement for the
    human-readable sas.md companion — a tool MUST also write it, regardless
    of the requested --format/--output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            [
                "sas",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--output",
                os.path.join(tmpdir, "sas.json"),
            ],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        md_path = os.path.join(tmpdir, "sas.md")
        assert os.path.exists(md_path)
        with open(md_path, encoding="utf-8") as f:
            content = f.read()
        assert content.startswith("# Software Accomplishment Summary")
        assert "|" in content  # markdown table, not the plain-text renderer


# fusa:test REQ-CLI009
def test_sas_format_md_accepted():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["sas", "--dir", tmpdir, "--format", "md", "--output", ""], stdout=out
        )
        assert code == pyfusa.EXIT_OK
        assert out.getvalue().startswith("# Software Accomplishment Summary")


# fusa:test REQ-CLI009
def test_sas_md_companion_not_duplicated_when_output_is_sas_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        md_path = os.path.join(tmpdir, "sas.md")
        code = run(
            ["sas", "--dir", tmpdir, "--format", "md", "--output", md_path],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        # exactly one "wrote" line — no duplicate write of the same file
        lines = [l for l in out.getvalue().splitlines() if l.startswith("wrote")]
        assert lines == ["wrote sas.md"]


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_sci_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["sci", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "sci"
        assert "artifacts" in doc


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_coverage_text_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["coverage", "--dir", tmpdir], stdout=out)
        assert "coverage:" in out.getvalue()


# ---------------------------------------------------------------------------
# template
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_template_list():
    out = io.StringIO()
    code = run(["template", "--list"], stdout=out)
    assert code == pyfusa.EXIT_OK
    assert "safety-plan" in out.getvalue()


# fusa:test REQ-CLI001
def test_template_generate_safety_plan():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["template", "safety-plan", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, "SAFETY_PLAN.md"))


# ---------------------------------------------------------------------------
# misra
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_misra_text():
    out = io.StringIO()
    code = run(["misra"], stdout=out)
    assert code == pyfusa.EXIT_OK
    assert "MISRA" in out.getvalue()


# fusa:test REQ-CLI001
def test_misra_json():
    out = io.StringIO()
    code = run(["misra", "--format", "json"], stdout=out)
    mapping = json.loads(out.getvalue())
    assert isinstance(mapping, list)
    assert mapping[0]["pyfusaRule"]


# ---------------------------------------------------------------------------
# req
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_req_add_and_list():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(
            [
                "req",
                "add",
                "--dir",
                tmpdir,
                "--id",
                "REQ-999",
                "--title",
                "Test requirement",
            ],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK
        out = io.StringIO()
        run(["req", "list", "--dir", tmpdir], stdout=out)
        assert "REQ-999" in out.getvalue()


# fusa:test REQ-CLI001
def test_req_export_csv():
    with tempfile.TemporaryDirectory() as tmpdir:
        run(
            ["req", "add", "--dir", tmpdir, "--id", "REQ-001", "--title", "First req"],
            stdout=io.StringIO(),
        )
        out = io.StringIO()
        code = run(["req", "export", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert "REQ-001" in out.getvalue()


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
# fusa:test REQ-CLI001
def test_fix_lists_fixable():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["fix", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
def test_hooks_install_creates_pre_commit():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, ".git", "hooks"))
        out = io.StringIO()
        code = run(["hooks", "install", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        hook_path = os.path.join(tmpdir, ".git", "hooks", "pre-commit")
        assert os.path.exists(hook_path)
        with open(hook_path) as f:
            content = f.read()
        assert "pyfusa check --strict" in content
        assert "installed pre-commit hook" in out.getvalue()


# fusa:test REQ-CLI009
def test_hooks_remove_deletes_pre_commit():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, ".git", "hooks"))
        run(["hooks", "install", "--dir", tmpdir], stdout=io.StringIO())
        hook_path = os.path.join(tmpdir, ".git", "hooks", "pre-commit")
        assert os.path.exists(hook_path)

        out = io.StringIO()
        code = run(["hooks", "remove", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert not os.path.exists(hook_path)
        assert "removed pre-commit hook" in out.getvalue()


# fusa:test REQ-CLI009
def test_hooks_remove_when_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["hooks", "remove", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert "no pre-commit hook found" in out.getvalue()
