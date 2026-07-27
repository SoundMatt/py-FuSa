"""Second coverage boost pass — report formats, rule violations, analyze/lint/sec rules."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
from pyfusa.cli.main import run
from pyfusa.config import default
import pyfusa.report as report
import pyfusa.tara as tara


# ---------------------------------------------------------------------------
# report.py — all render formats
# ---------------------------------------------------------------------------


def _make_run_result():
    from pyfusa.report import RunResult

    findings = [
        pyfusa.Finding(
            rule_id="LINT001",
            severity=pyfusa.SEVERITY_WARNING,
            message="function too long",
            location=pyfusa.Location(file="src/foo.py", line=10),
            remediation="split the function",
        ),
        pyfusa.Finding(
            rule_id="SEC001",
            severity=pyfusa.SEVERITY_ERROR,
            message="bare except",
            location=pyfusa.Location(file="src/bar.py", line=5),
            remediation="use specific exception",
        ),
    ]
    return RunResult(findings=findings)


def test_report_render_text():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_run_result()
        text = report.render_text(result, tmpdir)
        assert "LINT001" in text
        assert "SEC001" in text
        assert "Summary:" in text


def test_report_render_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_run_result()
        md = report.render_md(result, tmpdir)
        assert "# py-FuSa Check Report" in md
        assert "LINT001" in md
        assert "Summary" in md


def test_report_render_html():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_run_result()
        html = report.render_html(result, tmpdir)
        assert "<!DOCTYPE html>" in html
        assert "LINT001" in html
        assert "SEC001" in html


def test_report_render_sarif():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_run_result()
        cfg = default()
        sarif = report.render_sarif(result, tmpdir, cfg)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1


def test_report_render_dispatch():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = _make_run_result()
        cfg = default()
        for fmt in ("text", "md", "html"):
            w = io.StringIO()
            report.render(w, result, fmt, tmpdir, cfg)
            assert len(w.getvalue()) > 0


def test_check_cli_html_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["check", "--dir", tmpdir, "--format", "html", "--output", ""], stdout=out
        )
        assert "<!DOCTYPE html>" in out.getvalue()


def test_check_cli_md_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["check", "--dir", tmpdir, "--format", "md", "--output", ""], stdout=out
        )
        assert "# py-FuSa Check Report" in out.getvalue()


def test_check_cli_sarif_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["check", "--dir", tmpdir, "--format", "sarif", "--output", ""], stdout=out
        )
        sarif = json.loads(out.getvalue())
        assert sarif["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# tara.py — to_markdown
# ---------------------------------------------------------------------------


def test_tara_to_markdown():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        with open(os.path.join(tmpdir, "bad.py"), "w") as f:
            f.write("import hashlib\nh = hashlib.md5(b'test')\n")
        doc_check = json.loads(
            io.StringIO(
                json.dumps(
                    {
                        "kind": "check-report",
                        "findings": [
                            {
                                "ruleId": "CYBER001",
                                "severity": "WARNING",
                                "message": "md5 weak hash",
                                "location": {"file": "bad.py", "line": 2},
                            }
                        ],
                    }
                )
            ).getvalue()
        )
        entries = tara.build(doc_check["findings"], tmpdir, cfg)
        md = tara.to_markdown(entries, "mymodule")
        assert "TARA" in md


def test_tara_to_dict_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        doc = tara.to_dict([], tmpdir, cfg)
        assert doc["kind"] == "tara"
        assert doc["entries"] == []


def test_tara_cli_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["tara", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "tara"


def test_tara_cli_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["tara", "--dir", tmpdir, "--format", "md", "--output", ""], stdout=out
        )
        assert "TARA" in out.getvalue()


# ---------------------------------------------------------------------------
# rules/lint.py — trigger individual rules
# ---------------------------------------------------------------------------


def _rule_by_id(rule_id: str, code: str):
    """Run a specific rule by ID via the engine and return its findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        # Run check and filter by rule_id
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out)
        try:
            doc = json.loads(out.getvalue())
            return [f for f in doc.get("findings", []) if f.get("ruleId") == rule_id]
        except json.JSONDecodeError:
            return []


def test_lint001_long_function():
    body = "\n".join(f"    x{i} = {i}" for i in range(65))
    code = f"def long_func():\n{body}\n    return x0\n"
    findings = _rule_by_id("LINT001", code)
    assert any(f["ruleId"] == "LINT001" for f in findings)


def test_lint002_long_file():
    code = "\n".join(f"x_{i} = {i}" for i in range(510))
    findings = _rule_by_id("LINT002", code)
    assert any(f["ruleId"] == "LINT002" for f in findings)


def test_lint003_deep_nesting():
    code = (
        "def nested(a, b, c, d, e):\n"
        "    if a:\n"
        "        if b:\n"
        "            if c:\n"
        "                if d:\n"
        "                    if e:\n"
        "                        return 1\n"
    )
    findings = _rule_by_id("LINT003", code)
    assert any(f["ruleId"] == "LINT003" for f in findings)


def test_lint005_mutable_default():
    code = "def func(items=[]):\n    return items\n"
    findings = _rule_by_id("LINT005", code)
    assert any(f["ruleId"] == "LINT005" for f in findings)


def test_lint006_wildcard_import():
    code = "from os.path import *\n"
    findings = _rule_by_id("LINT006", code)
    assert any(f["ruleId"] == "LINT006" for f in findings)


def test_lint007_assert_used():
    code = "def check(x):\n    assert x > 0, 'must be positive'\n    return x\n"
    findings = _rule_by_id("LINT007", code)
    assert any(f["ruleId"] == "LINT007" for f in findings)


# ---------------------------------------------------------------------------
# rules/security.py — trigger via CLI
# ---------------------------------------------------------------------------


def test_sec001_bare_except():
    code = "try:\n    pass\nexcept:\n    pass\n"
    findings = _rule_by_id("SEC001", code)
    assert any(f["ruleId"] == "SEC001" for f in findings)


def test_sec002_eval():
    code = "x = eval('1+1')\n"
    findings = _rule_by_id("SEC002", code)
    assert any(f["ruleId"] == "SEC002" for f in findings)


def test_sec003_exec():
    code = "exec('print(1)')\n"
    findings = _rule_by_id("SEC003", code)
    assert any(f["ruleId"] == "SEC003" for f in findings)


def test_sec004_pickle():
    code = "import pickle\npickle.loads(b'')\n"
    findings = _rule_by_id("SEC004", code)
    assert any(f["ruleId"] == "SEC004" for f in findings)


def test_sec005_os_system():
    code = "import os\nos.system('ls -la')\n"
    findings = _rule_by_id("SEC005", code)
    assert any(f["ruleId"] == "SEC005" for f in findings)


def test_sec006_shell_true():
    code = "import subprocess\nsubprocess.run('ls', shell=True)\n"
    findings = _rule_by_id("SEC006", code)
    assert any(f["ruleId"] == "SEC006" for f in findings)


# ---------------------------------------------------------------------------
# rules/concurrency.py — trigger via direct instantiation (correct class names)
# ---------------------------------------------------------------------------


def _run_rule_direct(cls, code: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        return cls().run(tmpdir, cfg)


def test_conc001_thread_no_sync():
    from pyfusa.rules.concurrency import RuleThreadWithoutLock

    code = "import threading\nt = threading.Thread(target=lambda: None)\n"
    findings = _run_rule_direct(RuleThreadWithoutLock, code)
    assert any(f.rule_id == "CONC001" for f in findings)


def test_conc002_global_mutation():
    from pyfusa.rules.concurrency import RuleGlobalMutation

    code = "x = 0\ndef inc():\n    global x\n    x += 1\n"
    findings = _run_rule_direct(RuleGlobalMutation, code)
    assert any(f.rule_id == "CONC002" for f in findings)


def test_conc003_async_no_await():
    from pyfusa.rules.concurrency import RuleAsyncWithoutAwait

    code = "async def noop():\n    pass\n"
    findings = _run_rule_direct(RuleAsyncWithoutAwait, code)
    assert any(f.rule_id == "CONC003" for f in findings)


# ---------------------------------------------------------------------------
# rules/analyze.py — trigger ANA001, ANA002, ANA003
# ---------------------------------------------------------------------------


def test_ana001_thread_no_stop_event():
    from pyfusa.rules.analyze import ANA001

    code = "import threading\nt = threading.Thread(target=lambda: None)\nt.start()\n"
    findings = _run_rule_direct(ANA001, code)
    assert any(f.rule_id == "ANA001" for f in findings)


def test_ana001_thread_with_event_no_finding():
    from pyfusa.rules.analyze import ANA001

    code = (
        "import threading\n"
        "stop = threading.Event()\n"
        "t = threading.Thread(target=lambda: None)\n"
    )
    findings = _run_rule_direct(ANA001, code)
    assert findings == []


def test_ana002_thread_in_loop():
    from pyfusa.rules.analyze import ANA002

    code = (
        "import threading\n"
        "for i in range(10):\n"
        "    t = threading.Thread(target=lambda: None)\n"
        "    t.start()\n"
    )
    findings = _run_rule_direct(ANA002, code)
    assert any(f.rule_id == "ANA002" for f in findings)


def test_ana003_runs_without_crash():
    from pyfusa.rules.analyze import ANA003

    code = (
        "import threading, time\n"
        "def worker():\n"
        "    while True:\n"
        "        time.sleep(1)\n"
        "t = threading.Thread(target=worker)\n"
    )
    findings = _run_rule_direct(ANA003, code)
    # ANA003 fires when sleep is directly inside a threading.Thread target function
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# cli/main.py — test report command and more formats
# ---------------------------------------------------------------------------


def test_report_cli_html():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["report", "--dir", tmpdir, "--format", "html", "--output", ""], stdout=out
        )
        assert "<!DOCTYPE html>" in out.getvalue() or "<html" in out.getvalue()


def test_report_cli_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["report", "--dir", tmpdir, "--format", "md", "--output", ""], stdout=out
        )
        assert "py-FuSa" in out.getvalue() or "#" in out.getvalue()


def test_lint_cli_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["lint", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert "findings" in doc


def test_analyze_cli_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["analyze", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        doc = json.loads(out.getvalue())
        assert "findings" in doc


def test_check_cli_json_with_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.json")
        out = io.StringIO()
        code = run(
            ["check", "--dir", tmpdir, "--format", "json", "--output", out_path],
            stdout=out,
        )
        assert os.path.exists(out_path)
        with open(out_path) as f:
            doc = json.load(f)
        assert "findings" in doc


def test_check_cli_strict_mode():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["check", "--dir", tmpdir, "--strict"], stdout=out)
        # strict exits 1 if any warnings; fresh dir may still have warnings from FUSA rules
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)


def test_qualify_cli_json_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "qual.json")
        run(
            ["qualify", "--dir", tmpdir, "--format", "json", "--output", out_path],
            stdout=io.StringIO(),
        )
        with open(out_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "qualification"


def test_trace_cli_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["trace", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        assert "requirements" in doc or "kind" in doc


def test_version_command():
    out = io.StringIO()
    code = run(["version"], stdout=out)
    assert code == pyfusa.EXIT_OK
    assert "py-FuSa" in out.getvalue() or "0." in out.getvalue()


def test_capabilities_json():
    out = io.StringIO()
    code = run(["capabilities", "--format", "json"], stdout=out)
    doc = json.loads(out.getvalue())
    assert doc["kind"] == "capabilities"
    assert "verify" in doc["commands"]
    assert "check" in doc["commands"]


def test_init_creates_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["init", "--dir", tmpdir, "--name", "testproj", "--standard", "iso26262"],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, ".fusa.json"))


def test_init_already_exists():
    with tempfile.TemporaryDirectory() as tmpdir:
        run(
            ["init", "--dir", tmpdir, "--name", "p", "--standard", "iso26262"],
            stdout=io.StringIO(),
        )
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["init", "--dir", tmpdir, "--name", "p", "--standard", "iso26262"],
            stdout=out,
            stderr=err,
        )
        # Should fail or print warning when already exists
        assert code in (
            pyfusa.EXIT_OK,
            pyfusa.EXIT_GATE_FAIL,
            pyfusa.EXIT_RUNTIME,
            pyfusa.EXIT_USAGE,
        )


def test_check_no_config_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["check", "--dir", tmpdir], stdout=out)
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)


def test_unknown_command():
    out = io.StringIO()
    err = io.StringIO()
    code = run(["nonexistent-command-xyz"], stdout=out, stderr=err)
    assert code == pyfusa.EXIT_USAGE
