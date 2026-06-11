"""Tests for check command and engine."""

import os
import json
import tempfile

import pyfusa
from pyfusa.config import default, Config
from pyfusa.engine import Engine, RunResult


#fusa:test REQ-LINT001
def test_engine_finds_no_issues_in_empty_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="test")
        eng = Engine()
        result = eng.run(tmpdir, cfg)
        # No rules registered, so no findings
        assert result.findings == []


#fusa:test REQ-FUSA001
def test_run_result_summary():
    result = RunResult(findings=[
        pyfusa.Finding("LINT001", pyfusa.SEVERITY_ERROR, "msg", pyfusa.Location("f.py"), remediation="fix"),
        pyfusa.Finding("SEC001", pyfusa.SEVERITY_WARNING, "msg2", pyfusa.Location("f.py"), remediation="fix"),
        pyfusa.Finding("CFG001", pyfusa.SEVERITY_INFO, "msg3", pyfusa.Location("f.py"), remediation="fix"),
    ])
    s = result.summary()
    assert s["total"] == 3
    assert s["errors"] == 1
    assert s["warnings"] == 1
    assert s["infos"] == 1


#fusa:test REQ-FUSA001
def test_run_result_has_errors():
    r = RunResult(findings=[
        pyfusa.Finding("LINT001", pyfusa.SEVERITY_ERROR, "msg", pyfusa.Location("f.py"), remediation="fix"),
    ])
    assert r.has_errors()


#fusa:test REQ-FUSA001
def test_run_result_accepted_does_not_gate():
    f = pyfusa.Finding("LINT001", pyfusa.SEVERITY_ERROR, "msg", pyfusa.Location("f.py"), remediation="fix")
    f.disposition = pyfusa.DISPOSITION_ACCEPTED
    r = RunResult(findings=[f])
    assert not r.has_errors()


#fusa:test REQ-FUSA001
def test_run_result_deferred_does_not_gate():
    f = pyfusa.Finding("SEC001", pyfusa.SEVERITY_ERROR, "msg", pyfusa.Location("f.py"), remediation="fix")
    f.disposition = pyfusa.DISPOSITION_DEFERRED
    r = RunResult(findings=[f])
    assert not r.has_errors()


#fusa:test REQ-FUSA001
def test_run_result_rejected_still_gates():
    f = pyfusa.Finding("LINT001", pyfusa.SEVERITY_ERROR, "msg", pyfusa.Location("f.py"), remediation="fix")
    f.disposition = pyfusa.DISPOSITION_REJECTED
    r = RunResult(findings=[f])
    assert r.has_errors()


#fusa:test REQ-LINT001
def test_check_detects_fusa001_missing_config():
    from pyfusa.rules.project import RuleConfigPresent
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        rule = RuleConfigPresent()
        findings = rule.run(tmpdir, cfg)
        assert len(findings) == 1
        assert findings[0].rule_id == "FUSA001"
        assert findings[0].severity == pyfusa.SEVERITY_ERROR


#fusa:test REQ-FUSA001
def test_check_no_fusa001_when_config_present():
    from pyfusa.rules.project import RuleConfigPresent
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, ".fusa.json"), "w").close()
        cfg = default()
        findings = RuleConfigPresent().run(tmpdir, cfg)
        assert findings == []


#fusa:test REQ-LINT001
def test_lint001_function_too_long():
    from pyfusa.rules.lint import RuleFunctionLength
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "def big_func():\n" + "    x = 1\n" * 70 + "    return x\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleFunctionLength().run(tmpdir, cfg)
        assert any(f.rule_id == "LINT001" for f in findings)


#fusa:test REQ-SEC001
def test_sec001_bare_except():
    from pyfusa.rules.security import RuleBareExcept
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "try:\n    pass\nexcept:\n    pass\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleBareExcept().run(tmpdir, cfg)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC001"
        assert findings[0].severity == pyfusa.SEVERITY_ERROR


#fusa:test REQ-SEC001
def test_sec001_typed_except_passes():
    from pyfusa.rules.security import RuleBareExcept
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "try:\n    pass\nexcept ValueError:\n    pass\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleBareExcept().run(tmpdir, cfg)
        assert findings == []


#fusa:test REQ-SEC002
def test_sec002_eval_detected():
    from pyfusa.rules.security import RuleEvalUsage
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "result = eval('1 + 1')\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleEvalUsage().run(tmpdir, cfg)
        assert any(f.rule_id == "SEC002" for f in findings)


#fusa:test REQ-SEC003
def test_sec003_exec_detected():
    from pyfusa.rules.security import RuleExecUsage
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "exec('x = 1')\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleExecUsage().run(tmpdir, cfg)
        assert any(f.rule_id == "SEC003" for f in findings)


#fusa:test REQ-SEC004
def test_sec004_pickle_detected():
    from pyfusa.rules.security import RulePickleUsage
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "import pickle\ndata = pickle.load(open('f', 'rb'))\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RulePickleUsage().run(tmpdir, cfg)
        assert any(f.rule_id == "SEC004" for f in findings)


#fusa:test REQ-LINT005
def test_lint005_mutable_default():
    from pyfusa.rules.lint import RuleMutableDefaultArg
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "def foo(items=[]):\n    return items\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleMutableDefaultArg().run(tmpdir, cfg)
        assert any(f.rule_id == "LINT005" for f in findings)


#fusa:test REQ-LINT006
def test_lint006_star_import():
    from pyfusa.rules.lint import RuleStarImport
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "from os.path import *\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleStarImport().run(tmpdir, cfg)
        assert any(f.rule_id == "LINT006" for f in findings)


#fusa:test REQ-LINT007
def test_lint007_assert_detected():
    from pyfusa.rules.lint import RuleAssertStatement
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "assert x > 0, 'must be positive'\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleAssertStatement().run(tmpdir, cfg)
        assert any(f.rule_id == "LINT007" for f in findings)


#fusa:test REQ-CONC001
def test_conc001_thread_without_lock():
    from pyfusa.rules.concurrency import RuleThreadWithoutLock
    with tempfile.TemporaryDirectory() as tmpdir:
        src = "import threading\nt = threading.Thread(target=lambda: None)\nt.start()\n"
        path = os.path.join(tmpdir, "test.py")
        with open(path, "w") as f:
            f.write(src)
        cfg = default()
        findings = RuleThreadWithoutLock().run(tmpdir, cfg)
        assert any(f.rule_id == "CONC001" for f in findings)


#fusa:test REQ-FUSA001
def test_finding_fingerprint_auto_computed():
    f = pyfusa.Finding(
        rule_id="LINT001",
        severity=pyfusa.SEVERITY_WARNING,
        message="function is too long",
        location=pyfusa.Location(file="foo.py"),
        remediation="split the function",
    )
    assert f.fingerprint.startswith("sha256:")


#fusa:test REQ-FUSA001
def test_finding_to_dict_has_required_keys():
    f = pyfusa.Finding(
        rule_id="LINT001",
        severity=pyfusa.SEVERITY_WARNING,
        message="test",
        location=pyfusa.Location(file="f.py", line=10),
        remediation="fix",
    )
    d = f.to_dict()
    for key in ("ruleId", "severity", "message", "location", "category", "remediation", "fingerprint"):
        assert key in d, f"missing key {key!r}"
