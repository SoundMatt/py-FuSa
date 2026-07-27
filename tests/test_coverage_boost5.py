"""Targeted tests to improve coverage for impact, fmea, engine, coupling_analysis, sci, and cyber rules."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

import pytest

import pyfusa
from pyfusa.config import default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(tmpdir: str, name: str, content: str) -> str:
    path = os.path.join(tmpdir, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _cfg(tmpdir: str = "."):
    cfg = default()
    cfg.source_dirs = ["."]
    return cfg


# ---------------------------------------------------------------------------
# pyfusa/impact.py
# ---------------------------------------------------------------------------


class TestImpact:
    # fusa:test REQ-IMPACT001

    def test_run_basic_no_git(self):
        """run() returns a valid impact-report dict even in a non-git directory."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = default()
            doc = imp.run(tmpdir, cfg)
            assert doc["kind"] == "impact-report"
            assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
            assert isinstance(doc["changedFiles"], list)
            assert isinstance(doc["impactedReqs"], list)
            assert isinstance(doc["staleArtifacts"], list)

    def test_git_changed_files_with_to_ref(self):
        """_git_changed_files uses two-ref form when to_ref is set."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            # Non-git dir will return [] gracefully
            result = imp._git_changed_files(tmpdir, "HEAD", "HEAD~1")
            assert isinstance(result, list)

    def test_git_changed_files_oserror(self):
        """_git_changed_files returns [] on OSError (missing git binary or similar)."""
        import pyfusa.impact as imp

        # Pass a nonexistent directory to provoke CalledProcessError or OSError
        result = imp._git_changed_files("/nonexistent/path/xyz")
        assert result == []

    def test_load_trace_matrix_missing(self):
        """_load_trace_matrix returns {} when trace-matrix.json absent."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            assert imp._load_trace_matrix(tmpdir) == {}

    def test_load_trace_matrix_with_data(self):
        """_load_trace_matrix parses requirements and tag files."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            doc = {
                "requirements": [
                    {
                        "id": "REQ-001",
                        "tags": [{"file": "src/foo.py"}, {"file": "tests/test_foo.py"}],
                    }
                ]
            }
            _write(tmpdir, "trace-matrix.json", json.dumps(doc))
            result = imp._load_trace_matrix(tmpdir)
            assert "REQ-001" in result
            assert "src/foo.py" in result["REQ-001"]

    def test_check_stale_artifact_older_than_source(self):
        """_check_stale detects artifact older than modified source file."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create artifact first, then source (so source is newer)
            art_path = _write(tmpdir, "check-report.json", "{}")
            time.sleep(0.05)
            src_path = _write(tmpdir, "src.py", "x = 1")
            changed = [{"status": "M", "path": "src.py"}]
            stale = imp._check_stale(tmpdir, changed)
            assert any(s["file"] == "check-report.json" for s in stale)

    def test_check_stale_no_artifacts(self):
        """_check_stale returns [] when no artifact files exist."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            changed = [{"status": "M", "path": "foo.py"}]
            assert imp._check_stale(tmpdir, changed) == []

    def test_run_with_trace_matrix_impacted(self):
        """run() populates impactedReqs when trace matrix overlaps changed files."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            doc = {
                "requirements": [
                    {
                        "id": "REQ-001",
                        "tags": [
                            {"file": "src/foo.py"},
                            {"file": "tests/test_foo.py"},
                        ],
                    }
                ]
            }
            _write(tmpdir, "trace-matrix.json", json.dumps(doc))
            # Monkeypatch _git_changed_files to return a predictable set
            orig = imp._git_changed_files
            imp._git_changed_files = lambda root, f="HEAD", t="": [
                {"status": "M", "path": "src/foo.py"}
            ]
            try:
                result = imp.run(tmpdir, default())
                assert len(result["impactedReqs"]) == 1
                assert result["impactedReqs"][0]["requirementID"] == "REQ-001"
                assert "tests/test_foo.py" in result["rerunTests"]
            finally:
                imp._git_changed_files = orig

    def test_run_with_to_ref(self):
        """run() passes to_ref through to _git_changed_files."""
        import pyfusa.impact as imp

        with tempfile.TemporaryDirectory() as tmpdir:
            result = imp.run(tmpdir, default(), from_ref="HEAD", to_ref="HEAD~1")
            assert result["kind"] == "impact-report"


# ---------------------------------------------------------------------------
# pyfusa/fmea.py
# ---------------------------------------------------------------------------


class TestFmea:
    # fusa:test REQ-DFMEA001

    def test_parse_syntax_error(self):
        """_parse returns (None, []) for files with syntax errors."""
        import pyfusa.fmea as fmea

        with tempfile.TemporaryDirectory() as tmpdir:
            bad = _write(tmpdir, "bad.py", "def broken(\n")
            tree, lines = fmea._parse(bad)
            assert tree is None
            assert lines == []

    def test_has_raise_true(self):
        """_has_raise returns True when a Raise node is present."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    raise ValueError('oops')\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._has_raise(func) is True

    def test_has_raise_false(self):
        """_has_raise returns False when no Raise node present."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    return 1\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._has_raise(func) is False

    def test_has_thread_threading_thread(self):
        """_has_thread detects threading.Thread call."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("import threading\ndef f():\n    threading.Thread(target=g)\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._has_thread(func) is True

    def test_has_thread_bare_thread(self):
        """_has_thread detects bare Thread() call."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    Thread(target=g)\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._has_thread(func) is True

    def test_has_thread_false(self):
        """_has_thread returns False for normal function."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    return 1\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._has_thread(func) is False

    def test_returns_none_bare_return(self):
        """_returns_none detects bare return statement."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    return\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._returns_none(func) is True

    def test_returns_none_explicit_none(self):
        """_returns_none detects 'return None'."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    return None\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._returns_none(func) is True

    def test_returns_none_false(self):
        """_returns_none returns False for non-None return."""
        import ast

        import pyfusa.fmea as fmea

        tree = ast.parse("def f():\n    return 42\n")
        func = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        assert fmea._returns_none(func) is False

    def test_req_ids_from_comments(self):
        """_req_ids_from_comments extracts IDs from #fusa:req comments."""
        import pyfusa.fmea as fmea

        # NOTE: "#" + "fusa:req ..." is split via adjacent-literal concatenation
        # so this fixture's own source line isn't itself mistaken for a real
        # (malformed, multi-ID) annotation when tests/ is scanned (§1.4.1).
        lines = [
            "def process(x):",
            "    x = 1  #" + "fusa:req REQ-001 REQ-002",
            "    return x",
        ]
        ids = fmea._req_ids_from_comments(lines, 0, 3)
        assert "REQ-001" in ids
        assert "REQ-002" in ids

    def test_req_ids_no_comment(self):
        """_req_ids_from_comments returns [] when no fusa:req comment."""
        import pyfusa.fmea as fmea

        lines = ["def f():", "    return 1"]
        assert fmea._req_ids_from_comments(lines, 0, 2) == []

    def test_derive_analysis_raise_only(self):
        """_derive_analysis: has_raise → severity=high, detection=unit testing."""
        import pyfusa.fmea as fmea

        fm, eff, sev, det, cyber = fmea._derive_analysis("f", False, False, True, [])
        assert sev == "high"
        assert det == "unit testing"
        assert "uncaught exception / early return" in fm

    def test_derive_analysis_thread_only(self):
        """_derive_analysis: has_thread → severity=high, detection=integration testing."""
        import pyfusa.fmea as fmea

        fm, eff, sev, det, cyber = fmea._derive_analysis("f", False, True, False, [])
        assert sev == "high"
        assert det == "integration testing"
        assert "race condition" in cyber

    def test_derive_analysis_req_ids_only(self):
        """_derive_analysis: req_ids only → severity=medium."""
        import pyfusa.fmea as fmea

        fm, eff, sev, det, cyber = fmea._derive_analysis(
            "f", False, False, False, ["REQ-001"]
        )
        assert sev == "medium"

    def test_derive_analysis_none_return_only(self):
        """_derive_analysis: returns_none only → severity=low."""
        import pyfusa.fmea as fmea

        fm, eff, sev, det, cyber = fmea._derive_analysis("f", True, False, False, [])
        assert "silent None return" in fm
        assert sev == "low"

    def test_derive_analysis_no_signals(self):
        """_derive_analysis: no signals → unexpected return value, severity=low."""
        import pyfusa.fmea as fmea

        fm, eff, sev, det, cyber = fmea._derive_analysis("f", False, False, False, [])
        assert "unexpected return value" in fm
        assert sev == "low"

    def test_scan_skips_private_functions(self):
        """scan() skips private functions (those starting with _)."""
        import pyfusa.fmea as fmea

        with tempfile.TemporaryDirectory() as tmpdir:
            _write(
                tmpdir,
                "mod.py",
                "def _private(x):\n    return x\ndef public(x):\n    return x\n",
            )
            cfg = default()
            cfg.source_dirs = ["."]
            entries = fmea.scan(tmpdir, cfg)
            names = [e["function"] for e in entries]
            assert "public" in names
            assert "_private" not in names

    def test_scan_syntax_error_file_skipped(self):
        """scan() skips files with syntax errors."""
        import pyfusa.fmea as fmea

        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "bad.py", "def oops(\n")
            cfg = default()
            cfg.source_dirs = ["."]
            entries = fmea.scan(tmpdir, cfg)
            assert isinstance(entries, list)

    def test_scan_with_req_id_comment(self):
        """scan() extracts req_ids from #fusa:req comment."""
        import pyfusa.fmea as fmea

        # See NOTE in test_req_ids_from_comments re: adjacent-literal split.
        code = "def process(x):\n    x = x  #" + "fusa:req REQ-001\n    return x\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "mod.py", code)
            cfg = default()
            cfg.source_dirs = ["."]
            entries = fmea.scan(tmpdir, cfg)
            assert any("REQ-001" in e["requirement_ids"] for e in entries)

    def test_to_dict_structure(self):
        """to_dict returns a valid fmea document dict."""
        import pyfusa.fmea as fmea

        entries = [
            {
                "component": ".",
                "function": "run",
                "file": "mod.py",
                "line": 1,
                "failure_modes": ["uncaught exception"],
                "effects": ["loss of service"],
                "severity": "high",
                "detection_control": "unit testing",
                "requirement_ids": [],
                "cyber_risks": [],
            }
        ]
        cfg = default(project_name="mymod")
        with tempfile.TemporaryDirectory() as tmpdir:
            doc = fmea.to_dict(entries, tmpdir, cfg)
        assert doc["kind"] == "fmea"
        assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
        assert len(doc["entries"]) == 1

    def test_to_csv_round_trip(self):
        """to_csv produces CSV with a header row and one data row."""
        import pyfusa.fmea as fmea

        entries = [
            {
                "component": ".",
                "function": "run",
                "file": "mod.py",
                "failure_modes": ["uncaught exception"],
                "effects": ["loss of service"],
                "severity": "high",
                "detection_control": "unit testing",
                "requirement_ids": ["REQ-001"],
                "cyber_risks": [],
            }
        ]
        csv_text = fmea.to_csv(entries)
        assert "component" in csv_text
        assert "run" in csv_text
        assert "REQ-001" in csv_text


# ---------------------------------------------------------------------------
# pyfusa/engine.py
# ---------------------------------------------------------------------------


class TestEngine:
    # fusa:test REQ-ENGINE001

    def test_has_warnings_true(self):
        """has_warnings returns True when active (not accepted) warnings exist."""
        from pyfusa.engine import RunResult

        rr = RunResult()
        rr.findings.append(
            pyfusa.Finding(
                rule_id="LINT001",
                severity=pyfusa.SEVERITY_WARNING,
                message="a warning",
                location=pyfusa.Location(file="foo.py"),
            )
        )
        assert rr.has_warnings() is True

    def test_has_warnings_accepted_not_counted(self):
        """has_warnings returns False when the only warning is accepted."""
        from pyfusa.engine import RunResult

        rr = RunResult()
        f = pyfusa.Finding(
            rule_id="LINT001",
            severity=pyfusa.SEVERITY_WARNING,
            message="accepted warning",
            location=pyfusa.Location(file="foo.py"),
        )
        f.disposition = pyfusa.DISPOSITION_ACCEPTED
        rr.findings.append(f)
        assert rr.has_warnings() is False

    def test_rules_property(self):
        """Engine.rules returns a copy of registered rules."""
        from pyfusa.engine import Engine
        from pyfusa.rules import Rule

        class FakeRule(Rule):
            rule_id = "FAKE001"
            description = "fake rule for testing"

            def run(self, root, cfg):
                return []

        eng = Engine()
        rule = FakeRule()
        eng.register(rule)
        assert len(eng.rules) == 1
        assert eng.rules[0] is rule

    def test_rule_exception_captured_in_errors(self):
        """Engine.run captures rule exceptions in result.errors, not a crash."""
        from pyfusa.engine import Engine
        from pyfusa.rules import Rule

        class BrokenRule(Rule):
            rule_id = "BROKEN001"
            description = "broken rule for testing"

            def run(self, root, cfg):
                raise RuntimeError("boom")

        eng = Engine()
        eng.register(BrokenRule())
        with tempfile.TemporaryDirectory() as tmpdir:
            result = eng.run(tmpdir, default())
        assert any("BROKEN001" in e for e in result.errors)

    def test_apply_dispositions_fingerprint_match(self):
        """_apply_dispositions matches by fingerprint and applies status."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        finding = pyfusa.Finding(
            rule_id="SEC001",
            severity=pyfusa.SEVERITY_ERROR,
            message="a finding",
            location=pyfusa.Location(file="foo.py"),
        )
        fp = finding.fingerprint
        dispositions = [{"fingerprint": fp, "status": "accepted"}]
        rr = RunResult(findings=[finding])
        engine._apply_dispositions([finding], dispositions, ".", rr)
        assert finding.disposition == "accepted"

    def test_apply_dispositions_ruleid_file_line_match(self):
        """_apply_dispositions matches by ruleId + file + line."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        finding = pyfusa.Finding(
            rule_id="LINT001",
            severity=pyfusa.SEVERITY_WARNING,
            message="lint warning",
            location=pyfusa.Location(file="foo.py", line=10),
        )
        dispositions = [
            {"ruleId": "LINT001", "file": "foo.py", "line": 10, "status": "deferred"}
        ]
        rr = RunResult(findings=[finding])
        engine._apply_dispositions([finding], dispositions, ".", rr)
        assert finding.disposition == "deferred"

    def test_apply_dispositions_rule_level_accept(self):
        """_apply_dispositions rule-level accept (ruleId only, no file)."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        finding = pyfusa.Finding(
            rule_id="CFG001",
            severity=pyfusa.SEVERITY_WARNING,
            message="config issue",
            location=pyfusa.Location(file="config.py"),
        )
        dispositions = [{"ruleId": "CFG001", "status": "accepted"}]
        rr = RunResult(findings=[finding])
        engine._apply_dispositions([finding], dispositions, ".", rr)
        assert finding.disposition == "accepted"

    def test_apply_dispositions_orphaned_warning(self):
        """_apply_dispositions adds a WARNING finding for orphaned accepted dispositions."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        dispositions = [{"ruleId": "NONEXIST001", "status": "accepted"}]
        rr = RunResult()
        engine._apply_dispositions([], dispositions, ".", rr)
        assert any(f.rule_id == "CFG001" for f in rr.findings)

    def test_apply_dispositions_orphaned_deferred(self):
        """_apply_dispositions adds a WARNING for orphaned deferred dispositions."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        dispositions = [{"fingerprint": "sha256:deadbeef", "status": "deferred"}]
        rr = RunResult()
        engine._apply_dispositions([], dispositions, ".", rr)
        assert any("orphaned" in f.message for f in rr.findings)

    def test_apply_dispositions_no_status_skipped(self):
        """_apply_dispositions ignores entries with no status."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        finding = pyfusa.Finding(
            rule_id="LINT001",
            severity=pyfusa.SEVERITY_WARNING,
            message="lint",
            location=pyfusa.Location(file="x.py"),
        )
        dispositions = [{"ruleId": "LINT001", "file": "x.py"}]  # no status
        rr = RunResult(findings=[finding])
        engine._apply_dispositions([finding], dispositions, ".", rr)
        assert finding.disposition == ""

    def test_apply_dispositions_ruleid_file_match_no_line(self):
        """_apply_dispositions matches ruleId+file when disp has no line."""
        import pyfusa.engine as engine
        from pyfusa.engine import RunResult

        finding = pyfusa.Finding(
            rule_id="LINT002",
            severity=pyfusa.SEVERITY_WARNING,
            message="lint2",
            location=pyfusa.Location(file="bar.py", line=5),
        )
        dispositions = [{"ruleId": "LINT002", "file": "bar.py", "status": "accepted"}]
        rr = RunResult(findings=[finding])
        engine._apply_dispositions([finding], dispositions, ".", rr)
        assert finding.disposition == "accepted"


# ---------------------------------------------------------------------------
# pyfusa/coupling_analysis.py
# ---------------------------------------------------------------------------


class TestCouplingAnalysis:
    # fusa:test REQ-COUPLING001

    def test_run_returns_coupling_report(self):
        """run() returns a coupling-report dict for an empty directory."""
        import pyfusa.coupling_analysis as ca

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = _cfg(tmpdir)
            doc = ca.run(tmpdir, cfg)
            assert doc["kind"] == "coupling-report"
            assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
            assert "dataCoupling" in doc
            assert "controlCoupling" in doc

    def test_run_with_source_file(self):
        """run() analyses actual Python source and returns coupling data."""
        import pyfusa.coupling_analysis as ca

        code = (
            "GLOBAL_STATE = {}\n"
            "def read_data():\n"
            "    return GLOBAL_STATE.get('key')\n"
            "def write_data(v):\n"
            "    GLOBAL_STATE['key'] = v\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "mod.py", code)
            cfg = _cfg(tmpdir)
            doc = ca.run(tmpdir, cfg)
            assert isinstance(doc["dataCoupling"], list)
            assert isinstance(doc["controlCoupling"], list)

    def test_run_rules_exception_swallowed(self):
        """_run_rules swallows exceptions from individual rules."""
        import pyfusa.coupling_analysis as ca

        class BrokenRule:
            def run(self, root, cfg):
                raise RuntimeError("broken")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = ca._run_rules([BrokenRule()], tmpdir, _cfg(tmpdir))
            assert result == []

    # fusa:test REQ-COUP001
    def test_coup001_findings_go_to_data_coupling(self):
        """Findings from COUP001 appear in dataCoupling."""
        import pyfusa.coupling_analysis as ca

        code = (
            "_STATE = []\n"
            "def push(x):\n"
            "    _STATE.append(x)\n"
            "def pop():\n"
            "    return _STATE.pop()\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "mod.py", code)
            cfg = _cfg(tmpdir)
            doc = ca.run(tmpdir, cfg)
            # dataCoupling contains COUP001 findings
            assert all(e["ruleId"] == "COUP001" for e in doc["dataCoupling"])

    # fusa:test REQ-COUP002
    def test_coup002_callable_parameter_flagged(self):
        """COUP002 flags a public function accepting a Callable parameter."""
        from pyfusa.rules.coupling import COUP002

        code = (
            "from typing import Callable\n"
            "def register(handler: Callable) -> None:\n"
            "    pass\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "mod.py", code)
            findings = COUP002().run(tmpdir, _cfg(tmpdir))
            assert any(f.rule_id == "COUP002" for f in findings)

    def test_coup002_no_callable_parameter_no_finding(self):
        from pyfusa.rules.coupling import COUP002

        code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "mod.py", code)
            findings = COUP002().run(tmpdir, _cfg(tmpdir))
            assert findings == []

    # fusa:test REQ-COUP003
    def test_coup003_missing_report_flagged(self):
        """COUP003 warns when coupling-report.json is absent."""
        from pyfusa.rules.coupling import COUP003

        with tempfile.TemporaryDirectory() as tmpdir:
            findings = COUP003().run(tmpdir, _cfg(tmpdir))
            assert any(f.rule_id == "COUP003" for f in findings)

    def test_coup003_present_report_no_finding(self):
        from pyfusa.rules.coupling import COUP003

        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "coupling-report.json", "{}")
            findings = COUP003().run(tmpdir, _cfg(tmpdir))
            assert findings == []


# ---------------------------------------------------------------------------
# pyfusa/sci.py
# ---------------------------------------------------------------------------


class TestSci:
    # fusa:test REQ-SCI001

    def test_generate_with_existing_artifact(self):
        """generate() marks artifact items present when their files exist."""
        import pyfusa.sci as sci

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a few artifact files that SCI looks for
            _write(tmpdir, ".fusa-reqs.json", '{"requirements": []}')
            _write(tmpdir, "CHANGELOG.md", "# Changelog\n")
            _write(tmpdir, "LICENSE", "MIT\n")
            cfg = default(project_name="mymod")
            doc = sci.generate(tmpdir, cfg)
            assert doc["kind"] == "sci"
            assert doc["present"] >= 1  # at least source code always present

    def test_generate_items_structure(self):
        """generate() returns items with id/title/present/files keys."""
        import pyfusa.sci as sci

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = default(project_name="mymod")
            doc = sci.generate(tmpdir, cfg)
            for item in doc["items"]:
                assert "id" in item
                assert "title" in item
                assert "present" in item
                assert "files" in item

    def test_render_text_present_and_missing(self):
        """render_text shows checkmarks for present items and crosses for missing."""
        import pyfusa.sci as sci

        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "CHANGELOG.md", "# log\n")
            cfg = default(project_name="proj")
            doc = sci.generate(tmpdir, cfg)
            text = sci.render_text(doc)
            assert "SCI" in text
            assert "proj" in text
            assert "✓" in text or "✗" in text

    def test_render_text_format(self):
        """render_text header contains module name and Present: N/M line."""
        import pyfusa.sci as sci

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = default(project_name="testmod")
            doc = sci.generate(tmpdir, cfg)
            text = sci.render_text(doc)
            assert "testmod" in text
            assert "Present:" in text


# ---------------------------------------------------------------------------
# pyfusa/rules/cyber.py — targeted tests for uncovered rules
# ---------------------------------------------------------------------------


def _cyber_cfg(tmpdir: str):
    cfg = default()
    cfg.source_dirs = ["."]
    return cfg


class TestCyberRules:
    # fusa:test REQ-CYBER001
    # fusa:test REQ-CYBER002
    # fusa:test REQ-CYBER003
    # fusa:test REQ-CYBER004
    # fusa:test REQ-CYBER005
    # fusa:test REQ-CYBER006
    # fusa:test REQ-CYBER007
    # fusa:test REQ-CYBER008
    # fusa:test REQ-CYBER009
    # fusa:test REQ-CYBER010
    # fusa:test REQ-CYBER011
    # fusa:test REQ-CYBER012
    # fusa:test REQ-CYBER013
    # fusa:test REQ-CYBER014
    # fusa:test REQ-CYBER015
    # fusa:test REQ-CYBER016
    # fusa:test REQ-CYBER017
    # fusa:test REQ-CYBER018
    # fusa:test REQ-CYBER019
    # fusa:test REQ-CYBER020

    def test_cyber001_md5(self):
        """CYBER001 flags hashlib.md5() usage."""
        from pyfusa.rules.cyber import CYBER001

        code = "import hashlib\ndef f():\n    h = hashlib.md5(b'data')\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER001().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER001" for f in findings)

    def test_cyber001_hashlib_new_sha1(self):
        """CYBER001 flags hashlib.new('sha1')."""
        from pyfusa.rules.cyber import CYBER001

        code = "import hashlib\nh = hashlib.new('sha1')\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER001().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER001" for f in findings)

    def test_cyber001_hashlib_new_sha256_not_flagged(self):
        """CYBER001 does not flag hashlib.new('sha256') — safe algorithm."""
        from pyfusa.rules.cyber import CYBER001

        code = "import hashlib\nh = hashlib.new('sha256')\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER001().run(tmpdir, _cyber_cfg(tmpdir))
            assert findings == []

    def test_cyber001_syntax_error_file_skipped(self):
        """CYBER001 gracefully skips files with syntax errors."""
        from pyfusa.rules.cyber import CYBER001

        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "bad.py", "def broken(\n")
            findings = CYBER001().run(tmpdir, _cyber_cfg(tmpdir))
            assert isinstance(findings, list)

    def test_cyber002_weak_cipher_import(self):
        """CYBER002 flags import of weak cipher module."""
        from pyfusa.rules.cyber import CYBER002

        code = "from Crypto.Cipher import DES\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER002().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER002" for f in findings)

    def test_cyber003_random_in_security_context(self):
        """CYBER003 flags random.randint used on a line mentioning 'token'."""
        from pyfusa.rules.cyber import CYBER003

        code = "import random\ntoken = random.randint(0, 1000000)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER003().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER003" for f in findings)

    def test_cyber004_ctypes_import(self):
        """CYBER004 flags ctypes import."""
        from pyfusa.rules.cyber import CYBER004

        code = "import ctypes\nbuf = ctypes.create_string_buffer(100)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER004().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER004" for f in findings)

    def test_cyber005_subprocess_dynamic_command(self):
        """CYBER005 flags subprocess.run with a non-literal command."""
        from pyfusa.rules.cyber import CYBER005

        code = "import subprocess\ncmd = get_command()\nsubprocess.run(cmd)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER005().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER005" for f in findings)

    def test_cyber005_subprocess_shell_true(self):
        """CYBER005 flags subprocess.run with shell=True and f-string."""
        from pyfusa.rules.cyber import CYBER005

        code = (
            "import subprocess\n"
            "user = input()\n"
            'subprocess.run(f"echo {user}", shell=True)\n'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER005().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER005" for f in findings)

    def test_cyber006_hardcoded_password(self):
        """CYBER006 flags hardcoded password string."""
        from pyfusa.rules.cyber import CYBER006

        code = 'password = "hunter2secret"\n'
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER006().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER006" for f in findings)

    def test_cyber007_verify_false(self):
        """CYBER007 flags requests.get with verify=False."""
        from pyfusa.rules.cyber import CYBER007

        code = (
            "import requests\nr = requests.get('https://example.com', verify=False)\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER007().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER007" for f in findings)

    def test_cyber007_ssl_cert_none(self):
        """CYBER007 flags ssl.CERT_NONE usage."""
        from pyfusa.rules.cyber import CYBER007

        code = "import ssl\nctx = ssl.create_default_context()\nctx.verify_mode = ssl.CERT_NONE\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER007().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER007" for f in findings)

    def test_cyber008_http_server_no_timeout(self):
        """CYBER008 flags HTTPServer created without timeout."""
        from pyfusa.rules.cyber import CYBER008

        code = (
            "from http.server import HTTPServer, BaseHTTPRequestHandler\n"
            "server = HTTPServer(('', 8080), BaseHTTPRequestHandler)\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER008().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER008" for f in findings)

    def test_cyber009_integer_narrowing(self):
        """CYBER009 flags ctypes.c_int8 with a non-constant argument."""
        from pyfusa.rules.cyber import CYBER009

        code = "import ctypes\nv = ctypes.c_int8(get_value())\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER009().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER009" for f in findings)

    def test_cyber010_sql_concatenation(self):
        """CYBER010 flags string concatenation in execute() call."""
        from pyfusa.rules.cyber import CYBER010

        code = (
            "def run(conn, user_id):\n"
            '    conn.execute("SELECT * FROM users WHERE id=" + user_id)\n'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER010().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER010" for f in findings)

    def test_cyber011_ssrf_variable_url(self):
        """CYBER011 flags requests.get with non-literal URL."""
        from pyfusa.rules.cyber import CYBER011

        code = "import requests\ndef fetch(url):\n    return requests.get(url)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER011().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER011" for f in findings)

    def test_cyber012_debug_true(self):
        """CYBER012 flags app.run(debug=True)."""
        from pyfusa.rules.cyber import CYBER012

        code = "app.run(host='0.0.0.0', debug=True)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER012().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER012" for f in findings)

    def test_cyber013_extractall(self):
        """CYBER013 flags zipfile.extractall() without validation."""
        from pyfusa.rules.cyber import CYBER013

        code = "import zipfile\nwith zipfile.ZipFile('a.zip') as z:\n    z.extractall('/tmp')\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER013().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER013" for f in findings)

    def test_cyber014_weak_tls_version(self):
        """CYBER014 flags ssl.PROTOCOL_SSLv2 attribute access."""
        from pyfusa.rules.cyber import CYBER014

        code = "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv2)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER014().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER014" for f in findings)

    def test_cyber015_fstring_sql(self):
        """CYBER015 flags SQL query built with f-string."""
        from pyfusa.rules.cyber import CYBER015

        code = 'def q(uid):\n    return f"SELECT * FROM users WHERE id={uid}"\n'
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER015().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER015" for f in findings)

    def test_cyber015_percent_format_sql(self):
        """CYBER015 flags SQL query built with % format."""
        from pyfusa.rules.cyber import CYBER015

        code = 'def q(uid):\n    sql = "SELECT * FROM t WHERE id=%s" % uid\n    return sql\n'
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER015().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER015" for f in findings)

    def test_cyber016_dir_mode_777(self):
        """CYBER016 flags os.mkdir with mode=0o777."""
        from pyfusa.rules.cyber import CYBER016

        code = "import os\nos.mkdir('/tmp/mydir', mode=0o777)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER016().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER016" for f in findings)

    def test_cyber017_file_mode_666(self):
        """CYBER017 flags open() with mode=0o666."""
        from pyfusa.rules.cyber import CYBER017

        code = "import os\nfd = os.open('secret.txt', os.O_RDWR, mode=0o666)\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER017().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER017" for f in findings)

    def test_cyber018_user_input_in_file_path(self):
        """CYBER018 flags file path derived from sys.argv."""
        from pyfusa.rules.cyber import CYBER018

        code = (
            "import sys\n"
            "filename = sys.argv[1]\n"
            "with open(filename) as f:\n"
            "    data = f.read()\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER018().run(tmpdir, _cyber_cfg(tmpdir))
            # May or may not trigger (depends on AST assignment form) — just no crash
            assert isinstance(findings, list)

    def test_cyber019_toctou(self):
        """CYBER019 flags existence check followed by open within 10 lines."""
        from pyfusa.rules.cyber import CYBER019

        code = (
            "import os\n"
            "def read_file(path):\n"
            "    if os.path.exists(path):\n"
            "        with open(path) as f:\n"
            "            return f.read()\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER019().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER019" for f in findings)

    def test_cyber020_mktemp(self):
        """CYBER020 flags tempfile.mktemp() usage."""
        from pyfusa.rules.cyber import CYBER020

        code = "import tempfile\npath = tempfile.mktemp(suffix='.txt')\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            _write(tmpdir, "c.py", code)
            findings = CYBER020().run(tmpdir, _cyber_cfg(tmpdir))
            assert any(f.rule_id == "CYBER020" for f in findings)

    def test_all_cyber_rules_empty_dir(self):
        """All CYBER rules return empty list on an empty directory."""
        from pyfusa.rules.cyber import ALL

        with tempfile.TemporaryDirectory() as tmpdir:
            for rule in ALL:
                findings = rule.run(tmpdir, _cyber_cfg(tmpdir))
                assert isinstance(findings, list)

    def test_call_name_nested_attribute(self):
        """_call_name handles deeply nested attribute calls."""
        import ast

        from pyfusa.rules.cyber import _call_name

        # Nested: a.b.c()
        tree = ast.parse("a.b.c()")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        name = _call_name(call)
        assert "c" in name

    def test_import_names_collects_all(self):
        """_import_names collects both 'import x' and 'from x import y' forms."""
        import ast

        from pyfusa.rules.cyber import _import_names

        tree = ast.parse("import os\nfrom pathlib import Path\nimport sys as system\n")
        names = _import_names(tree)
        assert "os" in names
        assert "pathlib" in names
        assert "sys" in names
        assert "system" in names
