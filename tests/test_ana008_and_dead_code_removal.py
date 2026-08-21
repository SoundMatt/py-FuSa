"""Regression tests for two findings from a follow-up authenticity/quality
audit of py-FuSa's own rule engine:

- ANA008's only finding-producing branch required a `global` statement
  inside a lambda body -- a Python SyntaxError, so no valid file could ever
  trigger it. The realistic pattern (Thread(target=named_function) where
  named_function uses `global`) was never handled at all.
- Four AST visitor classes (_ThreadVisitor, _AsyncEmptyVisitor,
  _GlobalMutationVisitor, _NoneDerefVisitor in analyze.py), one rule
  factory (_presence() in evidence.py), and one function (_node() in
  safetycase.py) were defined but never called anywhere -- dead code
  reading as coverage that doesn't exist. This just confirms their removal
  didn't take anything real down with it.
"""

from __future__ import annotations

import os
import tempfile

from pyfusa.config import default


def test_ana008_flags_global_mutation_in_named_thread_target():
    from pyfusa.rules.analyze import ANA008

    code = """
import threading
counter = 0
def worker():
    global counter
    counter += 1
t = threading.Thread(target=worker)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        findings = ANA008().run(tmpdir, cfg)
    assert len(findings) == 1


def test_ana008_does_not_flag_a_pure_thread_target():
    from pyfusa.rules.analyze import ANA008

    code = """
import threading
def worker(x):
    return x + 1
t = threading.Thread(target=worker)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        findings = ANA008().run(tmpdir, cfg)
    assert findings == []


def test_dead_visitor_classes_are_gone():
    import pyfusa.rules.analyze as analyze

    for name in (
        "_ThreadVisitor",
        "_AsyncEmptyVisitor",
        "_GlobalMutationVisitor",
        "_NoneDerefVisitor",
    ):
        assert not hasattr(analyze, name), f"{name} should have been removed"
    # the ones actually used by ANA003/ANA009 must still be present
    assert hasattr(analyze, "_SleepInThreadVisitor")
    assert hasattr(analyze, "_DeadCodeVisitor")


def test_presence_factory_is_gone():
    import pyfusa.rules.evidence as evidence

    assert not hasattr(evidence, "_presence")


def test_safetycase_node_helper_is_gone():
    import pyfusa.safetycase as safetycase

    assert not hasattr(safetycase, "_node")
