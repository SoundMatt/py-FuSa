"""Regression tests for verified detection bugs found during a follow-up
authenticity/quality audit of py-FuSa's own rule engine (ANA001/ANA005/
ANA007, CYBER002/CYBER018). Each test reproduces the exact failure mode
found -- a false negative, a false positive, or an unreachable branch --
and confirms the fix without changing the rules' intended scope."""

from __future__ import annotations

import os
import tempfile

from pyfusa.config import default


def _run(rule_cls, code: str, filename: str = "mod.py"):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, filename), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        return rule_cls().run(tmpdir, cfg)


# ---------------------------------------------------------------------------
# ANA001 -- signal detection was file-scoped, not function-scoped
# ---------------------------------------------------------------------------


def test_ana001_signal_in_unrelated_function_does_not_silence_unsignaled_thread():
    from pyfusa.rules.analyze import ANA001

    code = """
import threading

def unrelated_helper():
    t = threading.Thread(target=lambda: print("hi"))
    t.start()

def signaled_worker(stop):
    while not stop.is_set():
        pass
"""
    findings = _run(ANA001, code)
    assert len(findings) == 1
    assert findings[0].location.line == 5  # the Thread(...) call in unrelated_helper


def test_ana001_local_event_in_same_function_still_suppresses():
    from pyfusa.rules.analyze import ANA001

    code = """
import threading

def worker():
    stop = threading.Event()
    t = threading.Thread(target=lambda: None)
    t.start()
"""
    assert _run(ANA001, code) == []


def test_ana001_module_level_signal_still_suppresses_module_level_thread():
    from pyfusa.rules.analyze import ANA001

    code = """
import threading
stop = threading.Event()
t = threading.Thread(target=lambda: None)
t.start()
"""
    assert _run(ANA001, code) == []


# ---------------------------------------------------------------------------
# ANA005 -- _call_name only resolved 2-level attribute chains, so
# os.environ.get (3 levels) could never match GLOBAL_FETCHERS
# ---------------------------------------------------------------------------


def test_ana005_detects_os_environ_get():
    from pyfusa.rules.analyze import ANA005

    code = """
def connect(timeout):
    t = os.environ.get("timeout")
    return t
"""
    findings = _run(ANA005, "import os\n" + code)
    assert len(findings) == 1


def test_ana005_still_detects_os_getenv():
    from pyfusa.rules.analyze import ANA005

    code = """
import os
def connect(timeout):
    t = os.getenv("timeout")
    return t
"""
    assert len(_run(ANA005, code)) == 1


# ---------------------------------------------------------------------------
# ANA007 -- a properly None-guarded attribute access was still flagged; the
# guard-check the rule's own remediation text advertises was never
# implemented
# ---------------------------------------------------------------------------


def test_ana007_guarded_access_is_not_flagged():
    from pyfusa.rules.analyze import ANA007

    code = """
def f(d):
    v = d.get("x")
    if v is not None:
        return v.upper()
    return None
"""
    assert _run(ANA007, code) == []


def test_ana007_unguarded_access_is_still_flagged():
    from pyfusa.rules.analyze import ANA007

    code = """
def f(d):
    v = d.get("x")
    return v.upper()
"""
    assert len(_run(ANA007, code)) == 1


def test_ana007_truthy_guard_is_also_recognized():
    from pyfusa.rules.analyze import ANA007

    code = """
def f(d):
    v = d.get("x")
    if v:
        return v.upper()
    return None
"""
    assert _run(ANA007, code) == []


# ---------------------------------------------------------------------------
# CYBER002 -- import-substring matching flagged secure code for merely
# importing from the same package a weak cipher also lives in
# ---------------------------------------------------------------------------


def test_cyber002_aes_only_usage_is_not_flagged():
    from pyfusa.rules.cyber import CYBER002

    code = (
        "from cryptography.hazmat.primitives.ciphers import algorithms, "
        "modes, Cipher\n"
        "def encrypt(key, iv, data):\n"
        "    return Cipher(algorithms.AES(key), modes.GCM(iv))\n"
    )
    assert _run(CYBER002, code) == []


def test_cyber002_tripledes_construction_is_flagged():
    from pyfusa.rules.cyber import CYBER002

    code = (
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "def encrypt(key):\n"
        "    return algorithms.TripleDES(key)\n"
    )
    assert len(_run(CYBER002, code)) == 1


# ---------------------------------------------------------------------------
# CYBER018 -- the Subscript detection branch was nested inside an
# ast.Call-only check, making it unreachable (node.value can't be both)
# ---------------------------------------------------------------------------


def test_cyber018_detects_request_args_subscript():
    from pyfusa.rules.cyber import CYBER018

    code = """
def handler(request):
    fname = request.args["file"]
    with open(fname) as f:
        return f.read()
"""
    assert len(_run(CYBER018, code)) == 1


def test_cyber018_detects_sys_argv_subscript():
    from pyfusa.rules.cyber import CYBER018

    code = """
import sys
def main():
    fname = sys.argv[1]
    with open(fname) as f:
        return f.read()
"""
    assert len(_run(CYBER018, code)) == 1
