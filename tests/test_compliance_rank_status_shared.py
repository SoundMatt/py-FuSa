"""Regression test for a duplicated-logic finding from a follow-up
authenticity/quality audit: iso26262.py, iec61508.py, iec62443.py, and
iso21434.py each carried near-identical rank-comparison status logic
(three near-identical module-local _status() functions plus two more
copies inlined directly in run()) that could silently drift out of sync.
All four now share pyfusa.compliance._evidence.rank_status().

do178.py and unece.py are deliberately not part of this consolidation --
do178's DAL applicability is a per-objective list membership check, not a
single minimum-rank threshold, and unece has no level dimension at all."""

from __future__ import annotations

import json
import os
import tempfile

from pyfusa.compliance._evidence import rank_status
from pyfusa.config import default


def test_four_modules_share_the_same_rank_status_function():
    from pyfusa.compliance import iec61508, iec62443, iso21434, iso26262

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="t")
        # Every objective is either satisfied/gap/partial -- confirm each
        # module's run() actually calls through rank_status by checking a
        # partial-tier objective (project level below the objective's
        # minimum) reports "partial" consistently.
        for mod, kwargs in (
            (iso26262, {"asil": "QM"}),
            (iec61508, {"sil": "SIL-1"}),
            (iec62443, {"sl": "SL-1"}),
            (iso21434, {"cal": "CAL-1"}),
        ):
            doc = mod.run(tmpdir, cfg, **kwargs)
            assert doc["summary"]["partial"] > 0, mod.__name__


def test_rank_status_directly():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert rank_status(1, 2, tmpdir, "x.json") == ("partial", [])
        assert rank_status(2, 2, tmpdir, "x.json") == ("gap", [])
        with open(os.path.join(tmpdir, "x.json"), "w") as f:
            json.dump({"ok": True}, f)
        assert rank_status(2, 2, tmpdir, "x.json") == ("satisfied", ["x.json"])


def test_garbage_content_still_rejected_after_consolidation():
    """The content-aware check (garbage JSON doesn't count as evidence)
    must survive the refactor unchanged. Only .json-backed objectives are
    checked here -- non-JSON evidence (SECURITY.md etc.) has a lower,
    presence-only bar by design, see _evidence.evidence_present."""
    from pyfusa.compliance import iec62443

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="t")
        json_objectives = [o for o in iec62443._OBJECTIVES if o[-1].endswith(".json")]
        for _id, _clause, _title, _min, fname in json_objectives:
            with open(os.path.join(tmpdir, fname), "w") as f:
                f.write("garbage, not real evidence")
        doc = iec62443.run(tmpdir, cfg, sl="SL-2")
        satisfied_ids = {
            o["id"] for o in doc["objectives"] if o["status"] == "satisfied"
        }
        json_ids = {o[0] for o in json_objectives}
        assert not (satisfied_ids & json_ids)
