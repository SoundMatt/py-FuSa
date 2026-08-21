"""Baseline — bulk snapshot of pre-existing findings' fingerprints.

Not part of the x-FuSa spec; a workflow-parity feature matching c-FuSa's
`cfusa baseline` (issue #208 there).

Dispositions (`pyfusa disposition add`) are a reviewed, one-at-a-time
judgment call on a single finding. That doesn't scale to turning the gate on
for an existing codebase with hundreds or thousands of pre-existing findings
nobody has looked at yet. `pyfusa baseline` snapshots every CURRENT finding's
fingerprint into `.fusa-baseline.json`; `engine.py`'s `_apply_baseline` then
excludes baselined fingerprints from the exit-code gate the same way an
accepted disposition is (fingerprint-scoped, findings stay visible in
output, tagged `dispositionSource="baseline"` so a report reader can tell
"predates baseline enrollment" apart from "reviewed and accepted") —
genuinely NEW findings introduced after the snapshot still fail the gate as
normal.

Re-running `pyfusa baseline` OVERWRITES the file with a fresh snapshot of
whatever findings exist right now (a finding that's since been fixed simply
drops out) — this is a bulk, regenerable starting point, not a permanent
record; use `pyfusa disposition add` for a durable, reviewed exception to a
specific finding.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from pyfusa.config import Config
from pyfusa.engine import Default


# fusa:req REQ-BASELINE001
def build(project_root: str, cfg: Config) -> tuple[dict, int]:
    """Run the default engine and build a baseline snapshot document.

    Returns `(doc, skipped_count)`. A finding already covered by a REAL
    (non-baseline-sourced) disposition is excluded — the baseline stays
    focused on genuinely un-reviewed pre-existing findings, and doesn't
    duplicate a reviewer's decision. `skipped_count` is that exclusion
    count, surfaced so the CLI can report it.

    A finding whose current disposition came from a *previous* baseline run
    (`disposition_source == "baseline"`) is deliberately NOT excluded here —
    it must still be re-included in the fresh snapshot below, or re-running
    `baseline` would silently drop still-present findings from the new file
    and they'd stop being excluded from the gate on the next `check`.
    """
    result = Default.run(project_root, cfg)

    entries = []
    skipped = 0
    for f in result.findings:
        if not f.fingerprint:
            continue
        if f.disposition and f.disposition_source != "baseline":
            skipped += 1
            continue
        entries.append(
            {
                "id": f"BASELINE-{len(entries) + 1:04d}",
                "rule": f.rule_id,
                "fingerprint": f.fingerprint,
                "action": "baseline",
            }
        )

    doc = {
        "project": cfg.project.name or os.path.basename(os.path.abspath(project_root)),
        "generatedAt": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "baseline": entries,
    }
    return doc, skipped


# fusa:req REQ-BASELINE002
def render_summary(doc: dict, skipped: int, path: str) -> str:
    n = len(doc["baseline"])
    msg = f"wrote {path}: {n} finding(s) baselined"
    if skipped:
        msg += f" ({skipped} already covered by a disposition, not duplicated)"
    return msg
