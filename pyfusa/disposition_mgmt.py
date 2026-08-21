"""Disposition management CLI helper (separate from engine disposition matching)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

from pyfusa.config import DISPOSITIONS_FILE

ACTIONS = ["accept", "fix", "defer", "reject"]

# §4.1 defines exactly three waiver states plus "open" — map the CLI's
# present-tense verbs onto the spec's canonical past-tense `status` values.
# "fix" is an acknowledgement, not a waiver: it records intent but MUST NOT
# suppress the gate, so it maps to "open".
_ACTION_TO_STATUS = {
    "accept": "accepted",
    "defer": "deferred",
    "reject": "rejected",
    "fix": "open",
}


# fusa:req REQ-CLI009
def load(project_root: str) -> dict:
    """Load `.fusa-dispositions.json` in the §1.2.3 canonical shape.

    This MUST stay aligned with `pyfusa.config.load_dispositions()` and
    `pyfusa.rules.evidence.DISP001`, which are the two other readers of this
    file — all three previously disagreed on the top-level key and per-entry
    action key, so `disposition add` silently never affected the gate.
    """
    path = os.path.join(project_root, DISPOSITIONS_FILE)
    if not os.path.exists(path):
        return {"project": os.path.basename(project_root), "dispositions": []}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    # Tolerate a bare JSON array on read (an older/foreign shape); the
    # canonical §1.2.3 shape is always an object with a "dispositions" key.
    if isinstance(raw, list):
        return {"project": "", "dispositions": raw}
    return raw


# fusa:req REQ-CLI009
def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, DISPOSITIONS_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


# fusa:req REQ-CLI009
def add(
    project_root: str,
    rule_id: str,
    rationale: str,
    reviewer: str = "",
    action: str = "accept",
    reference: str = "",
    fingerprint: str = "",
) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = load(project_root)
    entry: dict = {
        "ruleId": rule_id,
        # "status" is the §1.2.3/§4.1 gating field read by config.py and
        # engine.py; "action" preserves the verb the reviewer actually chose
        # for display, since "fix" has no separate status of its own.
        "status": _ACTION_TO_STATUS.get(action, "open"),
        "action": action,
        "rationale": rationale,
        "reviewer": reviewer,
        "date": now,
        "reference": reference,
    }
    if fingerprint:
        entry["fingerprint"] = fingerprint
    data.setdefault("dispositions", []).append(entry)
    save(project_root, data)
    return entry


# fusa:req REQ-CLI009
def list_all(project_root: str, rule_filter: Optional[str] = None) -> List[dict]:
    data = load(project_root)
    entries = data.get("dispositions", [])
    if rule_filter:
        entries = [e for e in entries if e.get("ruleId", "").startswith(rule_filter)]
    return entries


# fusa:req REQ-CLI009
def render_text(entries: List[dict]) -> str:
    if not entries:
        return "no disposition entries"
    lines = []
    for e in entries:
        label = e.get("action") or e.get("status", "")
        lines.append(
            f"{e.get('ruleId', ''):12s} [{label.upper()}]  "
            f"{e.get('rationale', '')[:80]}"
        )
        if e.get("reviewer"):
            lines.append(
                f"              reviewer: {e['reviewer']}  date: {e.get('date', '')}"
            )
    return "\n".join(lines)
