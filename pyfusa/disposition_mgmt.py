"""Disposition management CLI helper (separate from engine disposition matching)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

from pyfusa.config import DISPOSITIONS_FILE

ACTIONS = ["accept", "fix", "defer", "reject"]


# fusa:req REQ-CLI009
def load(project_root: str) -> dict:
    path = os.path.join(project_root, DISPOSITIONS_FILE)
    if not os.path.exists(path):
        return {"project": os.path.basename(project_root), "entries": []}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    # Normalise: the engine uses a flat list; wrap if needed
    if isinstance(raw, list):
        return {"project": "", "entries": raw}
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
        "disposition": action,
        "rationale": rationale,
        "reviewer": reviewer,
        "date": now,
        "reference": reference,
    }
    if fingerprint:
        entry["fingerprint"] = fingerprint
    data.setdefault("entries", []).append(entry)
    save(project_root, data)
    return entry


# fusa:req REQ-CLI009
def list_all(project_root: str, rule_filter: Optional[str] = None) -> List[dict]:
    data = load(project_root)
    entries = data.get("entries", [])
    if rule_filter:
        entries = [e for e in entries if e.get("ruleId", "").startswith(rule_filter)]
    return entries


# fusa:req REQ-CLI009
def render_text(entries: List[dict]) -> str:
    if not entries:
        return "no disposition entries"
    lines = []
    for e in entries:
        lines.append(
            f"{e.get('ruleId', ''):12s} [{e.get('disposition', '').upper()}]  "
            f"{e.get('rationale', '')[:80]}"
        )
        if e.get("reviewer"):
            lines.append(
                f"              reviewer: {e['reviewer']}  date: {e.get('date', '')}"
            )
    return "\n".join(lines)
