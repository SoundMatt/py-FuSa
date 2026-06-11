"""diff — compare two check-report JSON files."""

from __future__ import annotations

import json
import os
from typing import List, Tuple


def _key(finding: dict) -> str:
    loc = finding.get("location", {})
    return f"{finding.get('ruleId','')}:{loc.get('file','')}:{loc.get('line',0)}"


def compare(baseline_path: str, current_path: str) -> dict:
    with open(baseline_path, encoding="utf-8") as f:
        baseline = json.load(f)
    with open(current_path, encoding="utf-8") as f:
        current = json.load(f)

    baseline_findings = baseline.get("findings", [])
    current_findings = current.get("findings", [])

    baseline_idx = {_key(f): f for f in baseline_findings}
    current_idx = {_key(f): f for f in current_findings}

    introduced = [f for k, f in current_idx.items() if k not in baseline_idx]
    resolved = [f for k, f in baseline_idx.items() if k not in current_idx]
    unchanged = [f for k, f in current_idx.items() if k in baseline_idx]

    return {
        "introduced": introduced,
        "resolved": resolved,
        "unchanged": unchanged,
    }


def render_text(diff: dict) -> str:
    lines = []
    lines.append(f"introduced: {len(diff['introduced'])}  resolved: {len(diff['resolved'])}  unchanged: {len(diff['unchanged'])}")
    lines.append("")
    for f in diff["introduced"]:
        loc = f.get("location", {})
        lines.append(f"[+] {f.get('ruleId','')}  {loc.get('file','')}:{loc.get('line',0)}  {f.get('message','')}")
    for f in diff["resolved"]:
        loc = f.get("location", {})
        lines.append(f"[-] {f.get('ruleId','')}  {loc.get('file','')}:{loc.get('line',0)}  {f.get('message','')}")
    return "\n".join(lines)
