"""Requirements management — list, add, import/export CSV."""

from __future__ import annotations

import csv
import io
import json
import os
from typing import List, Optional

from pyfusa.config import REQS_FILE


def load(project_root: str) -> dict:
    path = os.path.join(project_root, REQS_FILE)
    if not os.path.exists(path):
        return {"requirements": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save(project_root: str, data: dict) -> None:
    path = os.path.join(project_root, REQS_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def add(project_root: str, req_id: str, title: str, text: str = "",
        standard: str = "", level: str = "HLR", asil: str = "") -> dict:
    data = load(project_root)
    # Check for duplicate
    existing_ids = {r["id"] for r in data.get("requirements", [])}
    if req_id in existing_ids:
        raise ValueError(f"requirement {req_id} already exists")
    entry: dict = {"id": req_id, "title": title}
    if text:
        entry["text"] = text
    if standard:
        entry["standard"] = standard
    if level:
        entry["level"] = level
    if asil:
        entry["asil"] = asil
    data.setdefault("requirements", []).append(entry)
    save(project_root, data)
    return entry


def to_csv(requirements: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "title", "text", "standard", "level", "asil"])
    for r in requirements:
        w.writerow([
            r.get("id", ""), r.get("title", ""), r.get("text", ""),
            r.get("standard", ""), r.get("level", ""), r.get("asil", ""),
        ])
    return buf.getvalue()


def from_csv(csv_text: str) -> List[dict]:
    reader = csv.DictReader(io.StringIO(csv_text))
    reqs = []
    for row in reader:
        r: dict = {"id": row.get("id", "").strip(), "title": row.get("title", "").strip()}
        for field in ("text", "standard", "level", "asil"):
            val = row.get(field, "").strip()
            if val:
                r[field] = val
        if r["id"]:
            reqs.append(r)
    return reqs


def render_text(requirements: List[dict], verbose: bool = False) -> str:
    if not requirements:
        return "no requirements"
    lines = []
    for r in requirements:
        lines.append(f"{r.get('id',''):20s} {r.get('title','')}")
        if verbose and r.get("text"):
            lines.append(f"    {r['text'][:120]}")
    return "\n".join(lines)
