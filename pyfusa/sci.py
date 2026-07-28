"""Software Configuration Index — x-FuSa spec §9.3 `sci` (DO-178C §11.16).

`artifacts[].hash` MUST be a real SHA-256 of the file's current contents
(§2.7 hash convention) — a placeholder or presence-only boolean defeats the
point of a configuration index, so every entry here is a real per-file hash,
not a category-level presence check.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

import pyfusa
from pyfusa.config import Config

# Generated/config evidence files that, when present, belong in the
# configuration index alongside the project's own source tree.
_EVIDENCE_FILES = [
    ".fusa.json",
    ".fusa-reqs.json",
    ".fusa-hara.json",
    ".fusa-dispositions.json",
    ".fusa-problems.json",
    "check-report.json",
    "qualify-report.json",
    "sbom.json",
    "provenance.json",
    "fmea.json",
    "tara.json",
    "safety-case.json",
    "sas.json",
    "audit-pack.zip",
    "CHANGELOG.md",
    "LICENSE",
]


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _python_files(root: str, cfg: Config):
    from pyfusa.fmea import _python_files as _pf

    return _pf(root, cfg)


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


# fusa:req REQ-SCI001
def generate(project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    version = cfg.project.version or "0.1.0"

    artifacts = []
    for path in _python_files(project_root, cfg):
        artifacts.append(
            {"file": _rel(path, project_root), "hash": _file_hash(path), "version": version}
        )
    for fname in _EVIDENCE_FILES:
        full = os.path.join(project_root, fname)
        if os.path.exists(full) and os.path.isfile(full):
            artifacts.append({"file": fname, "hash": _file_hash(full), "version": version})

    artifacts.sort(key=lambda a: a["file"])

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "sci",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "artifacts": artifacts,
    }


# fusa:req REQ-SCI001
def render_text(doc: dict) -> str:
    lines = [f"SCI — {doc['project']}", f"Artifacts: {len(doc['artifacts'])}", ""]
    for a in doc["artifacts"]:
        lines.append(f"  {a['hash'][:19]}…  v{a['version']}  {a['file']}")
    return "\n".join(lines)
