"""Audit pack — evidence bundle ZIP (§8)."""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Optional

from pyfusa.config import (
    CONFIG_FILE,
    DISPOSITIONS_FILE,
    EVIDENCE_FILE,
    HARA_FILE,
    REQS_FILE,
)

_GENERATED_FILES = [
    "sbom.json",
    "provenance.json",
    "provenance.intoto.jsonl",
    "artifact-manifest.json",
    "safety-case.json",
    "safety-case.md",
    "safety-case.mermaid",
    "tara.json",
    "tara.md",
    "fmea.json",
    "fmea.csv",
    "qualify-report.json",
    "coupling-report.json",
    "cyber-report.json",
    "vuln.json",
    "boundary.dot",
    "boundary.mermaid",
    "comp-report.json",
]

_INPUT_FILES = [
    CONFIG_FILE,
    REQS_FILE,
    DISPOSITIONS_FILE,
    HARA_FILE,
    EVIDENCE_FILE,
]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# fusa:req REQ-FUSA001
def create(project_root: str, output_path: Optional[str] = None) -> str:
    """Create audit-pack.zip at output_path (default: project_root/audit-pack.zip).

    §8: flat ZIP with manifest.json listing all packed files.
    """
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION

    if output_path is None:
        output_path = os.path.join(project_root, "audit-pack.zip")

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Collect files to pack
    candidates = _INPUT_FILES + _GENERATED_FILES
    files_to_pack: list[tuple[str, str]] = []  # (abs_path, arcname)

    for fname in candidates:
        abs_path = os.path.join(project_root, fname)
        if fname == "audit-pack.zip":
            continue  # §8: exclude itself
        if os.path.isfile(abs_path):
            files_to_pack.append((abs_path, fname))

    # Also include gap reports matching <standard>-gap-report.json
    for fname in os.listdir(project_root):
        if fname.endswith("-gap-report.json"):
            abs_path = os.path.join(project_root, fname)
            if (abs_path, fname) not in files_to_pack:
                files_to_pack.append((abs_path, fname))

    # Build manifest entries
    manifest_files = []
    for abs_path, arcname in files_to_pack:
        sha = _sha256_file(abs_path)
        size = os.path.getsize(abs_path)
        manifest_files.append({"path": arcname, "size": size, "sha256": sha})

    manifest = {
        "schemaVersion": SPEC_VERSION,
        "kind": "audit-manifest",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "files": sorted(manifest_files, key=lambda x: x["path"]),
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        for abs_path, arcname in files_to_pack:
            zf.write(abs_path, arcname)

    return output_path
