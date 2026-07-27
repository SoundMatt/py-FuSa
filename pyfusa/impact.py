"""Change impact analysis — maps git changes to requirements and stale artefacts."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import REQS_FILE, Config


def _git_changed_files(
    project_root: str, from_ref: str = "HEAD", to_ref: str = ""
) -> List[dict]:
    try:
        if to_ref:
            cmd = ["git", "diff", "--name-status", from_ref, to_ref]
        else:
            cmd = ["git", "diff", "--name-status", from_ref]
        out = subprocess.check_output(
            cmd, cwd=project_root, stderr=subprocess.DEVNULL, text=True
        )
        files = []
        for line in out.strip().splitlines():
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) == 2:
                files.append({"status": parts[0], "path": parts[1]})
        return files
    except (subprocess.CalledProcessError, OSError):
        return []


def _load_reqs(project_root: str) -> List[dict]:
    path = os.path.join(project_root, REQS_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("requirements", [])


def _load_trace_matrix(project_root: str) -> dict:
    """Return {req_id: [impl_files], ...} from trace-matrix or check-report."""
    trace_path = os.path.join(project_root, "trace-matrix.json")
    if not os.path.exists(trace_path):
        return {}
    with open(trace_path, encoding="utf-8") as f:
        doc = json.load(f)
    result: dict = {}
    for req in doc.get("requirements", []):
        req_id = req.get("id", "")
        tags = req.get("tags", [])
        files = list({t.get("file", "") for t in tags})
        result[req_id] = files
    return result


def _check_stale(project_root: str, changed_files: List[dict]) -> List[dict]:
    stale: List[dict] = []
    ARTIFACTS = [
        "check-report.json",
        "qualify-report.json",
        "sbom.json",
        "provenance.json",
        "coupling-report.json",
        "fmea.json",
        "tara.json",
        "coverage-report.json",
    ]
    for artifact in ARTIFACTS:
        art_path = os.path.join(project_root, artifact)
        if not os.path.exists(art_path):
            continue
        art_mtime = os.path.getmtime(art_path)
        for cf in changed_files:
            src_path = os.path.join(project_root, cf["path"])
            if os.path.exists(src_path):
                if os.path.getmtime(src_path) > art_mtime:
                    stale.append(
                        {
                            "file": artifact,
                            "stale": True,
                            "reason": f"older than modified source {cf['path']}",
                        }
                    )
                    break
    return stale


def run(
    project_root: str, cfg: Config, from_ref: str = "HEAD", to_ref: str = ""
) -> dict:
    changed = _git_changed_files(project_root, from_ref, to_ref)
    changed_paths = {f["path"] for f in changed}
    trace = _load_trace_matrix(project_root)

    impacted_reqs: List[dict] = []
    rerun_tests: List[str] = []
    for req_id, impl_files in trace.items():
        affected = [f for f in impl_files if f in changed_paths]
        if affected:
            tests = [f for f in impl_files if "test" in f.lower()]
            impacted_reqs.append(
                {
                    "requirementID": req_id,
                    "affectedFiles": affected,
                    "testsNeeded": tests,
                    "stale": bool(tests),
                }
            )
            rerun_tests.extend(tests)

    stale = _check_stale(project_root, changed)
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "impact-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "changedFiles": changed,
        "impactedReqs": impacted_reqs,
        "staleArtifacts": stale,
        "rerunTests": list(set(rerun_tests)),
    }
