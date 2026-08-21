"""Shared content-aware evidence check for compliance gap-report generators.

`os.path.exists()` alone treats a zero-byte or garbage-content file
identically to real evidence — verified directly: an empty `provenance.json`
and one full of `"this is not json at all, just garbage bytes"` both
"satisfied" every objective that used a bare existence check, and every
DO-178C Annex A evidence file created as literally zero bytes satisfied 21
of 22 objectives.

`pyfusa/compliance/slsa.py`'s `_provenance_has_builder()` already proves the
fix for one objective — parse the file and check it actually has content,
not just the right name. This generalizes that pattern to every evidence
file across `iso26262`/`do178`/`iec61508`/`iec62443`/`iso21434`/`unece`,
without trying to be a full per-objective semantic validator (that would
risk false negatives on legitimately-thin-but-real reports, e.g. a coupling
analysis that genuinely found nothing). The bar stays deliberately low:
parseable, non-empty content. A well-formed empty report from any of
py-FuSa's own generators always carries populated top-level keys
(`schemaVersion`, `kind`, `tool`, ...) even when its findings/entries arrays
are empty, so this check only fails a file that's missing, truncated,
unparseable, or a bare `{}`/`[]` placeholder — exactly the failure modes
proven above, not a real analysis result.
"""

from __future__ import annotations

import json
import os
import zipfile


# fusa:req REQ-COMPLY002
def evidence_present(project_root: str, filename: str) -> bool:
    """True only if `filename` exists AND carries real, parseable content.

    - `.json`: must parse, and the top-level value must be non-empty
      (a populated dict/list, or a non-null scalar).
    - `.zip`: must be a structurally valid ZIP archive.
    - anything else (`.md`, CI config, etc.): must be non-empty — content
      validation beyond that isn't meaningful for free-form text/config.
    """
    path = os.path.join(project_root, filename)
    if not os.path.exists(path):
        return False
    if filename.endswith(".json"):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(data, (dict, list)):
            return bool(data)
        return data is not None
    if filename.endswith(".zip"):
        return zipfile.is_zipfile(path)
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False


# fusa:req REQ-COMPLY003
def rank_status(
    proj_rank: int, req_rank: int, project_root: str, evidence_file: str
) -> tuple:
    """Shared status logic for a level-gated compliance objective:
    "partial" when the project's own level doesn't reach the objective's
    minimum, else "satisfied"/"gap" based on evidence_present() above.

    Used by iso26262/iec61508/iec62443/iso21434 -- these four previously
    carried near-identical rank-comparison logic (three near-identical
    module-local `_status()` functions plus two more copies inlined
    directly in their `run()` loops) that could silently drift out of
    sync with each other, the same duplication class evidence_present()
    itself was extracted to close for the content-check half of this
    logic.

    do178.py is deliberately NOT one of these four: its DAL applicability
    is a per-objective list of applicable DALs (`dal not in dals_apply`),
    not a single minimum-rank threshold, so it has a genuinely different
    shape and keeps its own `_status()`. unece.py has no level dimension
    at all.
    """
    if proj_rank < req_rank:
        return "partial", []
    if evidence_present(project_root, evidence_file):
        return "satisfied", [evidence_file]
    return "gap", []
