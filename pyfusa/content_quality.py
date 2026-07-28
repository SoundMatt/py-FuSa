"""Evidence artifact content-quality baseline — x-FuSa spec §1.6/§1.6.1/§1.6.2.

A 2026-07-28 cross-tool content audit (see spec changelog 1.13.0/1.14.0) found
generated evidence that was schema-shaped but not information-bearing:
templated FMEA rows, an untouched HARA template, a single hardcoded string
applied to every entry regardless of the underlying item. This module is the
shared, checkable implementation of that baseline for every artifact that
carries free-text qualitative content — `fmea`, `.fusa-hara.json`/`hara`,
`tara`, `safety-case`, `sas`.

Two detection heuristics (§1.6.1):

  Rule A / FUSA-STUB001 (MUST, always ERROR) — a deny-list scan for literal
    placeholder/template text. Disposition-suppressible only (§1.2.3/§4.1);
    never attestation-suppressible, because no attestation can make literal
    placeholder text real.

  Rule B / FUSA-STUB002 (SHOULD, WARNING by default) — a distinct-value-ratio
    check (<0.1 across >=10 entries) that flags a single hardcoded
    qualitative string applied to every entry. Advisory by default; a
    non-stale, genuinely-independent attestation (§1.6.2) suppresses it, and
    `--require-attestation`/`--strict` escalates an unsuppressed instance to
    a gate failure.

Plus the §1.6.2 attestation mechanism itself: a document-level `attestation`
object, hash-pinned to the artifact's own content, that a consumer must
treat as stale (falling back to "heuristic") whenever the content it was
reviewed against has since changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Iterable, List, Optional, Tuple

import pyfusa
from pyfusa.config import load_dispositions

# §1.6.1 rule ids
RULE_PLACEHOLDER = "FUSA-STUB001"
RULE_BLANKET_FALLBACK = "FUSA-STUB002"

# §1.6.2 attestation status values
STATUS_HEURISTIC = "heuristic"
STATUS_REVIEWED = "reviewed"

# §1.6.1 rule A — bracket-wrapped instructional text, or a case-insensitive
# substring match against the canonical deny-list.
_BRACKET_RE = re.compile(r"\[[A-Za-z][^\]]*\]")
_DENYLIST = ("replace with", "example hazard", "tbd", "lorem ipsum", "fill in")

# Keys that are envelope/attribution/timestamp, not analysis content — excluded
# from the §1.6.2 contentHash so unrelated regeneration (e.g. a re-run that
# only bumps generatedAt) doesn't spuriously invalidate a real review.
_HASH_EXCLUDED_KEYS = frozenset(
    {"attestation", "generatedAt", "schemaVersion", "kind", "tool", "toolVersion", "language"}
)


# fusa:req REQ-QUALBASE001
def is_placeholder(text: str) -> bool:
    """§1.6.1 rule A match test for one qualitative-field value."""
    if not text:
        return False
    if _BRACKET_RE.search(text):
        return True
    lower = text.lower()
    return any(needle in lower for needle in _DENYLIST)


# fusa:req REQ-QUALBASE001
def scan_placeholder(
    entries: Iterable[dict], fields: List[str], file: str
) -> List[pyfusa.Finding]:
    """§1.6.1 rule A — always ERROR, never attestation-suppressible."""
    findings: List[pyfusa.Finding] = []
    for entry in entries:
        entry_id = entry.get("id") or entry.get("item") or ""
        for field in fields:
            value = entry.get(field)
            if isinstance(value, str) and is_placeholder(value):
                findings.append(
                    pyfusa.Finding(
                        rule_id=RULE_PLACEHOLDER,
                        severity=pyfusa.SEVERITY_ERROR,
                        message=(
                            f"placeholder/template text detected in '{field}' "
                            f"of entry '{entry_id}': {value!r}"
                        ),
                        location=pyfusa.Location(file=file),
                        category=pyfusa.CATEGORY_SAFETY,
                        remediation=(
                            "replace the placeholder text with project-specific "
                            "analysis, or leave the section as an empty array "
                            "until it has actually been analyzed"
                        ),
                    )
                )
    return findings


# fusa:req REQ-QUALBASE002
def distinct_value_ratio(values: List[str]) -> float:
    """Count of distinct non-empty values / total non-empty values.

    An all-empty field is not a "blanket fallback" (there is nothing to be
    a fallback from) so it reports 1.0 — never-flagged — rather than 0.0.
    """
    non_empty = [v for v in values if v]
    if not non_empty:
        return 1.0
    return len(set(non_empty)) / len(non_empty)


# fusa:req REQ-QUALBASE002
def scan_blanket_fallback(
    entries: List[dict], fields: List[str], file: str
) -> List[pyfusa.Finding]:
    """§1.6.1 rule B — WARNING by default, attestation-suppressible.

    Only evaluated for artifacts with >=10 entries (spec's own threshold —
    below that, low variety is not a meaningful signal).
    """
    findings: List[pyfusa.Finding] = []
    if len(entries) < 10:
        return findings
    for field in fields:
        values = [str(e.get(field, "")) for e in entries]
        ratio = distinct_value_ratio(values)
        if ratio < 0.1:
            findings.append(
                pyfusa.Finding(
                    rule_id=RULE_BLANKET_FALLBACK,
                    severity=pyfusa.SEVERITY_WARNING,
                    message=(
                        f"field '{field}' has a distinct-value ratio of "
                        f"{ratio:.3f} across {len(entries)} entries — possible "
                        f"blanket qualitative fallback (a single hardcoded "
                        f"string applied regardless of the underlying item)"
                    ),
                    location=pyfusa.Location(file=file),
                    category=pyfusa.CATEGORY_SAFETY,
                    remediation=(
                        "vary this field's content with the actual "
                        "signature/behaviour of each entry, or add a "
                        "genuinely-independent attestation (§1.6.2) confirming "
                        "the similarity is real"
                    ),
                )
            )
    return findings


# fusa:req REQ-QUALBASE003
def apply_dispositions(findings: List[pyfusa.Finding], project_root: str) -> None:
    """Match findings against .fusa-dispositions.json (§1.2.3/§4.1), mirroring
    engine._apply_dispositions so FUSA-STUB001 is disposition-suppressible
    outside of the `check` command too."""
    dispositions = load_dispositions(
        os.path.join(project_root, ".fusa-dispositions.json")
    )
    for finding in findings:
        for disp in dispositions:
            status = disp.get("status", "")
            if not status:
                continue
            fp = disp.get("fingerprint", "")
            if fp and fp == finding.fingerprint:
                finding.disposition = status
                break
            if disp.get("ruleId") == finding.rule_id and disp.get(
                "file"
            ) == finding.location.file:
                line = disp.get("line")
                if line is None or line == finding.location.line:
                    finding.disposition = status
                    break
            if disp.get("ruleId") == finding.rule_id and not disp.get("file"):
                finding.disposition = status
                break


# fusa:req REQ-ATTEST001
def content_hash(doc: dict) -> str:
    """§1.6.2 contentHash — a canonical hash over the document's substantive
    content, excluding the header/attribution/attestation/generatedAt fields
    that aren't the analysis itself. Uses the same practical RFC 8785 (JCS)
    subset as `qualify.compute_hash`: sorted keys, no insignificant
    whitespace."""
    substantive = {k: v for k, v in doc.items() if k not in _HASH_EXCLUDED_KEYS}
    canonical = json.dumps(
        substantive, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# fusa:req REQ-ATTEST002
def attestation_valid(attestation: Optional[dict], current_hash: str) -> bool:
    """§1.6.2 — fail-safe: an absent/malformed/self-attested/stale attestation
    is never valid; only an explicit, independent, hash-matching "reviewed"
    attestation is."""
    if not attestation or not current_hash:
        return False
    if attestation.get("status") != STATUS_REVIEWED:
        return False
    reviewer = attestation.get("independentReviewer", "")
    author = attestation.get("implementationAuthor", "")
    if not reviewer or reviewer == author:
        return False
    stored_hash = attestation.get("contentHash", "")
    if not stored_hash or stored_hash != current_hash:
        return False
    return True


# fusa:req REQ-ATTEST003
def load_existing_attestation(project_root: str, filename: str) -> Optional[dict]:
    """Load the `attestation` object from a previously-generated evidence
    file, if present, so a human-added review survives regeneration of the
    rest of the document."""
    path = os.path.join(project_root, filename)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    attestation = doc.get("attestation")
    return attestation if isinstance(attestation, dict) else None


# fusa:req REQ-QUALBASE004
def gate(
    findings: List[pyfusa.Finding],
    project_root: str,
    attestation: Optional[dict],
    current_hash: str,
    require_attestation: bool,
) -> Tuple[List[pyfusa.Finding], bool]:
    """Apply dispositions and attestation suppression to a set of
    FUSA-STUB001/002 findings; return (kept_findings, gate_failed).

    - FUSA-STUB001 always participates in the gate unless individually
      disposition-accepted/deferred (never attestation-suppressed).
    - FUSA-STUB002 is dropped entirely when a valid attestation exists; it
      only participates in the gate when `require_attestation` is set (the
      `--strict`/`--require-attestation` escalation) and it is still open.
    """
    apply_dispositions(findings, project_root)
    valid = attestation_valid(attestation, current_hash)
    kept = [
        f for f in findings if not (f.rule_id == RULE_BLANKET_FALLBACK and valid)
    ]

    def _open(f: pyfusa.Finding) -> bool:
        return f.disposition not in (
            pyfusa.DISPOSITION_ACCEPTED,
            pyfusa.DISPOSITION_DEFERRED,
        )

    gate_failed = any(
        f.severity == pyfusa.SEVERITY_ERROR and _open(f) for f in kept
    )
    if require_attestation:
        gate_failed = gate_failed or any(
            f.rule_id == RULE_BLANKET_FALLBACK and _open(f) for f in kept
        )
    return kept, gate_failed
