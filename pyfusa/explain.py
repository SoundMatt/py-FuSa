"""`pyfusa explain <RULE-ID>` — onboarding aid.

Not part of the x-FuSa spec; a workflow-parity feature matching c-FuSa's
`cfusa explain` (issue #212 there).

Prints a rule's id, family, standard/clause citation, and description in one
place, so someone new to the tool doesn't have to go read the rule's source
to understand a finding. Deliberately does NOT introduce a second,
separately-authored remediation-guidance table: py-FuSa's `remediation`
strings are computed per-finding (they name the actual function/file
involved), not a static per-rule template, so there is nothing generic to
show here beyond the rule's own `description` — a static guidance table
would be exactly the kind of hand-authored, drift-prone duplicate this
project has already been bitten by once (see the README/ANA-series
mismatch fixed alongside this audit). `pyfusa fix` is where per-finding
remediation actually lives, once a rule has produced a finding to explain.
"""

from __future__ import annotations

import re

from pyfusa.rules import Rule


# fusa:req REQ-EXPLAIN002
def _family(rule_id: str) -> str:
    """Alphabetic prefix of a rule id (e.g. "LINT001" -> "LINT")."""
    m = re.match(r"^([A-Za-z]+)", rule_id)
    return m.group(1).upper() if m else rule_id.upper()


def _normalize(rule_id: str) -> str:
    """Case- and separator-insensitive form, for loose matching."""
    return re.sub(r"[-_]", "", rule_id).upper()


# fusa:req REQ-EXPLAIN002
def find_rule(rules: list[Rule], want: str) -> Rule | None:
    """Exact match first (so a loose match on a different rule's id never
    shadows the real one), then a case-/separator-insensitive match — a
    human typing `pyfusa explain lint-001` shouldn't have to get the exact
    casing right."""
    for rule in rules:
        if rule.rule_id == want:
            return rule
    normalized = _normalize(want)
    for rule in rules:
        if _normalize(rule.rule_id) == normalized:
            return rule
    return None


# fusa:req REQ-EXPLAIN001 REQ-EXPLAIN003
def render_text(rule: Rule) -> str:
    standard = getattr(type(rule), "standard", "")
    clause = getattr(type(rule), "clause", "")

    lines = [f"{rule.rule_id} — {_family(rule.rule_id)}"]
    if standard:
        lines.append(f"Standard: {standard} {clause}".rstrip() if clause else f"Standard: {standard}")
    if rule.description:
        lines.append("")
        lines.append(rule.description)
    lines.append("")
    lines.append(
        "Remediation is finding-specific — run the rule against real code "
        "(e.g. via 'pyfusa check' or 'pyfusa fix') to see guidance for a "
        "particular occurrence."
    )
    return "\n".join(lines)


# fusa:req REQ-EXPLAIN002
def render_list_text(rules: list[Rule]) -> str:
    groups: dict[str, list[Rule]] = {}
    for rule in rules:
        groups.setdefault(_family(rule.rule_id), []).append(rule)

    lines = []
    for family in sorted(groups):
        lines.append(f"\n{family}:")
        for rule in sorted(groups[family], key=lambda r: r.rule_id):
            desc = rule.description or ""
            if len(desc) > 72:
                desc = desc[:69] + "..."
            lines.append(f"  {rule.rule_id:14s} {desc}")
    return "\n".join(lines).lstrip("\n")
