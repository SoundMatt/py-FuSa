"""TARA — Threat Analysis and Risk Assessment, x-FuSa spec §9.2 `tara`.

Per ISO/SAE 21434:2021 Clause 15: one `threats[]` entry per CYBER/SEC finding,
each rated on the four SFOP impact axes (safety/financial/operational/
privacy — ISO 21434 Clause 15.7) rather than one generic severity, since a
single threat can rate very differently across those axes.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config
from pyfusa import content_quality

TARA_FILE = "tara.json"

# Internal coarse severity scale used only to rank each `_RULE_META["impact"]`
# label (itself "Low"/"Medium"/"High"/"Critical") before it is projected onto
# the two *distinct*, spec-mandated output vocabularies below. This scale is
# never emitted verbatim.
_SCALE = ["low", "medium", "high", "critical"]
_RANK = {v: i for i, v in enumerate(_SCALE)}

# x-FuSa spec §9.2 tara closed enum for impact.{safety,financial,operational,
# privacy}: critical|major|moderate|negligible — NOT the high/medium/low
# vocabulary used for attackFeasibility. Index-aligned with `_SCALE` above so
# an `_RANK` value can be projected straight across (rank 0 -> "negligible",
# rank 3 -> "critical").
_IMPACT_ENUM = ["negligible", "moderate", "major", "critical"]
_IMPACT_RANK = {v: i for i, v in enumerate(_IMPACT_ENUM)}

# STRIDE metadata per CYBER rule. `impact` here is this project's own coarse
# overall-severity label (Low/Medium/High/Critical) from which the four SFOP
# axes below are *derived*, not copied verbatim — see _sfop_impact().
_RULE_META = {
    "CYBER001": {
        "threat": "Weak hash allows hash collision / pre-image attack",
        "stride": ["T", "I"],
        "cwe": "CWE-327",
        "attack_vector": "Local",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "code review",
    },
    "CYBER002": {
        "threat": "Weak cipher allows ciphertext decryption by attacker",
        "stride": ["I", "D"],
        "cwe": "CWE-327",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "code review",
    },
    "CYBER003": {
        "threat": "Predictable tokens allow session hijacking",
        "stride": ["S"],
        "cwe": "CWE-330",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "none",
    },
    "CYBER004": {
        "threat": "Memory corruption via unsafe pointer",
        "stride": ["E"],
        "cwe": "CWE-242",
        "attack_vector": "Local",
        "likelihood": "low",
        "impact": "Critical",
        "current_control": "code review",
    },
    "CYBER005": {
        "threat": "Command injection allows arbitrary OS command execution",
        "stride": ["E"],
        "cwe": "CWE-78",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "Critical",
        "current_control": "none",
    },
    "CYBER006": {
        "threat": "Hardcoded credentials exposed in source repository",
        "stride": ["S"],
        "cwe": "CWE-798",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "Critical",
        "current_control": "none",
    },
    "CYBER007": {
        "threat": "MITM attack via disabled TLS certificate verification",
        "stride": ["S", "T", "I"],
        "cwe": "CWE-295",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "High",
        "current_control": "none",
    },
    "CYBER008": {
        "threat": "Denial of service via connection starvation",
        "stride": ["D"],
        "cwe": "CWE-400",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "network firewall",
    },
    "CYBER009": {
        "threat": "Integer overflow leads to wrong size allocation",
        "stride": ["E"],
        "cwe": "CWE-190",
        "attack_vector": "Network",
        "likelihood": "low",
        "impact": "High",
        "current_control": "bounds check",
    },
    "CYBER010": {
        "threat": "SQL injection or path traversal via string concatenation",
        "stride": ["I", "E"],
        "cwe": "CWE-89",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "Critical",
        "current_control": "none",
    },
    "CYBER011": {
        "threat": "SSRF — attacker controls outbound requests",
        "stride": ["I"],
        "cwe": "CWE-918",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "URL allowlist",
    },
    "CYBER012": {
        "threat": "Debug endpoint exposes internals to attacker",
        "stride": ["I"],
        "cwe": "CWE-215",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "none",
    },
    "CYBER013": {
        "threat": "Zip slip: archive extraction writes outside target directory",
        "stride": ["E"],
        "cwe": "CWE-23",
        "attack_vector": "Network",
        "likelihood": "medium",
        "impact": "High",
        "current_control": "none",
    },
    "CYBER014": {
        "threat": "Weak TLS version allows protocol downgrade attack",
        "stride": ["T", "I"],
        "cwe": "CWE-326",
        "attack_vector": "Network",
        "likelihood": "low",
        "impact": "High",
        "current_control": "TLS config review",
    },
    "CYBER015": {
        "threat": "SQL injection via format string in query",
        "stride": ["I", "E"],
        "cwe": "CWE-89",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "Critical",
        "current_control": "none",
    },
    "CYBER016": {
        "threat": "World-writable directory allows attacker to plant malicious files",
        "stride": ["T"],
        "cwe": "CWE-732",
        "attack_vector": "Local",
        "likelihood": "low",
        "impact": "Medium",
        "current_control": "filesystem permissions",
    },
    "CYBER017": {
        "threat": "Permissive file mode allows data exfiltration by local attacker",
        "stride": ["I"],
        "cwe": "CWE-732",
        "attack_vector": "Local",
        "likelihood": "low",
        "impact": "Medium",
        "current_control": "filesystem permissions",
    },
    "CYBER018": {
        "threat": "Path traversal: user-controlled path allows reading arbitrary files",
        "stride": ["I"],
        "cwe": "CWE-22",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "High",
        "current_control": "none",
    },
    "CYBER019": {
        "threat": "TOCTOU: attacker replaces file between check and use",
        "stride": ["E"],
        "cwe": "CWE-362",
        "attack_vector": "Local",
        "likelihood": "low",
        "impact": "Medium",
        "current_control": "none",
    },
    "CYBER020": {
        "threat": "Insecure temp file allows attacker to pre-create file at predicted path",
        "stride": ["E"],
        "cwe": "CWE-377",
        "attack_vector": "Local",
        "likelihood": "low",
        "impact": "Medium",
        "current_control": "none",
    },
    "SEC001": {
        "threat": "Bare except catches and silences security exceptions",
        "stride": ["R"],
        "cwe": "CWE-703",
        "attack_vector": "Local",
        "likelihood": "medium",
        "impact": "Medium",
        "current_control": "code review",
    },
    "SEC002": {
        "threat": "eval() allows arbitrary code execution",
        "stride": ["E"],
        "cwe": "CWE-95",
        "attack_vector": "Network",
        "likelihood": "high",
        "impact": "Critical",
        "current_control": "none",
    },
}


def _impact_at(rank: int) -> str:
    """Project an internal 0-3 severity rank onto the spec's closed
    `impact.{safety,financial,operational,privacy}` enum (critical | major |
    moderate | negligible) — never onto `_SCALE`, which is a different scale
    (attackFeasibility's) and must not be substituted here."""
    return _IMPACT_ENUM[max(0, min(len(_IMPACT_ENUM) - 1, rank))]


# fusa:req REQ-TARA006
def _sfop_impact(meta: dict) -> dict:
    """Derive the four ISO 21434 Clause 15.7 SFOP axes from this project's
    own coarse (impact, stride) rating. This is a documented heuristic, not a
    formal per-asset ISO 21434 damage-scenario analysis: STRIDE category
    shifts which axis dominates (Elevation-of-privilege/Tampering skew
    safety+operational; Information-disclosure skews privacy; Denial-of-
    service skews operational), so the four axes genuinely differ per threat
    rather than repeating one value (§1.6.1 rule B)."""
    overall = _RANK.get(meta["impact"].lower(), 1)
    stride = set(meta["stride"])

    safety = overall if stride & {"E", "T"} else max(0, overall - 1)
    operational = overall if stride & {"D", "E"} else max(0, overall - 1)
    privacy = overall if "I" in stride else max(0, overall - 2)
    financial = max(0, overall - 1) if stride & {"R"} else overall

    return {
        "safety": _impact_at(safety),
        "financial": _impact_at(financial),
        "operational": _impact_at(operational),
        "privacy": _impact_at(privacy),
    }


def _compute_risk(impact: dict, feasibility: str) -> str:
    """x-FuSa spec §9.2 tara risk combination table: the highest-ranked of
    the four SFOP axes against `attackFeasibility`. Every `worst` row is
    covered (including "critical", the family's own ceiling above ISO
    21434's own Severe/Major/Moderate/Negligible scale) so no combination
    silently falls through to a default "low" — a feasibility outside
    high|medium|low (e.g. "very-low", or an unrecognised value) is treated
    fail-safe, at the table's own "very-low" column rather than its "low"
    column."""
    worst = max(impact.values(), key=lambda v: _IMPACT_RANK.get(v, 0))
    if worst == "critical":
        if feasibility in ("high", "medium"):
            return "critical"
        if feasibility == "low":
            return "high"
        return "medium"
    if worst == "major":
        if feasibility in ("high", "medium"):
            return "high"
        return "medium"
    if worst == "moderate":
        if feasibility in ("high", "medium"):
            return "medium"
        return "low"
    return "low"


def _treatment(risk: str, current_control: str) -> str:
    if risk in ("critical", "high"):
        return "mitigate"
    if current_control and current_control != "none":
        return "accept"
    return "mitigate"


# fusa:req REQ-CLI009
def build(findings: List[dict], project_root: str, cfg: Config) -> List[dict]:
    """Generate TARA threat scenarios from a list of cyber/security finding dicts."""
    entries: List[dict] = []
    counter = 0
    for f in findings:
        rule_id = f.get("ruleId", "")
        meta = _RULE_META.get(rule_id)
        if not meta:
            continue
        counter += 1
        impact = _sfop_impact(meta)
        risk = _compute_risk(impact, meta["likelihood"])
        entry = {
            "id": f"TARA-{counter:03d}",
            "asset": f.get("message", "") or f.get("location", {}).get("file", ""),
            "threat": meta["threat"],
            "cwe": meta["cwe"],
            "attackVector": meta["attack_vector"],
            "attackFeasibility": meta["likelihood"],
            "impact": impact,
            "risk": risk,
            "treatment": _treatment(risk, meta["current_control"]),
            "mitigations": (
                [meta["current_control"]]
                if meta["current_control"] and meta["current_control"] != "none"
                else ["identify and implement a specific control for this threat"]
            ),
            "cyberRuleId": rule_id,
        }
        loc_file = f.get("location", {}).get("file", "")
        if loc_file:
            entry["location"] = {
                "file": loc_file,
                "line": f.get("location", {}).get("line", 0),
            }
        entries.append(entry)
    return entries


# fusa:req REQ-TARA006
def _coverage(project_root: str, cfg: Config, entries: List[dict]) -> dict:
    from pyfusa.fmea import _python_files

    all_files = _python_files(project_root, cfg)
    assets_in_project = len(all_files)
    analyzed_files = {
        e["location"]["file"] for e in entries if e.get("location", {}).get("file")
    }
    assets_analyzed = len(analyzed_files)
    pct = (
        round(100.0 * assets_analyzed / assets_in_project, 1)
        if assets_in_project
        else 100.0
    )
    # x-FuSa spec §9.2 tara MUST: coveragePct must never exceed 100 — a
    # defensive backstop alongside `_python_files`' test-tree exclusion
    # (shared with fmea, which is what stops this in the normal case).
    pct = min(pct, 100.0)
    return {
        "assetsAnalyzed": assets_analyzed,
        "assetsInProject": assets_in_project,
        "coveragePct": pct,
        "assetInventoryMethod": (
            "one candidate asset per project .py source file under sourceDirs; "
            "an asset counts as analyzed once at least one cyber/security "
            "finding (and therefore threat scenario) was derived from it. "
            "This is a coarse file-level proxy, not a formal ISO 21434 asset "
            "catalogue — documented here rather than presented as complete."
        ),
    }


# fusa:req REQ-CLI009
def to_dict(entries: List[dict], project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    summary = {
        "total": len(entries),
        "critical": sum(1 for e in entries if e["risk"] == "critical"),
        "high": sum(1 for e in entries if e["risk"] == "high"),
    }
    summary.update(_coverage(project_root, cfg, entries))

    doc = {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "tara-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "projectRoot": os.path.abspath(project_root),
        "project": module,
        "standard": "iso21434",
        "threats": entries,
        "summary": summary,
    }
    existing = content_quality.load_existing_attestation(project_root, TARA_FILE)
    if existing:
        doc["attestation"] = existing
    return doc


# fusa:req REQ-CLI009
def to_markdown(entries: List[dict], module: str) -> str:
    lines = [
        f"# TARA — {module}",
        "",
        "| ID | Threat | CWE | Vector | Feasibility | Risk | Treatment |",
        "|---|---|---|---|---|---|---|",
    ]
    for e in entries:
        lines.append(
            f"| {e['id']} | {e['threat'][:60]} | {e.get('cwe', '')} | "
            f"{e['attackVector']} | {e['attackFeasibility']} | "
            f"{e['risk']} | {e['treatment']} |"
        )
    return "\n".join(lines)


# fusa:req REQ-QUALBASE005
def quality_findings(doc: dict) -> List[pyfusa.Finding]:
    """§1.6/§1.6.1 content-quality baseline over this document's own qualitative
    fields, run against the just-generated doc."""
    entries = doc.get("threats", [])
    findings = content_quality.scan_placeholder(
        entries, ["threat", "asset"], TARA_FILE
    )
    findings.extend(
        content_quality.scan_blanket_fallback(entries, ["threat"], TARA_FILE)
    )
    return findings
