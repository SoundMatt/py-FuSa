"""TARA — Threat Analysis and Risk Assessment (ISO 21434)."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config

# STRIDE metadata per CYBER rule
_RULE_META = {
    "CYBER001": {
        "threat": "Weak hash allows hash collision / pre-image attack",
        "stride": ["T", "I"],
        "cwe": "CWE-327",
        "attack_vector": "Local",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 2,
        "current_control": "code review",
        "residual_risk": "Medium",
    },
    "CYBER002": {
        "threat": "Weak cipher allows ciphertext decryption by attacker",
        "stride": ["I", "D"],
        "cwe": "CWE-327",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 2,
        "current_control": "code review",
        "residual_risk": "Medium",
    },
    "CYBER003": {
        "threat": "Predictable tokens allow session hijacking",
        "stride": ["S"],
        "cwe": "CWE-330",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 3,
        "current_control": "none",
        "residual_risk": "High",
    },
    "CYBER004": {
        "threat": "Memory corruption via unsafe pointer",
        "stride": ["E"],
        "cwe": "CWE-242",
        "attack_vector": "Local",
        "likelihood": "Low",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "code review",
        "residual_risk": "Low",
    },
    "CYBER005": {
        "threat": "Command injection allows arbitrary OS command execution",
        "stride": ["E"],
        "cwe": "CWE-78",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "none",
        "residual_risk": "Critical",
    },
    "CYBER006": {
        "threat": "Hardcoded credentials exposed in source repository",
        "stride": ["S"],
        "cwe": "CWE-798",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "none",
        "residual_risk": "Critical",
    },
    "CYBER007": {
        "threat": "MITM attack via disabled TLS certificate verification",
        "stride": ["S", "T", "I"],
        "cwe": "CWE-295",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "High",
        "security_level": 3,
        "current_control": "none",
        "residual_risk": "High",
    },
    "CYBER008": {
        "threat": "Denial of service via connection starvation",
        "stride": ["D"],
        "cwe": "CWE-400",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 2,
        "current_control": "network firewall",
        "residual_risk": "Medium",
    },
    "CYBER009": {
        "threat": "Integer overflow leads to wrong size allocation",
        "stride": ["E"],
        "cwe": "CWE-190",
        "attack_vector": "Network",
        "likelihood": "Low",
        "impact": "High",
        "security_level": 2,
        "current_control": "bounds check",
        "residual_risk": "Low",
    },
    "CYBER010": {
        "threat": "SQL injection or path traversal via string concatenation",
        "stride": ["I", "E"],
        "cwe": "CWE-89",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "none",
        "residual_risk": "Critical",
    },
    "CYBER011": {
        "threat": "SSRF — attacker controls outbound requests",
        "stride": ["I"],
        "cwe": "CWE-918",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 3,
        "current_control": "URL allowlist",
        "residual_risk": "Medium",
    },
    "CYBER012": {
        "threat": "Debug endpoint exposes internals to attacker",
        "stride": ["I"],
        "cwe": "CWE-215",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 2,
        "current_control": "none",
        "residual_risk": "High",
    },
    "CYBER013": {
        "threat": "Zip slip: archive extraction writes outside target directory",
        "stride": ["E"],
        "cwe": "CWE-23",
        "attack_vector": "Network",
        "likelihood": "Medium",
        "impact": "High",
        "security_level": 3,
        "current_control": "none",
        "residual_risk": "High",
    },
    "CYBER014": {
        "threat": "Weak TLS version allows protocol downgrade attack",
        "stride": ["T", "I"],
        "cwe": "CWE-326",
        "attack_vector": "Network",
        "likelihood": "Low",
        "impact": "High",
        "security_level": 2,
        "current_control": "TLS config review",
        "residual_risk": "Low",
    },
    "CYBER015": {
        "threat": "SQL injection via format string in query",
        "stride": ["I", "E"],
        "cwe": "CWE-89",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "none",
        "residual_risk": "Critical",
    },
    "CYBER016": {
        "threat": "World-writable directory allows attacker to plant malicious files",
        "stride": ["T"],
        "cwe": "CWE-732",
        "attack_vector": "Local",
        "likelihood": "Low",
        "impact": "Medium",
        "security_level": 2,
        "current_control": "filesystem permissions",
        "residual_risk": "Low",
    },
    "CYBER017": {
        "threat": "Permissive file mode allows data exfiltration by local attacker",
        "stride": ["I"],
        "cwe": "CWE-732",
        "attack_vector": "Local",
        "likelihood": "Low",
        "impact": "Medium",
        "security_level": 2,
        "current_control": "filesystem permissions",
        "residual_risk": "Low",
    },
    "CYBER018": {
        "threat": "Path traversal: user-controlled path allows reading arbitrary files",
        "stride": ["I"],
        "cwe": "CWE-22",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "High",
        "security_level": 3,
        "current_control": "none",
        "residual_risk": "High",
    },
    "CYBER019": {
        "threat": "TOCTOU: attacker replaces file between check and use",
        "stride": ["E"],
        "cwe": "CWE-362",
        "attack_vector": "Local",
        "likelihood": "Low",
        "impact": "Medium",
        "security_level": 2,
        "current_control": "none",
        "residual_risk": "Low",
    },
    "CYBER020": {
        "threat": "Insecure temp file allows attacker to pre-create file at predicted path",
        "stride": ["E"],
        "cwe": "CWE-377",
        "attack_vector": "Local",
        "likelihood": "Low",
        "impact": "Medium",
        "security_level": 2,
        "current_control": "none",
        "residual_risk": "Low",
    },
    # Extend with SEC rules for backward compatibility
    "SEC001": {
        "threat": "Bare except catches and silences security exceptions",
        "stride": ["R"],
        "cwe": "CWE-703",
        "attack_vector": "Local",
        "likelihood": "Medium",
        "impact": "Medium",
        "security_level": 2,
        "current_control": "code review",
        "residual_risk": "Medium",
    },
    "SEC002": {
        "threat": "eval() allows arbitrary code execution",
        "stride": ["E"],
        "cwe": "CWE-95",
        "attack_vector": "Network",
        "likelihood": "High",
        "impact": "Critical",
        "security_level": 4,
        "current_control": "none",
        "residual_risk": "Critical",
    },
}


# fusa:req REQ-CLI009
def build(findings: List[dict], project_root: str, cfg: Config) -> dict:
    """Generate TARA from a list of cyber/security finding dicts."""
    entries = []
    counter = 1
    for f in findings:
        rule_id = f.get("ruleId", "")
        meta = _RULE_META.get(rule_id)
        if not meta:
            continue
        entries.append(
            {
                "id": f"TARA-{counter:03d}",
                "asset": f.get("message", ""),
                "threat": meta["threat"],
                "stride": meta["stride"],
                "cwe": meta["cwe"],
                "standard": "ISO 21434",
                "attack_vector": meta["attack_vector"],
                "likelihood": meta["likelihood"],
                "impact": meta["impact"],
                "security_level": meta["security_level"],
                "current_control": meta["current_control"],
                "residual_risk": meta["residual_risk"],
                "cyber_rule_id": rule_id,
                "source_file": f.get("location", {}).get("file", ""),
                "source_line": f.get("location", {}).get("line", 0),
            }
        )
        counter += 1
    return entries


# fusa:req REQ-CLI009
def to_dict(entries: List[dict], project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "tara",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa TARA v1",
        "module": module,
        "entries": entries,
    }


# fusa:req REQ-CLI009
def to_markdown(entries: List[dict], module: str) -> str:
    lines = [
        f"# TARA — {module}",
        "",
        "| ID | Threat | STRIDE | CWE | Vector | Likelihood | Impact | SL | Residual |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for e in entries:
        lines.append(
            f"| {e['id']} | {e['threat'][:60]} | {''.join(e['stride'])} | {e['cwe']} | "
            f"{e['attack_vector']} | {e['likelihood']} | {e['impact']} | "
            f"{e['security_level']} | {e['residual_risk']} |"
        )
    return "\n".join(lines)
