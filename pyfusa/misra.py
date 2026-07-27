"""MISRA Python mapping table (py-FuSa rule → closest MISRA C:2023 analogue)."""

from __future__ import annotations

from typing import List

_MAPPING = [
    # (pyfusa_rule, misra_rule, description, status)
    ("LINT001", "Rule 15.1", "Function length constraint", "partial"),
    ("LINT002", "Rule 4.1", "File length / module size", "partial"),
    ("LINT003", "Rule 15.5", "Nesting depth constraint", "partial"),
    ("LINT004", "Rule 15.2", "Cyclomatic complexity", "partial"),
    ("LINT005", "Rule 9.1", "Mutable default arguments", "analogous"),
    ("LINT006", "Rule 8.14", "Wildcard imports / uncontrolled scope", "analogous"),
    ("LINT007", "Rule 21.7", "Assert statements", "analogous"),
    ("SEC001", "Rule 15.3", "Bare except = catch-all exception handler", "analogous"),
    ("SEC002", "Rule 17.1", "Dynamic code execution (eval)", "analogous"),
    ("SEC003", "Rule 17.1", "Dynamic code execution (exec)", "analogous"),
    ("SEC004", "Rule 21.8", "Unsafe deserialization (pickle)", "analogous"),
    ("SEC005", "Rule 21.8", "System command execution (os.system)", "analogous"),
    ("SEC006", "Rule 21.8", "Shell injection (subprocess shell=True)", "analogous"),
    ("SEC007", "Rule 5.9", "Hardcoded secrets", "analogous"),
    ("SEC008", "Rule 21.8", "Insecure temp file (mktemp)", "analogous"),
    ("CYBER001", "Rule 21.8", "Weak hash algorithm (MD5/SHA-1)", "analogous"),
    ("CYBER002", "Rule 21.8", "Weak cipher (DES/RC4)", "analogous"),
    ("CYBER005", "Rule 21.8", "Command injection", "analogous"),
    ("CYBER006", "Rule 5.9", "Hardcoded credentials", "analogous"),
    ("CYBER007", "Rule 21.8", "TLS verification disabled", "analogous"),
    ("CYBER010", "Rule 21.8", "SQL/path injection via concatenation", "analogous"),
    ("CYBER013", "Rule 21.8", "Zip slip path traversal", "analogous"),
    ("CYBER015", "Rule 21.8", "SQL injection via f-string", "analogous"),
    ("ANA001", "Rule 14.2", "Thread without termination signal", "analogous"),
    ("ANA002", "Rule 14.2", "Thread in loop (unbounded concurrency)", "analogous"),
    ("ANA006", "Rule 17.7", "Unchecked return value", "analogous"),
    ("ANA009", "Rule 14.3", "Dead code after return/raise", "analogous"),
    ("CONC001", "Rule 14.2", "Thread without lock", "analogous"),
    ("CONC002", "Rule 8.7", "Global mutation in concurrent context", "analogous"),
    ("COUP001", "Rule 8.7", "Module-level mutable state", "analogous"),
    ("COUP002", "Rule 17.1", "Control coupling via callable parameter", "analogous"),
]


# fusa:req REQ-CLI009
def render_text() -> str:
    lines = [
        "py-FuSa → MISRA C:2023 mapping",
        "",
        f"{'py-FuSa Rule':14s} {'MISRA Rule':12s} {'Status':10s} Description",
        "-" * 80,
    ]
    for pyfusa_rule, misra_rule, description, status in _MAPPING:
        lines.append(f"{pyfusa_rule:14s} {misra_rule:12s} {status:10s} {description}")
    return "\n".join(lines)


# fusa:req REQ-CLI009
def to_dict() -> List[dict]:
    return [
        {"pyfusaRule": r, "misraRule": m, "description": d, "status": s}
        for r, m, d, s in _MAPPING
    ]
