"""Package pyfusa — functional safety enablement toolkit for Python projects.

Core types, sentinel errors, and constants shared across all sub-modules.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass

VERSION = "0.2.5"
SPEC_VERSION = "1.10.12"
LANGUAGE = "python"
TOOL = "py-FuSa"
BINARY = "pyfusa"
IMAGE = "ghcr.io/soundmatt/py-fusa"

# Exit codes §2.3
EXIT_OK = 0
EXIT_GATE_FAIL = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

# Severity enum §2.4
SEVERITY_INFO = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_ERROR = "ERROR"

_VALID_SEVERITIES = {SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_ERROR}

# Category enum §4
CATEGORY_LINT = "lint"
CATEGORY_STYLE = "style"
CATEGORY_SAFETY = "safety"
CATEGORY_SECURITY = "security"
CATEGORY_COVERAGE = "coverage"
CATEGORY_REQUIREMENT = "requirement"
CATEGORY_CONCURRENCY = "concurrency"
CATEGORY_SUPPLY_CHAIN = "supply-chain"
CATEGORY_CONFIG = "config"
CATEGORY_OTHER = "other"

# Disposition enum §4.1
DISPOSITION_OPEN = "open"
DISPOSITION_ACCEPTED = "accepted"
DISPOSITION_DEFERRED = "deferred"
DISPOSITION_REJECTED = "rejected"

# §1.5.1 prefix → category registry
_PREFIX_CATEGORY: dict[str, str] = {
    "LINT": CATEGORY_LINT,
    "STYLE": CATEGORY_STYLE,
    "FUSA": CATEGORY_SAFETY,
    "SEC": CATEGORY_SECURITY,
    "CWE": CATEGORY_SECURITY,
    "CYBER": CATEGORY_SECURITY,
    "COV": CATEGORY_COVERAGE,
    "REQ": CATEGORY_REQUIREMENT,
    "TRACE": CATEGORY_REQUIREMENT,
    "CONC": CATEGORY_CONCURRENCY,
    "RACE": CATEGORY_CONCURRENCY,
    "SBOM": CATEGORY_SUPPLY_CHAIN,
    "SLSA": CATEGORY_SUPPLY_CHAIN,
    "VULN": CATEGORY_SUPPLY_CHAIN,
    "RELEASE": CATEGORY_SUPPLY_CHAIN,
    "CFG": CATEGORY_CONFIG,
    "ISO": CATEGORY_SAFETY,
    "IEC": CATEGORY_SAFETY,
    "DO": CATEGORY_SAFETY,
    "MISRA": CATEGORY_SAFETY,
    "AUTOSAR": CATEGORY_SAFETY,
    "CERT": CATEGORY_SAFETY,
    "UNECE": CATEGORY_SAFETY,
    "ANA": CATEGORY_SAFETY,
    "HARA": CATEGORY_SAFETY,
    "TARA": CATEGORY_SAFETY,
}

_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9.]+)*$")


def derive_category(rule_id: str) -> str:
    """Return category for a rule id using the §1.5.1 prefix registry."""
    upper = rule_id.upper()
    # extract alphabetic prefix up to first digit or hyphen
    m = re.match(r"^([A-Z]+)", upper)
    prefix = m.group(1) if m else ""
    return _PREFIX_CATEGORY.get(prefix, CATEGORY_OTHER)


def normalize_message(msg: str) -> str:
    """§4.2 message normalization: replace digit runs with '#', collapse whitespace."""
    # NFC for non-ASCII
    if any(ord(c) > 127 for c in msg):
        msg = unicodedata.normalize("NFC", msg)
    result = []
    in_digits = False
    in_space = False
    for ch in msg:
        if ch.isdigit():
            if not in_digits:
                if in_space and result:
                    result.append(" ")
                result.append("#")
                in_digits = True
            in_space = False
        elif ch in " \t\n\r":
            in_digits = False
            in_space = True
        else:
            if in_space and result:
                result.append(" ")
            result.append(ch)
            in_digits = False
            in_space = False
    return "".join(result).strip()


def compute_fingerprint(rule_id: str, file: str, message: str) -> str:
    """Compute §4.2 canonical SHA-256 fingerprint."""
    normalized = normalize_message(message)
    canonical = rule_id + "\x1f" + file + "\x1f" + normalized
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return "sha256:" + digest


@dataclass
class Location:
    """§4 Finding location."""

    file: str
    line: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0

    def to_dict(self) -> dict:
        d: dict = {"file": self.file}
        if self.line:
            d["line"] = self.line
        if self.column:
            d["column"] = self.column
        if self.end_line:
            d["endLine"] = self.end_line
        if self.end_column:
            d["endColumn"] = self.end_column
        return d


def ast_loc(file: str, node: object) -> Location:
    """Create a Location from a file path and an ast.AST node (§4 endLine/endColumn MAY)."""
    return Location(
        file=file,
        line=getattr(node, "lineno", 0),
        end_line=getattr(node, "end_lineno", 0),
        end_column=getattr(node, "end_col_offset", -1) + 1,
    )


@dataclass
class Finding:
    """§4 canonical finding atom."""

    rule_id: str
    severity: str
    message: str
    location: Location
    category: str = ""
    standard: str = ""
    clause: str = ""
    remediation: str = ""
    disposition: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.category:
            self.category = derive_category(self.rule_id)
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.rule_id, self.location.file, self.message
            )

    def to_dict(self) -> dict:
        d: dict = {
            "ruleId": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "location": self.location.to_dict(),
            "category": self.category,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
        }
        if self.standard:
            d["standard"] = self.standard
        if self.clause:
            d["clause"] = self.clause
        if self.disposition:
            d["disposition"] = self.disposition
        return d
