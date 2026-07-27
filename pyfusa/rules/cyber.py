"""CYBER001-020: Cybersecurity rules (Python AST + regex)."""

from __future__ import annotations

import ast
import os
import re
from typing import List

from pyfusa import SEVERITY_ERROR, SEVERITY_WARNING, Finding, Location
from pyfusa.config import Config
from pyfusa.rules import Rule


def _python_files(root: str, cfg: Config) -> List[str]:
    source_dirs = cfg.source_dirs or ["."]
    paths: List[str] = []
    skip = {
        "__pycache__",
        ".git",
        ".tox",
        "venv",
        ".venv",
        "node_modules",
        "dist",
        "build",
    }
    for sdir in source_dirs:
        base = os.path.join(root, sdir)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [
                d for d in dirnames if d not in skip and not d.startswith(".")
            ]
            for fn in filenames:
                if fn.endswith(".py"):
                    paths.append(os.path.join(dirpath, fn))
    return paths


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _parse(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        return ast.parse(src, filename=path), src.splitlines()
    except SyntaxError:
        return None, []


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        if isinstance(node.func.value, ast.Attribute):
            if isinstance(node.func.value.value, ast.Name):
                return f"{node.func.value.value.id}.{node.func.value.attr}.{node.func.attr}"
    return ""


def _import_names(tree) -> set:
    """Collect all imported module names (flat and dotted)."""
    names: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# CYBER001 — Weak cryptographic hash (MD5 / SHA-1)
# ---------------------------------------------------------------------------
class CYBER001(Rule):
    rule_id = "CYBER001"
    description = "Weak cryptographic hash function (MD5/SHA-1) — CWE-327"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in ("hashlib.md5", "hashlib.sha1", "hashlib.new"):
                        if name == "hashlib.new" and node.args:
                            if isinstance(node.args[0], ast.Constant):
                                alg = str(node.args[0].value).lower()
                                if alg not in ("md5", "sha1"):
                                    continue
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_ERROR,
                                message=f"weak hash algorithm '{name}' is cryptographically broken",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="iso26262",
                                clause="CWE-327",
                                remediation="use hashlib.sha256() or hashlib.sha3_256() instead",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# CYBER002 — Weak symmetric cipher (DES / RC4 / Blowfish)
# ---------------------------------------------------------------------------
class CYBER002(Rule):
    rule_id = "CYBER002"
    description = "Weak symmetric cipher (DES/RC4) — CWE-327"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        WEAK = {
            "Crypto.Cipher.DES",
            "Crypto.Cipher.ARC4",
            "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",
            "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
        }
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            imports = _import_names(tree)
            for weak in WEAK:
                if any(weak in imp or imp in weak for imp in imports):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=SEVERITY_ERROR,
                            message=f"weak cipher imported: {weak}",
                            location=Location(file=rel, line=1),
                            standard="iso26262",
                            clause="CWE-327",
                            remediation="use AES-256-GCM (cryptography.hazmat.primitives.ciphers.algorithms.AES)",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER003 — Insecure random source for security operations
# ---------------------------------------------------------------------------
class CYBER003(Rule):
    rule_id = "CYBER003"
    description = "Insecure random source (random module) for security — CWE-330"

    _SECURITY_CONTEXTS = re.compile(
        r"(token|secret|key|password|nonce|salt|csrf|auth|session)",
        re.IGNORECASE,
    )

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        RANDOM_CALLS = {
            "random.random",
            "random.randint",
            "random.choice",
            "random.choices",
            "random.shuffle",
            "random.sample",
            "random.uniform",
            "random.getrandbits",
        }
        for path in _python_files(project_root, cfg):
            tree, lines = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in RANDOM_CALLS:
                        lineno = getattr(node, "lineno", 1)
                        context_line = lines[lineno - 1] if lineno <= len(lines) else ""
                        if self._SECURITY_CONTEXTS.search(context_line):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_ERROR,
                                    message=f"'{name}' in security context — not cryptographically secure",
                                    location=Location(file=rel, line=lineno),
                                    standard="iso26262",
                                    clause="CWE-330",
                                    remediation="use secrets.token_bytes() or secrets.token_hex() for security-sensitive randomness",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER004 — Unsafe memory / ctypes usage
# ---------------------------------------------------------------------------
class CYBER004(Rule):
    rule_id = "CYBER004"
    description = "Unsafe memory access via ctypes/cffi — CWE-242"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        UNSAFE = {"ctypes", "cffi", "_ctypes"}
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            imports = _import_names(tree)
            for imp in imports:
                if any(u in imp for u in UNSAFE):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=SEVERITY_WARNING,
                            message=f"unsafe memory access via '{imp}' — must be reviewed and justified",
                            location=Location(file=rel, line=1),
                            standard="iso26262",
                            clause="CWE-242",
                            remediation="document rationale; add #fusa:accept with reviewer and justification",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER005 — Command injection (subprocess with variable as command)
# ---------------------------------------------------------------------------
class CYBER005(Rule):
    rule_id = "CYBER005"
    description = "Command injection risk: subprocess with non-literal command — CWE-78"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        CALLS = {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in CALLS and node.args:
                        first = node.args[0]
                        # flag if first arg is not a literal list/string
                        if not isinstance(first, (ast.Constant, ast.List)):
                            # check for shell=True too (more dangerous)
                            has_shell = any(
                                kw.arg == "shell"
                                and isinstance(kw.value, ast.Constant)
                                and kw.value.value
                                for kw in node.keywords
                            )
                            if has_shell or isinstance(
                                first, (ast.Name, ast.JoinedStr, ast.BinOp)
                            ):
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        severity=SEVERITY_ERROR,
                                        message=f"'{name}' with dynamic command — command injection risk",
                                        location=Location(
                                            file=rel,
                                            line=getattr(node, "lineno", 0),
                                            end_line=getattr(node, "end_lineno", 0),
                                            end_column=getattr(
                                                node, "end_col_offset", -1
                                            )
                                            + 1,
                                        ),
                                        standard="iso26262",
                                        clause="CWE-78",
                                        remediation="use a literal list of arguments; never pass shell=True with user-controlled input",
                                    )
                                )
        return findings


# ---------------------------------------------------------------------------
# CYBER006 — Hardcoded credentials
# ---------------------------------------------------------------------------
_CRED_RE = re.compile(
    r"(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key|"
    r"auth[_-]?token|client[_-]?secret)",
    re.IGNORECASE,
)


class CYBER006(Rule):
    rule_id = "CYBER006"
    description = "Hardcoded credential in variable/constant — CWE-798"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                target_name = ""
                value = None
                if isinstance(node, ast.Assign):
                    value = node.value
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            target_name = t.id
                elif isinstance(node, ast.AnnAssign) and node.value:
                    value = node.value
                    if isinstance(node.target, ast.Name):
                        target_name = node.target.id
                elif isinstance(node, (ast.keyword,)):
                    target_name = node.arg or ""
                    value = node.value

                if target_name and value and _CRED_RE.search(target_name):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        if len(value.value) >= 4 and not value.value.startswith("$"):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_ERROR,
                                    message=f"hardcoded credential in '{target_name}'",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-798",
                                    remediation="load from environment variable or secret manager; never hardcode credentials",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER007 — TLS certificate verification disabled
# ---------------------------------------------------------------------------
class CYBER007(Rule):
    rule_id = "CYBER007"
    description = "TLS certificate verification disabled — CWE-295"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                # requests.get(..., verify=False)
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is False:
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        severity=SEVERITY_ERROR,
                                        message="TLS certificate verification disabled (verify=False)",
                                        location=Location(
                                            file=rel,
                                            line=getattr(node, "lineno", 0),
                                            end_line=getattr(node, "end_lineno", 0),
                                            end_column=getattr(
                                                node, "end_col_offset", -1
                                            )
                                            + 1,
                                        ),
                                        standard="iso26262",
                                        clause="CWE-295",
                                        remediation="remove verify=False; use a proper CA bundle or client certificate",
                                    )
                                )
                # ssl.CERT_NONE
                if isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
                    if isinstance(node.value, ast.Name) and node.value.id == "ssl":
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_ERROR,
                                message="ssl.CERT_NONE disables TLS certificate verification",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="iso26262",
                                clause="CWE-295",
                                remediation="use ssl.CERT_REQUIRED and provide a trusted CA bundle",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# CYBER008 — HTTP server without timeout
# ---------------------------------------------------------------------------
class CYBER008(Rule):
    rule_id = "CYBER008"
    description = "HTTP server created without request timeout — CWE-400"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        NO_TIMEOUT = {
            "HTTPServer",
            "BaseHTTPServer",
            "http.server.HTTPServer",
            "socketserver.TCPServer",
        }
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if any(name.endswith(s) for s in NO_TIMEOUT):
                        # Check no timeout set nearby (heuristic: no timeout kwarg)
                        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                        if not has_timeout:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message=f"'{name}' created without request timeout — vulnerable to slowloris",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-400",
                                    remediation="set socket.settimeout() or use a WSGI server with configurable timeouts",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER009 — Integer narrowing / truncation
# ---------------------------------------------------------------------------
class CYBER009(Rule):
    rule_id = "CYBER009"
    description = "Explicit integer narrowing conversion — CWE-190"

    _NARROW = {
        "ctypes.c_int8",
        "ctypes.c_int16",
        "ctypes.c_uint8",
        "ctypes.c_uint16",
        "ctypes.c_uint32",
        "ctypes.c_int32",
    }

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in self._NARROW and node.args:
                        if not isinstance(node.args[0], ast.Constant):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message=f"integer narrowing via '{name}' may truncate value",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-190",
                                    remediation="validate value range before narrowing; add assertion on bounds",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER010 — String concatenation in SQL/path queries
# ---------------------------------------------------------------------------
class CYBER010(Rule):
    rule_id = "CYBER010"
    description = "String concatenation in SQL or path API call — CWE-89/CWE-22"

    _SQL_CALLS = {
        "execute",
        "executemany",
        "cursor.execute",
        "db.execute",
        "connection.execute",
        "session.execute",
    }
    _PATH_CALLS = {"os.open", "os.stat", "open", "pathlib.Path"}

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        ALL = self._SQL_CALLS | self._PATH_CALLS
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and node.args:
                    name = _call_name(node)
                    if any(name.endswith(s) for s in ALL):
                        first = node.args[0]
                        if isinstance(first, ast.BinOp) and isinstance(
                            first.op, ast.Add
                        ):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_ERROR,
                                    message=f"string concatenation in '{name}' — SQL injection or path traversal risk",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-89",
                                    remediation="use parameterised queries or pathlib.Path() with validated components",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER011 — SSRF (URL from variable in HTTP client call)
# ---------------------------------------------------------------------------
class CYBER011(Rule):
    rule_id = "CYBER011"
    description = (
        "Server-Side Request Forgery: URL from variable in HTTP client — CWE-918"
    )

    _HTTP_CALLS = {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.request",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "httpx.get",
        "httpx.post",
        "aiohttp.get",
    }

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and node.args:
                    name = _call_name(node)
                    if name in self._HTTP_CALLS:
                        url_arg = node.args[0]
                        if not isinstance(url_arg, ast.Constant):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_WARNING,
                                    message=f"'{name}' called with non-literal URL — SSRF risk if URL is user-controlled",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-918",
                                    remediation="validate and whitelist URLs before making outbound requests",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER012 — Debug server / profiling endpoint exposed
# ---------------------------------------------------------------------------
class CYBER012(Rule):
    rule_id = "CYBER012"
    description = "Debug mode or profiling endpoint exposed in production — CWE-215"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    # Flask/Django debug=True
                    if name in ("app.run", "application.run"):
                        for kw in node.keywords:
                            if kw.arg == "debug" and isinstance(kw.value, ast.Constant):
                                if kw.value.value is True:
                                    findings.append(
                                        Finding(
                                            rule_id=self.rule_id,
                                            severity=SEVERITY_ERROR,
                                            message="debug=True in app.run() — exposes interactive debugger",
                                            location=Location(
                                                file=rel,
                                                line=getattr(node, "lineno", 0),
                                                end_line=getattr(node, "end_lineno", 0),
                                                end_column=getattr(
                                                    node, "end_col_offset", -1
                                                )
                                                + 1,
                                            ),
                                            standard="iso26262",
                                            clause="CWE-215",
                                            remediation="set debug=False; use environment variable DEBUG=0 in production",
                                        )
                                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER013 — Zip slip (unsafe archive extraction)
# ---------------------------------------------------------------------------
class CYBER013(Rule):
    rule_id = "CYBER013"
    description = "Unsafe archive extraction — zip slip path traversal — CWE-23"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name.endswith("extractall"):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_ERROR,
                                message="extractall() without member validation — zip slip path traversal risk",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="iso26262",
                                clause="CWE-23",
                                remediation="validate each member path: reject entries with '..' or absolute paths",
                            )
                        )
        return findings


# ---------------------------------------------------------------------------
# CYBER014 — TLS minimum version too low
# ---------------------------------------------------------------------------
class CYBER014(Rule):
    rule_id = "CYBER014"
    description = "TLS minimum version too low (SSLv2/SSLv3/TLSv1.0/TLSv1.1) — CWE-326"

    _WEAK_VERSIONS = {
        "PROTOCOL_SSLv2",
        "PROTOCOL_SSLv3",
        "PROTOCOL_TLSv1",
        "PROTOCOL_TLSv1_1",
        "TLSVersion.TLSv1",
        "TLSVersion.TLSv1_1",
    }

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in self._WEAK_VERSIONS:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=SEVERITY_ERROR,
                            message=f"weak TLS version '{node.attr}' — deprecated and vulnerable",
                            location=Location(
                                file=rel,
                                line=getattr(node, "lineno", 0),
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="iso26262",
                            clause="CWE-326",
                            remediation="use ssl.TLSVersion.TLSv1_2 or TLSv1_3 as minimum_version",
                        )
                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER015 — SQL injection via format string
# ---------------------------------------------------------------------------
class CYBER015(Rule):
    rule_id = "CYBER015"
    description = "SQL injection via f-string or % format in query — CWE-89"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        SQL_KW = re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b", re.IGNORECASE
        )
        for path in _python_files(project_root, cfg):
            tree, lines = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                # f-string containing SQL keywords
                if isinstance(node, ast.JoinedStr):
                    lineno = getattr(node, "lineno", 1)
                    line = lines[lineno - 1] if lineno <= len(lines) else ""
                    if SQL_KW.search(line):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_ERROR,
                                message="SQL query constructed with f-string — SQL injection risk",
                                location=Location(file=rel, line=lineno),
                                standard="iso26262",
                                clause="CWE-89",
                                remediation="use parameterised queries: cursor.execute(sql, params)",
                            )
                        )
                # %-format or .format() with SQL
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    if isinstance(node.left, ast.Constant) and isinstance(
                        node.left.value, str
                    ):
                        if SQL_KW.search(node.left.value):
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    severity=SEVERITY_ERROR,
                                    message="SQL query built with '%' string format — SQL injection risk",
                                    location=Location(
                                        file=rel,
                                        line=getattr(node, "lineno", 0),
                                        end_line=getattr(node, "end_lineno", 0),
                                        end_column=getattr(node, "end_col_offset", -1)
                                        + 1,
                                    ),
                                    standard="iso26262",
                                    clause="CWE-89",
                                    remediation="use parameterised queries: cursor.execute(sql, params)",
                                )
                            )
        return findings


# ---------------------------------------------------------------------------
# CYBER016 — Permissive directory creation mode
# ---------------------------------------------------------------------------
class CYBER016(Rule):
    rule_id = "CYBER016"
    description = "Directory created with permissive mode (0o777) — CWE-732"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        DIR_CALLS = {"os.mkdir", "os.makedirs", "pathlib.Path.mkdir"}
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if any(name.endswith(s) for s in DIR_CALLS):
                        for kw in node.keywords:
                            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                                if kw.value.value == 0o777:
                                    findings.append(
                                        Finding(
                                            rule_id=self.rule_id,
                                            severity=SEVERITY_WARNING,
                                            message=f"'{name}' with mode=0o777 — world-writable directory",
                                            location=Location(
                                                file=rel,
                                                line=getattr(node, "lineno", 0),
                                                end_line=getattr(node, "end_lineno", 0),
                                                end_column=getattr(
                                                    node, "end_col_offset", -1
                                                )
                                                + 1,
                                            ),
                                            standard="iso26262",
                                            clause="CWE-732",
                                            remediation="use mode=0o755 or 0o700 and set umask appropriately",
                                        )
                                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER017 — Permissive file creation mode
# ---------------------------------------------------------------------------
class CYBER017(Rule):
    rule_id = "CYBER017"
    description = "File created with permissive mode (0o666/0o777) — CWE-732"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and node.args:
                    name = _call_name(node)
                    if name in ("open", "os.open", "io.open"):
                        for kw in node.keywords:
                            if kw.arg in ("mode", "opener") and isinstance(
                                kw.value, ast.Constant
                            ):
                                if isinstance(
                                    kw.value.value, int
                                ) and kw.value.value in (0o666, 0o777):
                                    findings.append(
                                        Finding(
                                            rule_id=self.rule_id,
                                            severity=SEVERITY_WARNING,
                                            message=f"'{name}' with permissive mode 0o{kw.value.value:o} — world-readable/writable",
                                            location=Location(
                                                file=rel,
                                                line=getattr(node, "lineno", 0),
                                                end_line=getattr(node, "end_lineno", 0),
                                                end_column=getattr(
                                                    node, "end_col_offset", -1
                                                )
                                                + 1,
                                            ),
                                            standard="iso26262",
                                            clause="CWE-732",
                                            remediation="use mode=0o600 for sensitive files; apply principle of least privilege",
                                        )
                                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER018 — File path derived from request / user input
# ---------------------------------------------------------------------------
class CYBER018(Rule):
    rule_id = "CYBER018"
    description = "File path derived from user-controlled input — path traversal CWE-22"

    _USER_SOURCES = {
        "request.args",
        "request.form",
        "request.json",
        "request.get_json",
        "request.values",
        "flask.request",
        "input",
        "sys.argv",
    }

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            user_vars: set = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if _call_name(node.value) in self._USER_SOURCES:
                        for t in node.targets:
                            if isinstance(t, ast.Name):
                                user_vars.add(t.id)
                    if isinstance(node.value, ast.Subscript):
                        if isinstance(node.value.value, ast.Attribute):
                            full = f"{getattr(node.value.value.value, 'id', '')}.{node.value.value.attr}"
                            if full in self._USER_SOURCES:
                                for t in node.targets:
                                    if isinstance(t, ast.Name):
                                        user_vars.add(t.id)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and node.args:
                    name = _call_name(node)
                    if name in ("open", "os.open", "os.path.join", "pathlib.Path"):
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id in user_vars:
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        severity=SEVERITY_ERROR,
                                        message=f"user-controlled variable '{arg.id}' used in file path '{name}'",
                                        location=Location(
                                            file=rel,
                                            line=getattr(node, "lineno", 0),
                                            end_line=getattr(node, "end_lineno", 0),
                                            end_column=getattr(
                                                node, "end_col_offset", -1
                                            )
                                            + 1,
                                        ),
                                        standard="iso26262",
                                        clause="CWE-22",
                                        remediation="use pathlib.Path(base / name).resolve() and verify it is inside the allowed directory",
                                    )
                                )
        return findings


# ---------------------------------------------------------------------------
# CYBER019 — TOCTOU race condition (exists check + open)
# ---------------------------------------------------------------------------
class CYBER019(Rule):
    rule_id = "CYBER019"
    description = "TOCTOU race condition: existence check before file open — CWE-362"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        CHECK_CALLS = {"os.path.exists", "os.path.isfile", "os.access"}
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            # Collect (lineno, varname) for each existence check
            checks: List[tuple] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in CHECK_CALLS and node.args:
                        arg = node.args[0]
                        if isinstance(arg, ast.Name):
                            checks.append((getattr(node, "lineno", 0), arg.id))
            # Look for an open() within 5 lines of each check
            if not checks:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in ("open", "os.open") and node.args:
                        lineno = getattr(node, "lineno", 0)
                        arg = node.args[0]
                        if isinstance(arg, ast.Name):
                            for check_line, check_var in checks:
                                if (
                                    arg.id == check_var
                                    and 0 < lineno - check_line <= 10
                                ):
                                    findings.append(
                                        Finding(
                                            rule_id=self.rule_id,
                                            severity=SEVERITY_WARNING,
                                            message=f"TOCTOU: '{arg.id}' checked then opened — file may change between check and use",
                                            location=Location(file=rel, line=lineno),
                                            standard="iso26262",
                                            clause="CWE-362",
                                            remediation="use try/except on open() instead of pre-checking existence",
                                        )
                                    )
        return findings


# ---------------------------------------------------------------------------
# CYBER020 — Insecure temporary file (tempfile.mktemp)
# ---------------------------------------------------------------------------
class CYBER020(Rule):
    rule_id = "CYBER020"
    description = "Insecure temporary file creation — CWE-377"

    def run(self, project_root: str, cfg: Config) -> List[Finding]:
        findings: List[Finding] = []
        for path in _python_files(project_root, cfg):
            tree, _ = _parse(path)
            if tree is None:
                continue
            rel = _rel(path, project_root)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    name = _call_name(node)
                    if name in ("tempfile.mktemp", "mktemp"):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=SEVERITY_ERROR,
                                message="tempfile.mktemp() is insecure — file may be created by attacker between check and use",
                                location=Location(
                                    file=rel,
                                    line=getattr(node, "lineno", 0),
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="iso26262",
                                clause="CWE-377",
                                remediation="use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead",
                            )
                        )
        return findings


ALL: List[Rule] = [
    CYBER001(),
    CYBER002(),
    CYBER003(),
    CYBER004(),
    CYBER005(),
    CYBER006(),
    CYBER007(),
    CYBER008(),
    CYBER009(),
    CYBER010(),
    CYBER011(),
    CYBER012(),
    CYBER013(),
    CYBER014(),
    CYBER015(),
    CYBER016(),
    CYBER017(),
    CYBER018(),
    CYBER019(),
    CYBER020(),
]
