"""Security rules (SEC/CWE-series): ISO 21434, CERT Python, CWE-mapped."""

from __future__ import annotations

import ast
import re

import pyfusa
from pyfusa.config import Config
from pyfusa.rules import Rule
from pyfusa.rules.lint import _parse_file, _python_files

_SECRET_RE = re.compile(
    r"""(password|passwd|secret|token|api_key|apikey|private_key|auth_token)\s*=\s*['"][^'"]{4,}['"]""",
    re.IGNORECASE,
)


# fusa:req REQ-SEC001
class RuleBareExcept(Rule):
    rule_id = "SEC001"
    standard = "iso26262"
    clause = "7.4.4"
    description = "Bare 'except:' clauses suppress all exceptions including SystemExit and KeyboardInterrupt (CWE-703)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.ExceptHandler):
                    continue
                if node.type is None:
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="iso26262",
                            clause="7.4.4",
                            remediation="specify the exception type(s) to catch: 'except (ValueError, TypeError):'",
                        )
                    )
        return findings


# fusa:req REQ-SEC002
class RuleEvalUsage(Rule):
    rule_id = "SEC002"
    standard = "cert-c"
    clause = "ENV33-C"
    description = "eval() executes arbitrary code and must not be used (CWE-95)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="eval() executes arbitrary expressions and is prohibited in safety-critical code",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="cert-c",
                            clause="ENV33-C",
                            remediation="replace eval() with explicit data parsing (json.loads, ast.literal_eval for literals only)",
                        )
                    )
        return findings


# fusa:req REQ-SEC003
class RuleExecUsage(Rule):
    rule_id = "SEC003"
    standard = "cert-c"
    clause = "ENV33-C"
    description = "exec() executes arbitrary code and must not be used (CWE-78)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id == "exec":
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="exec() executes arbitrary code and is prohibited in safety-critical code",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="cert-c",
                            clause="ENV33-C",
                            remediation="remove exec(); use explicit function calls or importlib for dynamic dispatch",
                        )
                    )
        return findings


# fusa:req REQ-SEC004
class RulePickleUsage(Rule):
    rule_id = "SEC004"
    standard = "iso21434"
    clause = "9.5"
    description = "pickle.load/loads deserialises arbitrary Python objects (CWE-502)."

    _FUNCS = {"load", "loads", "Unpickler"}

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr in self._FUNCS:
                    if isinstance(func.value, ast.Name) and func.value.id in (
                        "pickle",
                        "cPickle",
                    ):
                        findings.append(
                            pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_ERROR,
                                message=f"pickle.{func.attr}() deserialises arbitrary objects; unsafe from untrusted input",
                                location=pyfusa.Location(
                                    file=rel_path,
                                    line=node.lineno,
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="iso21434",
                                remediation="use json, msgpack, or protobuf for serialisation of safety-critical data",
                            )
                        )
        return findings


# fusa:req REQ-SEC005
class RuleOsSystem(Rule):
    rule_id = "SEC005"
    standard = "cert-c"
    clause = "ENV33-C"
    description = "os.system() passes commands to a shell and is vulnerable to injection (CWE-78)."

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "system"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "os"
                ):
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="os.system() invokes a shell and is vulnerable to command injection",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="cert-c",
                            clause="ENV33-C",
                            remediation="use subprocess.run([...], shell=False, check=True) with a list of arguments",
                        )
                    )
        return findings


# fusa:req REQ-SEC006
class RuleSubprocessShell(Rule):
    rule_id = "SEC006"
    standard = "cert-c"
    clause = "ENV33-C"
    description = (
        "subprocess with shell=True is vulnerable to command injection (CWE-78)."
    )

    _FUNCS = {"Popen", "call", "check_call", "check_output", "run"}

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                is_subprocess_func = (
                    isinstance(func, ast.Attribute)
                    and func.attr in self._FUNCS
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                ) or (isinstance(func, ast.Name) and func.id in self._FUNCS)
                if not is_subprocess_func:
                    continue
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        findings.append(
                            pyfusa.Finding(
                                rule_id=self.rule_id,
                                severity=pyfusa.SEVERITY_ERROR,
                                message="subprocess called with shell=True enables command injection",
                                location=pyfusa.Location(
                                    file=rel_path,
                                    line=node.lineno,
                                    end_line=getattr(node, "end_lineno", 0),
                                    end_column=getattr(node, "end_col_offset", -1) + 1,
                                ),
                                standard="cert-c",
                                clause="ENV33-C",
                                remediation="pass a list of arguments and use shell=False (the default)",
                            )
                        )
        return findings


# fusa:req REQ-SEC007
class RuleHardcodedSecret(Rule):
    rule_id = "SEC007"
    standard = "iso21434"
    clause = "9.4.2"
    description = (
        "Hardcoded credentials or secrets must not appear in source (CWE-312)."
    )

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            try:
                with open(abs_path, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                if _SECRET_RE.search(line):
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="potential hardcoded credential or secret found",
                            location=pyfusa.Location(file=rel_path, line=lineno),
                            standard="iso21434",
                            remediation="load credentials from environment variables or a secrets manager",
                        )
                    )
        return findings


# fusa:req REQ-SEC008
class RuleTempfileMktemp(Rule):
    rule_id = "SEC008"
    standard = "cert-c"
    clause = "FIO21-C"
    description = (
        "tempfile.mktemp() creates a race condition; use tempfile.mkstemp() (CWE-377)."
    )

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "mktemp"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "tempfile"
                ):
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_ERROR,
                            message="tempfile.mktemp() is insecure; creates a TOCTOU race condition",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            remediation="use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead",
                        )
                    )
        return findings


# fusa:req REQ-SEC009
class RuleRandomForSecurity(Rule):
    rule_id = "SEC009"
    standard = "iso21434"
    clause = "9.5"
    description = "random module must not be used for security-sensitive values; use secrets (CWE-330)."

    _SEC_FUNCS = {
        "randint",
        "random",
        "choice",
        "choices",
        "sample",
        "randrange",
        "uniform",
    }

    def run(self, project_root: str, cfg: Config) -> list[pyfusa.Finding]:
        findings = []
        for abs_path, rel_path in _python_files(
            project_root, cfg.source_dirs, cfg.exclude_patterns
        ):
            tree, _ = _parse_file(abs_path)
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr in self._SEC_FUNCS
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "random"
                ):
                    findings.append(
                        pyfusa.Finding(
                            rule_id=self.rule_id,
                            severity=pyfusa.SEVERITY_WARNING,
                            message=f"random.{func.attr}() is not cryptographically secure",
                            location=pyfusa.Location(
                                file=rel_path,
                                line=node.lineno,
                                end_line=getattr(node, "end_lineno", 0),
                                end_column=getattr(node, "end_col_offset", -1) + 1,
                            ),
                            standard="iso21434",
                            remediation="use secrets.token_bytes(), secrets.choice(), or secrets.randbelow() for security values",
                        )
                    )
        return findings


ALL: list[Rule] = [
    RuleBareExcept(),
    RuleEvalUsage(),
    RuleExecUsage(),
    RulePickleUsage(),
    RuleOsSystem(),
    RuleSubprocessShell(),
    RuleHardcodedSecret(),
    RuleTempfileMktemp(),
    RuleRandomForSecurity(),
]
