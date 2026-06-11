"""pyfusa CLI — functional safety enablement toolkit for Python.

Usage:
    pyfusa <command> [flags]

Commands:
    init         Initialise a pyfusa project configuration
    check        Run all safety checks (exits 1 on ERROR findings)
    report       Generate a safety compliance report (always exits 0)
    trace        Show requirements traceability matrix
    qualify      Run the tool qualification suite
    release      Generate SBOM, provenance, and artifact manifest
    audit-pack   Bundle all evidence artifacts into a single ZIP for auditors
    capabilities Report tool capabilities (commands, formats, standards)
    version      Print the py-FuSa version

Run 'pyfusa <command> --help' for command-specific flags.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

import pyfusa
from pyfusa import VERSION, SPEC_VERSION, LANGUAGE, TOOL, BINARY
from pyfusa import EXIT_OK, EXIT_GATE_FAIL, EXIT_USAGE, EXIT_RUNTIME
import pyfusa.config as _config
import pyfusa.engine as _engine
import pyfusa.report as _report
import pyfusa.trace as _trace
import pyfusa.qualify as _qualify
import pyfusa.release as _release
import pyfusa.auditpack as _auditpack


def _is_tty() -> bool:
    return sys.stdin.isatty()


def _no_color() -> bool:
    return (
        os.environ.get("NO_COLOR") is not None
        or not sys.stdout.isatty()
        or "--no-color" in sys.argv
    )


def _resolve_dir(d: Optional[str]) -> str:
    if d:
        return os.path.abspath(d)
    return os.getcwd()


def _load_config(project_root: str) -> _config.Config:
    """Load config or return default."""
    cfg_path = os.path.join(project_root, _config.CONFIG_FILE)
    try:
        return _config.load(cfg_path)
    except FileNotFoundError:
        return _config.default(project_name=os.path.basename(project_root))
    except ValueError as e:
        print(f"pyfusa: {e}", file=sys.stderr)
        return _config.default(project_name=os.path.basename(project_root))


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------

def cmd_version(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa version", add_help=True)
    p.add_argument("--format", choices=["text", "json"], default="text")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    if ns.format == "json":
        doc = {"tool": TOOL, "version": VERSION, "specVersion": SPEC_VERSION}
        print(json.dumps(doc, indent=2), file=stdout)
    else:
        print(f"{TOOL} {VERSION}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# capabilities
# ---------------------------------------------------------------------------

def cmd_capabilities(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa capabilities", add_help=True)
    p.add_argument("--format", choices=["text", "json"], default="json")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    from datetime import timezone, datetime
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = {
        "schemaVersion": SPEC_VERSION,
        "kind": "capabilities",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "specVersion": SPEC_VERSION,
        "commands": ["version", "capabilities", "init", "check", "report",
                     "trace", "qualify", "release", "audit-pack"],
        "formats": {
            "check": ["text", "json", "html", "sarif", "md"],
            "report": ["text", "json", "html", "sarif", "md"],
            "trace": ["text", "json"],
            "qualify": ["text", "json"],
        },
        "standards": ["iso26262", "iec61508", "iso21434"],
    }

    if ns.format == "json":
        print(json.dumps(doc, indent=2), file=stdout)
    else:
        print(f"{TOOL} {VERSION}", file=stdout)
        print(f"Commands: {', '.join(doc['commands'])}", file=stdout)
        print(f"Standards: {', '.join(doc['standards'])}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa init", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--name", default="", help="project name")
    p.add_argument("--standard", default="", help="safety standard (iso26262, iec61508, do178c, iso21434)")
    p.add_argument("--asil", default="", help="ASIL level (iso26262)")
    p.add_argument("--sil", default="", help="SIL level (iec61508)")
    p.add_argument("--dal", default="", help="DAL level (do178c)")
    p.add_argument("--project-version", default="0.1.0", help="project version")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)

    # Resolve required values
    name = ns.name
    standard = ns.standard

    if not name and not _is_tty():
        print("pyfusa init: --name is required in non-interactive mode", file=stderr)
        return EXIT_USAGE
    if not standard and not _is_tty():
        print("pyfusa init: --standard is required in non-interactive mode", file=stderr)
        return EXIT_USAGE

    if not name:
        name = input(f"Project name [{os.path.basename(project_root)}]: ").strip()
        if not name:
            name = os.path.basename(project_root)

    if not standard:
        standard = input("Safety standard [iso26262]: ").strip()
        if not standard:
            standard = "iso26262"

    standard = standard.lower()

    # Determine integrity field
    asil = ns.asil
    sil = ns.sil
    dal = ns.dal
    if not (asil or sil or dal) and _is_tty():
        integrity_key = {"iso26262": "asil", "iec61508": "sil", "do178c": "dal"}.get(standard, "asil")
        val = input(f"{integrity_key.upper()} level (optional, e.g. ASIL-B): ").strip()
        if val:
            if integrity_key == "asil":
                asil = val
            elif integrity_key == "sil":
                sil = val
            elif integrity_key == "dal":
                dal = val

    # Write .fusa.json
    cfg_path = os.path.join(project_root, _config.CONFIG_FILE)
    if os.path.exists(cfg_path) and not ns.force:
        print(f"pyfusa init: {_config.CONFIG_FILE} already exists; use --force to overwrite", file=stderr)
    else:
        cfg_doc: dict = {
            "configVersion": "1.0",
            "project": {"name": name, "version": ns.project_version},
            "standard": standard,
        }
        if asil:
            cfg_doc["asil"] = asil
        elif sil:
            cfg_doc["sil"] = sil
        elif dal:
            cfg_doc["dal"] = dal
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg_doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"created {_config.CONFIG_FILE}", file=stdout)

    # Write .fusa-reqs.json
    reqs_path = os.path.join(project_root, _config.REQS_FILE)
    if os.path.exists(reqs_path) and not ns.force:
        print(f"pyfusa init: {_config.REQS_FILE} already exists; use --force to overwrite", file=stderr)
    else:
        reqs_doc = {"requirements": []}
        with open(reqs_path, "w", encoding="utf-8") as f:
            json.dump(reqs_doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"created {_config.REQS_FILE}", file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def cmd_check(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa check", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--format", default="", dest="fmt", help="output format: text, json, html, sarif, md")
    p.add_argument("--output", default="", help="write report to file")
    p.add_argument("--strict", action="store_true", help="exit 1 on WARNING findings too")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    if ns.fmt:
        cfg.report_format = ns.fmt
    if ns.output:
        cfg.report_output = ns.output

    try:
        result = _engine.Default.run(project_root, cfg)
    except Exception as e:
        print(f"pyfusa check: engine error: {e}", file=stderr)
        return EXIT_RUNTIME

    for err in result.errors:
        print(f"pyfusa check: warning: {err}", file=stderr)

    w = stdout
    f_out = None
    if cfg.report_output:
        try:
            f_out = open(cfg.report_output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa check: create output: {e}", file=stderr)
            return EXIT_RUNTIME

    try:
        _report.render(w, result, cfg.report_format, project_root, cfg)
    finally:
        if f_out:
            f_out.close()

    if result.has_errors():
        return EXIT_GATE_FAIL
    if ns.strict and result.has_warnings():
        return EXIT_GATE_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def cmd_report(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    # Same as check but always exits 0 (§9.1)
    p = argparse.ArgumentParser(prog="pyfusa report", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--format", default="", dest="fmt", help="output format: text, json, html, sarif, md")
    p.add_argument("--output", default="", help="write report to file")
    p.add_argument("--strict", action="store_true", help="(not valid for report; usage error)")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    if ns.strict:
        print("pyfusa report: --strict is not valid for report", file=stderr)
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    if ns.fmt:
        cfg.report_format = ns.fmt
    if ns.output:
        cfg.report_output = ns.output

    try:
        result = _engine.Default.run(project_root, cfg)
    except Exception as e:
        print(f"pyfusa report: engine error: {e}", file=stderr)
        return EXIT_RUNTIME

    w = stdout
    f_out = None
    if cfg.report_output:
        try:
            f_out = open(cfg.report_output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa report: create output: {e}", file=stderr)
            return EXIT_RUNTIME

    try:
        _report.render(w, result, cfg.report_format, project_root, cfg)
    finally:
        if f_out:
            f_out.close()

    return EXIT_OK  # Always 0


# ---------------------------------------------------------------------------
# trace
# ---------------------------------------------------------------------------

def cmd_trace(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa trace", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="", help="write output to file")
    p.add_argument("--gaps", action="store_true", help="show only requirements with no test tag")
    p.add_argument("--req-coverage", type=int, default=0, metavar="N", help="exit 1 if req coverage < N%%")
    p.add_argument("--sec-tested", type=int, default=0, metavar="N", help="exit 1 if sec-test coverage < N%%")
    p.add_argument("--strict", action="store_true", help="equivalent to --req-coverage 100 --sec-tested 100")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    try:
        matrix = _trace.build(project_root, cfg)
    except Exception as e:
        print(f"pyfusa trace: {e}", file=stderr)
        return EXIT_RUNTIME

    # Determine thresholds (§5)
    req_threshold = 100 if ns.strict and ns.req_coverage == 0 else ns.req_coverage
    sec_threshold = 100 if ns.strict and ns.sec_tested == 0 else ns.sec_tested

    w = stdout
    f_out = None
    if ns.output:
        try:
            f_out = open(ns.output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa trace: create output: {e}", file=stderr)
            return EXIT_RUNTIME

    try:
        if ns.fmt == "json":
            doc = _trace.to_dict(matrix, project_root, cfg, gaps_only=ns.gaps)
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_trace.render_text(matrix, gaps_only=ns.gaps))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    cov = matrix.coverage
    total = cov.total_requirements or 1  # avoid div/0

    if req_threshold > 0:
        pct = int(cov.tested_requirements * 100 // total)
        if pct < req_threshold:
            print(f"pyfusa trace: req coverage {pct}% < {req_threshold}%", file=stderr)
            return EXIT_GATE_FAIL

    if sec_threshold > 0:
        pct = int(cov.sec_tested_requirements * 100 // total)
        if pct < sec_threshold:
            print(f"pyfusa trace: sec-test coverage {pct}% < {sec_threshold}%", file=stderr)
            return EXIT_GATE_FAIL

    return EXIT_OK


# ---------------------------------------------------------------------------
# qualify
# ---------------------------------------------------------------------------

def cmd_qualify(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa qualify", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="", help="write output to file (default: qualify-report.json for json)")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    report = _qualify.run()

    output_path = ns.output

    w = stdout
    f_out = None
    if output_path:
        try:
            f_out = open(output_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa qualify: create output: {e}", file=stderr)
            return EXIT_RUNTIME

    try:
        if ns.fmt == "json":
            doc = _qualify.to_dict(report, project_root, cfg)
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            for tc in report.results:
                print(f"  {tc.result:5s}  {tc.name}", file=w)
            print(file=w)
            print(f"Total: {report.total}  Passed: {report.passed}  Failed: {report.failed}", file=w)
    finally:
        if f_out:
            f_out.close()

    if output_path and ns.fmt != "json":
        pass

    return EXIT_OK if report.failed == 0 else EXIT_GATE_FAIL


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------

def cmd_release(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa release", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--output-dir", default="", help="directory for generated artifacts (default: project root)")
    p.add_argument("--full", action="store_true", help="also generate audit-pack.zip")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    output_dir = os.path.abspath(ns.output_dir) if ns.output_dir else project_root

    try:
        written = _release.run_release(project_root, cfg, output_dir)
        for path in written:
            print(f"wrote {os.path.relpath(path, project_root)}", file=stdout)
    except Exception as e:
        print(f"pyfusa release: {e}", file=stderr)
        return EXIT_RUNTIME

    if ns.full:
        try:
            pack_path = _auditpack.create(project_root, os.path.join(project_root, "audit-pack.zip"))
            print(f"wrote {os.path.relpath(pack_path, project_root)}", file=stdout)
        except Exception as e:
            print(f"pyfusa release: audit-pack: {e}", file=stderr)

    return EXIT_OK


# ---------------------------------------------------------------------------
# audit-pack
# ---------------------------------------------------------------------------

def cmd_audit_pack(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa audit-pack", add_help=True)
    p.add_argument("--dir", default="", help="project root directory")
    p.add_argument("--output", default="", help="output ZIP path (default: <dir>/audit-pack.zip)")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    output_path = os.path.abspath(ns.output) if ns.output else None

    try:
        pack_path = _auditpack.create(project_root, output_path)
        print(f"wrote {os.path.relpath(pack_path, project_root)}", file=stdout)
    except Exception as e:
        print(f"pyfusa audit-pack: {e}", file=stderr)
        return EXIT_RUNTIME

    return EXIT_OK


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

_COMMANDS = {
    "version": cmd_version,
    "capabilities": cmd_capabilities,
    "init": cmd_init,
    "check": cmd_check,
    "report": cmd_report,
    "trace": cmd_trace,
    "qualify": cmd_qualify,
    "release": cmd_release,
    "audit-pack": cmd_audit_pack,
}


def _strip_no_color(args: list[str]) -> list[str]:
    """§2.6 strip --no-color flag and set NO_COLOR env var."""
    out = []
    for a in args:
        if a in ("--no-color", "-no-color"):
            os.environ["NO_COLOR"] = "1"
        else:
            out.append(a)
    return out


def _usage(w=sys.stdout) -> None:
    print(f"{BINARY} — functional safety enablement toolkit for Python\n", file=w)
    print("Usage:", file=w)
    print(f"  {BINARY} <command> [flags]\n", file=w)
    print("Commands:", file=w)
    print("  init         Initialise a pyfusa project configuration", file=w)
    print("  check        Run all safety checks (exits 1 on ERROR findings)", file=w)
    print("  report       Generate a safety compliance report (always exits 0)", file=w)
    print("  trace        Show requirements traceability matrix", file=w)
    print("  qualify      Run the tool qualification suite", file=w)
    print("  release      Generate SBOM, provenance, and artifact manifest", file=w)
    print("  audit-pack   Bundle all evidence artifacts into a single ZIP for auditors", file=w)
    print("  capabilities Report tool capabilities (commands, formats, standards)", file=w)
    print("  version      Print the py-FuSa version", file=w)
    print(f"\nRun '{BINARY} <command> --help' for command-specific flags.", file=w)


def run(args: list[str] | None = None, stdout=sys.stdout, stderr=sys.stderr) -> int:
    if args is None:
        args = sys.argv[1:]

    args = _strip_no_color(list(args))

    if not args:
        _usage(stdout)
        return EXIT_USAGE

    cmd = args[0]
    rest = args[1:]

    if cmd in ("help", "--help", "-h"):
        _usage(stdout)
        return EXIT_OK

    if cmd not in _COMMANDS:
        print(f"pyfusa: unknown command {cmd!r}", file=stderr)
        print(f"Run 'pyfusa help' for usage.", file=stderr)
        return EXIT_USAGE

    return _COMMANDS[cmd](rest, stdout=stdout, stderr=stderr)


def main() -> None:
    sys.exit(run())
