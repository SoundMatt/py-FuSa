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
import pyfusa.fmea as _fmea
import pyfusa.boundary as _boundary
import pyfusa.coupling_analysis as _coupling
import pyfusa.tara as _tara
import pyfusa.hara as _hara
import pyfusa.diff as _diff
import pyfusa.badge as _badge
import pyfusa.sign as _sign
import pyfusa.vuln as _vuln
import pyfusa.pr as _pr
import pyfusa.disposition_mgmt as _disp_mgmt
import pyfusa.impact as _impact
import pyfusa.metrics as _metrics
import pyfusa.safetycase as _safetycase
import pyfusa.req_mgmt as _req_mgmt
import pyfusa.template as _template
import pyfusa.misra as _misra
import pyfusa.verify as _verify
import pyfusa.sas as _sas
import pyfusa.sci as _sci
import pyfusa.coverage as _coverage
from pyfusa.compliance import do178 as _do178
from pyfusa.compliance import iso26262 as _iso26262
from pyfusa.compliance import iec61508 as _iec61508
from pyfusa.compliance import iso21434 as _iso21434
from pyfusa.compliance import unece as _unece
from pyfusa.compliance import iec62443 as _iec62443_gap
from pyfusa.compliance import slsa as _slsa_gap


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
        "commands": [
            "version", "capabilities", "init", "check", "lint", "analyze", "cyber",
            "report", "trace", "verify", "qualify", "release", "audit-pack", "coverage",
            "fmea", "boundary", "coupling", "tara", "hara", "safety-case", "sas", "sci",
            "iso26262", "iec61508", "do178", "iso21434", "unece", "iec62443", "slsa", "misra",
            "req", "diff", "badge", "fix", "hooks", "sign", "vuln",
            "disposition", "pr", "impact", "metrics", "template",
        ],
        "formats": {
            "check":    ["text", "json", "html", "sarif", "md"],
            "lint":     ["text", "json", "html", "sarif", "md"],
            "analyze":  ["text", "json", "html", "sarif", "md"],
            "cyber":    ["text", "json", "html", "sarif", "md"],
            "report":   ["text", "json", "html", "sarif", "md"],
            "trace":    ["text", "json"],
            "qualify":  ["text", "json"],
            "fmea":     ["json", "csv"],
            "boundary": ["json", "mermaid", "dot"],
            "tara":     ["json", "md"],
            "misra":    ["text", "json"],
            "safety-case": ["json", "md", "mermaid"],
        },
        "standards": ["iso26262", "iec61508", "iso21434", "do178c", "unece-r155", "iec62443", "slsa"],
        "ruleCount": 47,
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
# lint — run only LINT rules
# ---------------------------------------------------------------------------

def cmd_lint(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa lint", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json", "sarif", "md", "html"])
    p.add_argument("--output", default="")
    p.add_argument("--strict", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    from pyfusa.rules import lint as _lint_rules
    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    eng = _engine.Engine()
    for r in _lint_rules.ALL:
        eng.register(r)
    result = eng.run(project_root, cfg)

    w = stdout
    f_out = None
    if ns.output:
        try:
            f_out = open(ns.output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa lint: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        _report.render(w, result, ns.fmt, project_root, cfg)
    finally:
        if f_out:
            f_out.close()

    if result.has_errors():
        return EXIT_GATE_FAIL
    if ns.strict and result.has_warnings():
        return EXIT_GATE_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# analyze — run ANA rules
# ---------------------------------------------------------------------------

def cmd_analyze(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa analyze", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json", "sarif", "md", "html"])
    p.add_argument("--output", default="")
    p.add_argument("--strict", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    from pyfusa.rules import analyze as _ana_rules
    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    eng = _engine.Engine()
    for r in _ana_rules.ALL:
        eng.register(r)
    result = eng.run(project_root, cfg)

    w = stdout
    f_out = None
    if ns.output:
        try:
            f_out = open(ns.output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa analyze: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        _report.render(w, result, ns.fmt, project_root, cfg)
    finally:
        if f_out:
            f_out.close()

    if result.has_errors():
        return EXIT_GATE_FAIL
    if ns.strict and result.has_warnings():
        return EXIT_GATE_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# cyber — run CYBER rules
# ---------------------------------------------------------------------------

def cmd_cyber(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa cyber", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json", "sarif", "md", "html"])
    p.add_argument("--output", default="")
    p.add_argument("--strict", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    from pyfusa.rules import cyber as _cyber_rules
    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    eng = _engine.Engine()
    for r in _cyber_rules.ALL:
        eng.register(r)
    result = eng.run(project_root, cfg)

    w = stdout
    f_out = None
    if ns.output:
        try:
            f_out = open(ns.output, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa cyber: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        _report.render(w, result, ns.fmt, project_root, cfg)
    finally:
        if f_out:
            f_out.close()

    if result.has_errors():
        return EXIT_GATE_FAIL
    if ns.strict and result.has_warnings():
        return EXIT_GATE_FAIL
    return EXIT_OK


# ---------------------------------------------------------------------------
# fmea
# ---------------------------------------------------------------------------

def cmd_fmea(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa fmea", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "csv", "text"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    entries = _fmea.scan(project_root, cfg)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa fmea: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            doc = _fmea.to_dict(entries, project_root, cfg)
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        elif ns.fmt == "csv":
            w.write(_fmea.to_csv(entries))
        else:
            for e in entries:
                print(f"{e['component']}.{e['function']}  [{e['severity']}]  {', '.join(e['failure_modes'])}", file=w)
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root) if not ns.output else out_path}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# boundary
# ---------------------------------------------------------------------------

def cmd_boundary(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa boundary", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "mermaid", "dot"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    graph = _boundary.scan(project_root, cfg)
    module = cfg.project.name or os.path.basename(project_root)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa boundary: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            doc = _boundary.to_dict(graph, project_root, cfg)
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        elif ns.fmt == "mermaid":
            w.write(_boundary.to_mermaid(graph, module))
            w.write("\n")
        else:
            w.write(_boundary.to_dot(graph, module))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# coupling
# ---------------------------------------------------------------------------

def cmd_coupling(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa coupling", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "text"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    report = _coupling.run(project_root, cfg)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa coupling: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(report, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            dc = len(report.get("dataCoupling", []))
            cc = len(report.get("controlCoupling", []))
            print(f"data coupling: {dc}  control coupling: {cc}", file=w)
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# tara
# ---------------------------------------------------------------------------

def cmd_tara(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa tara", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "md", "text"])
    p.add_argument("--output", default="")
    p.add_argument("--from-report", default="", help="path to cyber/check-report.json to derive threats from")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    # Load findings from existing report or run cyber check
    findings = []
    report_path = ns.from_report or os.path.join(project_root, "check-report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                doc = json.load(f)
            findings = doc.get("findings", [])
        except Exception:
            pass

    if not findings:
        # Run cyber rules inline
        from pyfusa.rules import cyber as _cyber_rules
        from pyfusa.rules import security as _sec_rules
        eng = _engine.Engine()
        for r in _cyber_rules.ALL + _sec_rules.ALL:
            eng.register(r)
        result = eng.run(project_root, cfg)
        findings = [f.to_dict() for f in result.findings]

    entries = _tara.build(findings, project_root, cfg)
    module = cfg.project.name or os.path.basename(project_root)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa tara: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            doc = _tara.to_dict(entries, project_root, cfg)
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_tara.to_markdown(entries, module))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# hara
# ---------------------------------------------------------------------------

def cmd_hara(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa hara", add_help=True)
    p.add_argument("subcommand", nargs="?", default="show", choices=["show", "init", "validate"])
    p.add_argument("--dir", default="")
    p.add_argument("--asil", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    module = cfg.project.name or os.path.basename(project_root)

    if ns.subcommand == "init":
        import os as _os
        hara_path = _os.path.join(project_root, _hara.HARA_FILE)
        if _os.path.exists(hara_path):
            print(f"pyfusa hara: {_hara.HARA_FILE} already exists", file=stderr)
            return EXIT_USAGE
        data = _hara.init_template(module, cfg.standard or "ISO 26262")
        _hara.save(project_root, data)
        print(f"wrote {_hara.HARA_FILE}", file=stdout)
        return EXIT_OK

    data = _hara.load(project_root)
    if data is None:
        print(f"pyfusa hara: {_hara.HARA_FILE} not found — run 'pyfusa hara init'", file=stderr)
        return EXIT_RUNTIME

    if ns.subcommand == "validate":
        asil = ns.asil or cfg.asil or "ASIL-B"
        errors = _hara.validate(data, asil)
        if errors:
            for e in errors:
                print(e, file=stdout)
            return EXIT_GATE_FAIL
        print(f"HARA valid — {len(data.get('hazards',[]))} hazards, {len(data.get('safetyGoals',[]))} safety goals", file=stdout)
        return EXIT_OK

    # show
    print(json.dumps(data, indent=2, ensure_ascii=False), file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def cmd_diff(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa diff", add_help=True)
    p.add_argument("baseline", help="baseline check-report.json")
    p.add_argument("current", help="current check-report.json")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    try:
        result = _diff.compare(ns.baseline, ns.current)
    except (OSError, ValueError) as e:
        print(f"pyfusa diff: {e}", file=stderr)
        return EXIT_RUNTIME

    if ns.fmt == "json":
        json.dump(result, stdout, indent=2, ensure_ascii=False)
        print(file=stdout)
    else:
        print(_diff.render_text(result), file=stdout)

    return EXIT_GATE_FAIL if result["introduced"] else EXIT_OK


# ---------------------------------------------------------------------------
# badge
# ---------------------------------------------------------------------------

def cmd_badge(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa badge", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--report", default="", help="path to check-report.json")
    p.add_argument("--output", default="badge.svg")
    p.add_argument("--errors", type=int, default=-1)
    p.add_argument("--warnings", type=int, default=-1)
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)

    if ns.errors >= 0 or ns.warnings >= 0:
        svg = _badge.generate(max(0, ns.errors), max(0, ns.warnings))
    else:
        report_path = ns.report or os.path.join(project_root, "check-report.json")
        if not os.path.exists(report_path):
            print(f"pyfusa badge: {report_path} not found", file=stderr)
            return EXIT_RUNTIME
        svg = _badge.from_report(report_path)

    out_path = ns.output if os.path.isabs(ns.output) else os.path.join(project_root, ns.output)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    except OSError as e:
        print(f"pyfusa badge: {e}", file=stderr)
        return EXIT_RUNTIME
    return EXIT_OK


# ---------------------------------------------------------------------------
# req
# ---------------------------------------------------------------------------

def cmd_req(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa req", add_help=True)
    p.add_argument("subcommand", nargs="?", default="list", choices=["list", "add", "export", "import"])
    p.add_argument("--dir", default="")
    p.add_argument("--id", default="")
    p.add_argument("--title", default="")
    p.add_argument("--text", default="")
    p.add_argument("--standard", default="")
    p.add_argument("--level", default="HLR")
    p.add_argument("--asil", default="")
    p.add_argument("--file", default="", help="CSV file for import/export")
    p.add_argument("--verbose", "-v", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)

    if ns.subcommand == "list":
        data = _req_mgmt.load(project_root)
        print(_req_mgmt.render_text(data.get("requirements", []), verbose=ns.verbose), file=stdout)

    elif ns.subcommand == "add":
        if not ns.id or not ns.title:
            print("pyfusa req add: --id and --title are required", file=stderr)
            return EXIT_USAGE
        try:
            entry = _req_mgmt.add(project_root, ns.id, ns.title, ns.text, ns.standard, ns.level, ns.asil)
            print(f"added {entry['id']}", file=stdout)
        except ValueError as e:
            print(f"pyfusa req: {e}", file=stderr)
            return EXIT_USAGE

    elif ns.subcommand == "export":
        data = _req_mgmt.load(project_root)
        csv_text = _req_mgmt.to_csv(data.get("requirements", []))
        if ns.file:
            with open(ns.file, "w", encoding="utf-8") as f:
                f.write(csv_text)
            print(f"exported to {ns.file}", file=stdout)
        else:
            print(csv_text, file=stdout, end="")

    elif ns.subcommand == "import":
        if not ns.file:
            print("pyfusa req import: --file required", file=stderr)
            return EXIT_USAGE
        with open(ns.file, encoding="utf-8") as f:
            csv_text = f.read()
        reqs = _req_mgmt.from_csv(csv_text)
        data = _req_mgmt.load(project_root)
        existing_ids = {r["id"] for r in data.get("requirements", [])}
        added = 0
        for r in reqs:
            if r["id"] not in existing_ids:
                data.setdefault("requirements", []).append(r)
                added += 1
        _req_mgmt.save(project_root, data)
        print(f"imported {added} requirements", file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# fix
# ---------------------------------------------------------------------------

def cmd_fix(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa fix", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    result = _engine.Default.run(project_root, cfg)
    fixable = [f for f in result.findings if f.remediation]

    if ns.fmt == "json":
        json.dump([f.to_dict() for f in fixable], stdout, indent=2, ensure_ascii=False)
        print(file=stdout)
    else:
        if not fixable:
            print("no fixable findings", file=stdout)
        for f in fixable:
            loc = f.location
            print(f"{f.rule_id}  {loc.file}:{loc.line}  {f.message}", file=stdout)
            print(f"  fix: {f.remediation}", file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# hooks
# ---------------------------------------------------------------------------

def cmd_hooks(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa hooks", add_help=True)
    p.add_argument("subcommand", nargs="?", default="install", choices=["install", "remove"])
    p.add_argument("--dir", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    hook_path = os.path.join(project_root, ".git", "hooks", "pre-commit")

    if ns.subcommand == "remove":
        if os.path.exists(hook_path):
            os.remove(hook_path)
            print("removed pre-commit hook", file=stdout)
        else:
            print("no pre-commit hook found", file=stdout)
        return EXIT_OK

    hook_script = """#!/bin/sh
set -e
if command -v pyfusa >/dev/null 2>&1; then
  pyfusa check --strict
else
  echo "pyfusa: not found in PATH; skipping safety check" >&2
fi
"""
    try:
        os.makedirs(os.path.dirname(hook_path), exist_ok=True)
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_script)
        os.chmod(hook_path, 0o750)
        print(f"installed pre-commit hook at {hook_path}", file=stdout)
    except OSError as e:
        print(f"pyfusa hooks: {e}", file=stderr)
        return EXIT_RUNTIME
    return EXIT_OK


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

def cmd_sign(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa sign", add_help=True)
    p.add_argument("subcommand", choices=["keygen", "sign", "verify"])
    p.add_argument("--key", default="sign.key", help="path to HMAC key file")
    p.add_argument("--file", default="", help="file to sign or verify")
    p.add_argument("--sig", default="", help="signature file (default: <file>.sig)")
    p.add_argument("--dir", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    key_path = ns.key if os.path.isabs(ns.key) else os.path.join(project_root, ns.key)

    if ns.subcommand == "keygen":
        try:
            _sign.keygen(key_path)
            print(f"key written to {key_path}", file=stdout)
        except OSError as e:
            print(f"pyfusa sign keygen: {e}", file=stderr)
            return EXIT_RUNTIME
        return EXIT_OK

    if not ns.file:
        print("pyfusa sign: --file required", file=stderr)
        return EXIT_USAGE

    file_path = ns.file if os.path.isabs(ns.file) else os.path.join(project_root, ns.file)

    if ns.subcommand == "sign":
        try:
            sig_path = _sign.sign_file(file_path, key_path, ns.sig)
            print(f"signature written to {sig_path}", file=stdout)
        except (OSError, ValueError) as e:
            print(f"pyfusa sign: {e}", file=stderr)
            return EXIT_RUNTIME
        return EXIT_OK

    # verify
    try:
        ok = _sign.verify_file(file_path, key_path, ns.sig)
        if ok:
            print("OK", file=stdout)
            return EXIT_OK
        else:
            print("FAIL — signature mismatch", file=stdout)
            return EXIT_GATE_FAIL
    except (OSError, ValueError) as e:
        print(f"pyfusa sign verify: {e}", file=stderr)
        return EXIT_RUNTIME


# ---------------------------------------------------------------------------
# vuln
# ---------------------------------------------------------------------------

def cmd_vuln(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa vuln", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="")
    p.add_argument("--timeout", type=int, default=30)
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    print("scanning installed packages via OSV API...", file=stderr)
    report = _vuln.scan(project_root, cfg, timeout=ns.timeout)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa vuln: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(report, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            findings = report.get("findings", [])
            print(f"scanned {report.get('scanned',0)} packages  vulnerabilities: {len(findings)}", file=w)
            for f in findings:
                print(f"  {f['module']}@{f['version']}  {f['id']}  {f.get('summary','')[:80]}", file=w)
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)

    return EXIT_GATE_FAIL if report.get("findings") else EXIT_OK


# ---------------------------------------------------------------------------
# pr (problem reports)
# ---------------------------------------------------------------------------

def cmd_pr(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa pr", add_help=True)
    p.add_argument("subcommand", nargs="?", default="list", choices=["list", "add"])
    p.add_argument("--dir", default="")
    p.add_argument("--title", default="")
    p.add_argument("--description", default="")
    p.add_argument("--phase", default="development", choices=_pr.PHASES)
    p.add_argument("--severity", default="minor", choices=_pr.SEVERITIES)
    p.add_argument("--status", default="open")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)

    if ns.subcommand == "add":
        if not ns.title:
            print("pyfusa pr add: --title required", file=stderr)
            return EXIT_USAGE
        entry = _pr.add(project_root, ns.title, ns.description, ns.phase, ns.severity, ns.status)
        print(f"added {entry['id']}", file=stdout)
    else:
        reports = _pr.list_all(project_root)
        print(_pr.render_text(reports), file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# disposition
# ---------------------------------------------------------------------------

def cmd_disposition(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa disposition", add_help=True)
    p.add_argument("subcommand", nargs="?", default="list", choices=["list", "add"])
    p.add_argument("--dir", default="")
    p.add_argument("--rule", default="", help="rule ID to disposition")
    p.add_argument("--rationale", default="")
    p.add_argument("--reviewer", default="")
    p.add_argument("--action", default="accept", choices=_disp_mgmt.ACTIONS)
    p.add_argument("--reference", default="")
    p.add_argument("--fingerprint", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)

    if ns.subcommand == "add":
        if not ns.rule or not ns.rationale:
            print("pyfusa disposition add: --rule and --rationale required", file=stderr)
            return EXIT_USAGE
        entry = _disp_mgmt.add(project_root, ns.rule, ns.rationale, ns.reviewer, ns.action, ns.reference, ns.fingerprint)
        print(f"added disposition for {entry['ruleId']}", file=stdout)
    else:
        entries = _disp_mgmt.list_all(project_root)
        print(_disp_mgmt.render_text(entries), file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# impact
# ---------------------------------------------------------------------------

def cmd_impact(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa impact", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--from", default="HEAD", dest="from_ref")
    p.add_argument("--to", default="", dest="to_ref")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    report = _impact.run(project_root, cfg, ns.from_ref, ns.to_ref)

    w = stdout
    f_out = None
    out_path = ns.output
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa impact: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(report, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            changed = report.get("changedFiles", [])
            impacted = report.get("impactedReqs", [])
            stale = report.get("staleArtifacts", [])
            print(f"changed files: {len(changed)}  impacted reqs: {len(impacted)}  stale artifacts: {len(stale)}", file=w)
            for r in impacted:
                print(f"  {r['requirementID']}  affected: {', '.join(r['affectedFiles'])}", file=w)
            for a in stale:
                print(f"  stale: {a['file']}  ({a['reason']})", file=w)
    finally:
        if f_out:
            f_out.close()

    return EXIT_OK


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------

def cmd_metrics(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa metrics", add_help=True)
    p.add_argument("subcommand", nargs="?", default="show", choices=["show", "record"])
    p.add_argument("--dir", default="")
    p.add_argument("--version", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)

    if ns.subcommand == "record":
        snapshot = _metrics.record(project_root, cfg, ns.version)
        print(f"recorded snapshot  errors={snapshot['errorCount']}  warnings={snapshot['warningCount']}", file=stdout)
    else:
        data = _metrics.load(project_root)
        print(_metrics.render_text(data), file=stdout)

    return EXIT_OK


# ---------------------------------------------------------------------------
# safety-case
# ---------------------------------------------------------------------------

def cmd_safety_case(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa safety-case", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "md", "mermaid"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _safetycase.assemble(project_root, cfg)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa safety-case: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        elif ns.fmt == "md":
            w.write(_safetycase.to_markdown(doc))
            w.write("\n")
        else:
            w.write(_safetycase.to_mermaid(doc))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK if not doc.get("gaps") else EXIT_GATE_FAIL


# ---------------------------------------------------------------------------
# do178 / iso26262 / iec61508 / iso21434 / unece / iec62443 / slsa
# ---------------------------------------------------------------------------

def _cmd_gap_report(name: str, runner, render_fn, default_level: str, level_arg: str):
    def cmd(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
        p = argparse.ArgumentParser(prog=f"pyfusa {name}", add_help=True)
        p.add_argument("--dir", default="")
        p.add_argument(f"--{level_arg}", default=default_level)
        p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
        p.add_argument("--output", default="")
        try:
            ns = p.parse_args(args)
        except SystemExit:
            return EXIT_USAGE

        project_root = _resolve_dir(ns.dir)
        cfg = _load_config(project_root)
        level = getattr(ns, level_arg)
        doc = runner(project_root, cfg, level)

        out_path = ns.output
        w = stdout
        f_out = None
        if out_path:
            try:
                f_out = open(out_path, "w", encoding="utf-8")
                w = f_out
            except OSError as e:
                print(f"pyfusa {name}: {e}", file=stderr)
                return EXIT_RUNTIME
        try:
            if ns.fmt == "json":
                json.dump(doc, w, indent=2, ensure_ascii=False)
                w.write("\n")
            else:
                w.write(render_fn(doc))
                w.write("\n")
        finally:
            if f_out:
                f_out.close()

        if out_path:
            print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)

        return EXIT_GATE_FAIL if doc.get("summary", {}).get("gaps", 0) > 0 else EXIT_OK
    return cmd


cmd_do178 = _cmd_gap_report("do178", _do178.run, _do178.render_text, "DAL-B", "dal")
cmd_iso26262 = _cmd_gap_report("iso26262", _iso26262.run, _iso26262.render_text, "ASIL-B", "asil")
cmd_iec61508 = _cmd_gap_report("iec61508", _iec61508.run, _iec61508.render_text, "SIL-2", "sil")
cmd_iso21434 = _cmd_gap_report("iso21434", _iso21434.run, _iso21434.render_text, "CAL-2", "cal")
cmd_iec62443 = _cmd_gap_report("iec62443", _iec62443_gap.run, _iec62443_gap.render_text, "SL-2", "sl")
cmd_slsa = _cmd_gap_report("slsa", _slsa_gap.run, _slsa_gap.render_text, "L2", "level")


def cmd_unece(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa unece", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _unece.run(project_root, cfg)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa unece: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_unece.render_text(doc))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_GATE_FAIL if doc.get("summary", {}).get("gaps", 0) > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# sas / sci
# ---------------------------------------------------------------------------

def cmd_sas(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa sas", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--dal", default="DAL-B")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "text"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _sas.generate(project_root, cfg, ns.dal)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa sas: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_sas.render_text(doc))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK


def cmd_sci(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa sci", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="json", dest="fmt", choices=["json", "text"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _sci.generate(project_root, cfg)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa sci: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_sci.render_text(doc))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------

def cmd_coverage(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa coverage", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--dal", default="")
    p.add_argument("--asil", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _coverage.run(project_root, cfg, ns.dal, ns.asil)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa coverage: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            status = "PASS" if doc["passed"] else "FAIL"
            print(f"coverage: {doc['coveragePct']}%  type: {doc['coverageType']}  threshold: {doc['threshold']}%  [{status}]", file=w)
    finally:
        if f_out:
            f_out.close()

    if out_path:
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    return EXIT_OK if doc["passed"] else EXIT_GATE_FAIL


# ---------------------------------------------------------------------------
# template
# ---------------------------------------------------------------------------

def cmd_template(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa template", add_help=True)
    p.add_argument("name", nargs="?", default="", help=f"template name: {', '.join(_template.list_templates())}")
    p.add_argument("--dir", default="")
    p.add_argument("--force", action="store_true")
    p.add_argument("--list", action="store_true")
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    if ns.list or not ns.name:
        print("available templates:", file=stdout)
        for t in _template.list_templates():
            print(f"  {t}", file=stdout)
        return EXIT_OK

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    try:
        out_path = _template.generate(ns.name, project_root, cfg, force=ns.force)
        print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)
    except FileExistsError as e:
        print(f"pyfusa template: {e}", file=stderr)
        return EXIT_USAGE
    except ValueError as e:
        print(f"pyfusa template: {e}", file=stderr)
        return EXIT_USAGE
    return EXIT_OK


# ---------------------------------------------------------------------------
# misra
# ---------------------------------------------------------------------------

def cmd_misra(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa misra", add_help=True)
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    if ns.fmt == "json":
        json.dump(_misra.to_dict(), stdout, indent=2, ensure_ascii=False)
        print(file=stdout)
    else:
        print(_misra.render_text(), file=stdout)
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(args: list[str], stdout=sys.stdout, stderr=sys.stderr) -> int:
    p = argparse.ArgumentParser(prog="pyfusa verify", add_help=True)
    p.add_argument("--dir", default="")
    p.add_argument("--format", default="text", dest="fmt", choices=["text", "json"])
    p.add_argument("--output", default="")
    p.add_argument("--timeout", type=int, default=120)
    try:
        ns = p.parse_args(args)
    except SystemExit:
        return EXIT_USAGE

    project_root = _resolve_dir(ns.dir)
    cfg = _load_config(project_root)
    doc = _verify.run(project_root, cfg, timeout=ns.timeout)

    out_path = ns.output
    w = stdout
    f_out = None
    if out_path:
        try:
            f_out = open(out_path, "w", encoding="utf-8")
            w = f_out
        except OSError as e:
            print(f"pyfusa verify: {e}", file=stderr)
            return EXIT_RUNTIME
    try:
        if ns.fmt == "json":
            json.dump(doc, w, indent=2, ensure_ascii=False)
            w.write("\n")
        else:
            w.write(_verify.render_text(doc))
            w.write("\n")
    finally:
        if f_out:
            f_out.close()

    # Auto-save evidence bundle
    if not out_path or out_path.endswith(".json"):
        ev_path = os.path.join(project_root, _verify.EVIDENCE_FILE)
        if not out_path:
            _verify.save(doc, project_root)
            print(f"wrote {_verify.EVIDENCE_FILE}", file=stdout)
        elif out_path:
            print(f"wrote {os.path.relpath(out_path, project_root)}", file=stdout)

    s = doc.get("summary", {})
    return EXIT_GATE_FAIL if (s.get("failed", 0) + s.get("errored", 0)) > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

_COMMANDS = {
    "version": cmd_version,
    "capabilities": cmd_capabilities,
    "init": cmd_init,
    "check": cmd_check,
    "lint": cmd_lint,
    "analyze": cmd_analyze,
    "cyber": cmd_cyber,
    "report": cmd_report,
    "trace": cmd_trace,
    "verify": cmd_verify,
    "qualify": cmd_qualify,
    "release": cmd_release,
    "audit-pack": cmd_audit_pack,
    "fmea": cmd_fmea,
    "boundary": cmd_boundary,
    "coupling": cmd_coupling,
    "tara": cmd_tara,
    "hara": cmd_hara,
    "diff": cmd_diff,
    "badge": cmd_badge,
    "req": cmd_req,
    "fix": cmd_fix,
    "hooks": cmd_hooks,
    "sign": cmd_sign,
    "vuln": cmd_vuln,
    "pr": cmd_pr,
    "disposition": cmd_disposition,
    "impact": cmd_impact,
    "metrics": cmd_metrics,
    "safety-case": cmd_safety_case,
    "do178": cmd_do178,
    "iso26262": cmd_iso26262,
    "iec61508": cmd_iec61508,
    "iso21434": cmd_iso21434,
    "unece": cmd_unece,
    "iec62443": cmd_iec62443,
    "slsa": cmd_slsa,
    "sas": cmd_sas,
    "sci": cmd_sci,
    "coverage": cmd_coverage,
    "template": cmd_template,
    "misra": cmd_misra,
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
    print("Core commands:", file=w)
    print("  init          Initialise a pyfusa project configuration", file=w)
    print("  check         Run all safety checks (exits 1 on ERROR findings)", file=w)
    print("  lint          Run coding-standard checks only (LINT rules)", file=w)
    print("  analyze       Run static analysis checks only (ANA rules)", file=w)
    print("  cyber         Run cybersecurity analysis (CYBER001-020)", file=w)
    print("  report        Generate a safety compliance report (always exits 0)", file=w)
    print("  trace         Show requirements traceability matrix", file=w)
    print("  qualify       Run the tool qualification suite", file=w)
    print("  release       Generate SBOM, provenance, and artifact manifest", file=w)
    print("  audit-pack    Bundle all evidence artifacts into a single ZIP", file=w)
    print("  coverage      Analyse structural code coverage", file=w)
    print("\nSafety artefacts:", file=w)
    print("  fmea          Generate dFMEA table from public functions", file=w)
    print("  boundary      Generate component boundary diagram", file=w)
    print("  coupling      Analyse data/control coupling", file=w)
    print("  tara          Generate Threat Analysis and Risk Assessment (ISO 21434)", file=w)
    print("  hara          Manage Hazard Analysis and Risk Assessment", file=w)
    print("  safety-case   Assemble structured safety case from evidence", file=w)
    print("  sas           Generate Software Accomplishment Summary (DO-178C §11.20)", file=w)
    print("  sci           Generate Software Configuration Index (DO-178C §11.16)", file=w)
    print("\nCompliance gap reports:", file=w)
    print("  iso26262      ISO 26262 Part 6 compliance gap report", file=w)
    print("  iec61508      IEC 61508 Parts 1-3 compliance gap report", file=w)
    print("  do178         DO-178C Annex A compliance gap report", file=w)
    print("  iso21434      ISO 21434 cybersecurity compliance gap report", file=w)
    print("  unece         UN R.155 cybersecurity compliance gap report", file=w)
    print("  iec62443      IEC 62443 IACS cybersecurity compliance gap report", file=w)
    print("  slsa          SLSA supply-chain levels compliance gap report", file=w)
    print("  misra         Show MISRA C:2023 → py-FuSa rule mapping", file=w)
    print("\nDeveloper workflow:", file=w)
    print("  req           Show/import/export requirements (CSV)", file=w)
    print("  diff          Compare two check-report JSON files", file=w)
    print("  badge         Generate SVG status badge from a check report", file=w)
    print("  fix           Show auto-fixable findings with remediation guidance", file=w)
    print("  hooks         Install/remove git pre-commit hook", file=w)
    print("  sign          Sign or verify a file with HMAC-SHA256", file=w)
    print("  vuln          Scan installed packages for known vulnerabilities (OSV)", file=w)
    print("  disposition   Manage finding disposition entries", file=w)
    print("  pr            Manage software problem reports (DO-178C §11.17)", file=w)
    print("  impact        Analyse change impact on requirements", file=w)
    print("  metrics       Track safety metrics over time", file=w)
    print("  template      Generate safety documentation templates", file=w)
    print("\nTool:", file=w)
    print("  capabilities  Report tool capabilities", file=w)
    print("  version       Print the py-FuSa version", file=w)
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
