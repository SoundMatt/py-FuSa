"""Report rendering: text, JSON, HTML, SARIF, MD (§4, §3)."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from typing import TextIO

import pyfusa
from pyfusa.config import Config
from pyfusa.engine import RunResult

_VALID_FORMATS = {"text", "json", "html", "sarif", "md"}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_envelope(project_root: str, cfg: Config, result: RunResult, error: dict | None = None) -> dict:
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION
    d: dict = {
        "schemaVersion": SPEC_VERSION,
        "kind": "check-report",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": _now_iso(),
        "projectRoot": os.path.abspath(project_root),
        "project": cfg.project.name,
        "standard": cfg.standard,
        "findings": [f.to_dict() for f in result.findings],
        "summary": result.summary(),
    }
    if cfg.asil:
        d["asil"] = cfg.asil
    elif cfg.sil:
        d["sil"] = cfg.sil
    elif cfg.dal:
        d["dal"] = cfg.dal
    if error:
        d["error"] = error
    return d


def render_text(result: RunResult, project_root: str) -> str:
    lines: list[str] = []
    for f in result.findings:
        disp = f" [{f.disposition}]" if f.disposition else ""
        loc = f.location.file
        if f.location.line:
            loc += f":{f.location.line}"
        lines.append(f"{f.severity}  {f.rule_id}  {loc}  {f.message}{disp}")
        if f.remediation:
            lines.append(f"       remediation: {f.remediation}")

    summary = result.summary()
    lines.append("")
    lines.append(
        f"Summary: {summary['errors']} errors, {summary['warnings']} warnings, "
        f"{summary['infos']} infos ({summary['total']} total)"
    )
    return "\n".join(lines)


def render_md(result: RunResult, project_root: str) -> str:
    lines: list[str] = ["# py-FuSa Check Report", ""]
    lines.append("| Severity | Rule | Location | Message |")
    lines.append("|---|---|---|---|")
    for f in result.findings:
        loc = f.location.file
        if f.location.line:
            loc += f":{f.location.line}"
        msg = f.message.replace("|", "\\|")
        lines.append(f"| {f.severity} | `{f.rule_id}` | `{loc}` | {msg} |")
    summary = result.summary()
    lines.append("")
    lines.append(
        f"**Summary:** {summary['errors']} errors, {summary['warnings']} warnings, "
        f"{summary['infos']} infos"
    )
    return "\n".join(lines)


def render_html(result: RunResult, project_root: str) -> str:
    rows: list[str] = []
    for f in result.findings:
        sev_class = f.severity.lower()
        loc = html.escape(f.location.file)
        if f.location.line:
            loc += f":{f.location.line}"
        rows.append(
            f'<tr class="{sev_class}">'
            f'<td>{html.escape(f.severity)}</td>'
            f'<td>{html.escape(f.rule_id)}</td>'
            f'<td>{loc}</td>'
            f'<td>{html.escape(f.message)}</td>'
            f'<td>{html.escape(f.remediation)}</td>'
            f'</tr>'
        )
    summary = result.summary()
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>py-FuSa Check Report</title>
<style>
body {{font-family:monospace;}}
table {{border-collapse:collapse;width:100%;}}
th,td {{border:1px solid #ccc;padding:4px 8px;text-align:left;}}
tr.error td:first-child {{color:#c00;font-weight:bold;}}
tr.warning td:first-child {{color:#c80;font-weight:bold;}}
</style></head>
<body>
<h1>py-FuSa Check Report</h1>
<p>Errors: {summary['errors']} &nbsp; Warnings: {summary['warnings']} &nbsp; Infos: {summary['infos']}</p>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Remediation</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</body></html>
"""


def render_sarif(result: RunResult, project_root: str, cfg: Config) -> dict:
    """§2.9 SARIF 2.1.0 with physicalLocation on every result."""
    from pyfusa import TOOL, VERSION

    # Build rules map
    rules_by_id: dict[str, pyfusa.Finding] = {}
    for f in result.findings:
        if f.rule_id not in rules_by_id:
            rules_by_id[f.rule_id] = f

    sarif_rules = []
    for rid, f in sorted(rules_by_id.items()):
        entry: dict = {
            "id": rid,
            "shortDescription": {"text": f.message},
        }
        props: dict = {"category": f.category}
        if f.standard:
            props["standard"] = f.standard
        if f.clause:
            props["clause"] = f.clause
        entry["properties"] = props
        sarif_rules.append(entry)

    sarif_results = []
    for f in result.findings:
        level = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}.get(f.severity, "note")
        sarif_result: dict = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.location.line or 1},
                },
            }],
            "fingerprints": {"sha256/v1": f.fingerprint},
        }
        props: dict = {"category": f.category, "remediation": f.remediation}
        if f.standard:
            props["standard"] = f.standard
        if f.clause:
            props["clause"] = f.clause
        if f.disposition:
            props["disposition"] = f.disposition
        sarif_result["properties"] = props
        sarif_results.append(sarif_result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL,
                    "version": VERSION,
                    "rules": sarif_rules,
                },
            },
            "results": sarif_results,
        }],
    }


def render(w: TextIO, result: RunResult, fmt: str, project_root: str, cfg: Config) -> None:
    """Write formatted report to w."""
    fmt = (fmt or "text").lower()
    if fmt not in _VALID_FORMATS:
        fmt = "text"

    if fmt == "text":
        w.write(render_text(result, project_root))
        w.write("\n")
    elif fmt == "json":
        doc = _check_envelope(project_root, cfg, result)
        json.dump(doc, w, indent=2, ensure_ascii=False)
        w.write("\n")
    elif fmt == "html":
        w.write(render_html(result, project_root))
    elif fmt == "sarif":
        doc = render_sarif(result, project_root, cfg)
        json.dump(doc, w, indent=2, ensure_ascii=False)
        w.write("\n")
    elif fmt == "md":
        w.write(render_md(result, project_root))
        w.write("\n")
