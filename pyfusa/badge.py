"""SVG status badge generation."""

from __future__ import annotations

import json


def _status(errors: int, warnings: int) -> tuple:
    if errors > 0:
        return "fail", f"{errors} errors", "#e05d44"
    if warnings > 0:
        return "warn", f"{warnings} warnings", "#dfb317"
    return "pass", "passing", "#4c1"


def from_report(report_path: str) -> str:
    with open(report_path, encoding="utf-8") as f:
        doc = json.load(f)
    summary = doc.get("summary", {})
    errors = summary.get("errors", 0)
    warnings = summary.get("warnings", 0)
    return generate(errors, warnings)


def generate(errors: int = 0, warnings: int = 0, label: str = "py-fusa") -> str:
    _, message, color = _status(errors, warnings)
    label_width = max(len(label) * 7, 50)
    msg_width = max(len(message) * 7, 50)
    total_width = label_width + msg_width + 20

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width + 10}" height="20" fill="#555"/>
    <rect x="{label_width + 10}" width="{msg_width + 10}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{(label_width + 10) // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{(label_width + 10) // 2}" y="14">{label}</text>
    <text x="{label_width + 10 + msg_width // 2}" y="15" fill="#010101" fill-opacity=".3">{message}</text>
    <text x="{label_width + 10 + msg_width // 2}" y="14">{message}</text>
  </g>
</svg>"""
    return svg
