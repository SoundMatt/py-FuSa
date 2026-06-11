"""Vulnerability scanning via OSV API (https://api.osv.dev/v1/querybatch)."""

from __future__ import annotations

import importlib.metadata
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List

import pyfusa
from pyfusa.config import Config

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _installed_packages() -> List[dict]:
    pkgs = []
    try:
        dists = importlib.metadata.packages_distributions()
        seen: set = set()
        for names in dists.values():
            for name in names:
                if name in seen:
                    continue
                seen.add(name)
                try:
                    meta = importlib.metadata.metadata(name)
                    version = meta.get("Version", "")
                    if version:
                        pkgs.append({"name": name, "version": version})
                except Exception:
                    pass
    except Exception:
        pass
    return pkgs


def _query_osv(packages: List[dict], timeout: int = 30) -> List[dict]:
    queries = [
        {"version": p["version"], "package": {"name": p["name"], "ecosystem": "PyPI"}}
        for p in packages
    ]
    payload = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("results", [])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return []


def scan(project_root: str, cfg: Config, timeout: int = 30) -> dict:
    packages = _installed_packages()
    results = _query_osv(packages, timeout=timeout)

    findings = []
    for i, result in enumerate(results):
        if i >= len(packages):
            break
        pkg = packages[i]
        vulns = result.get("vulns", [])
        for v in vulns:
            findings.append({
                "module": pkg["name"],
                "version": pkg["version"],
                "id": v.get("id", ""),
                "aliases": v.get("aliases", []),
                "summary": v.get("summary", ""),
                "call_graph": [],
            })

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "vuln-report",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa Vulnerability Report v1",
        "module": module,
        "scanned": len(packages),
        "findings": findings,
    }
