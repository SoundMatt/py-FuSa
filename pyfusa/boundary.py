"""Component boundary diagram generation."""

from __future__ import annotations

import ast
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Set

import pyfusa
from pyfusa.config import Config


def _python_files(root: str, cfg: Config) -> List[str]:
    source_dirs = cfg.source_dirs or ["."]
    paths: List[str] = []
    skip = {"__pycache__", ".git", ".tox", "venv", ".venv", "dist", "build"}
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


def _sanitize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


def _package_id(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    pkg = os.path.dirname(rel).replace(os.sep, ".") or "root"
    return _sanitize(pkg)


def _package_label(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    return os.path.dirname(rel).replace(os.sep, ".") or "root"


# fusa:req REQ-CLI009
def scan(project_root: str, cfg: Config) -> dict:
    """Build the boundary graph."""
    nodes: Dict[str, dict] = {}
    edges: Set[tuple] = set()
    known_internal: Set[str] = set()

    # First pass: collect all packages
    for path in _python_files(project_root, cfg):
        pkg_id = _package_id(path, project_root)
        pkg_label = _package_label(path, project_root)
        if pkg_id not in nodes:
            nodes[pkg_id] = {
                "id": pkg_id,
                "package": pkg_label,
                "trust_level": "internal",
                "exports": [],
            }
        known_internal.add(pkg_id)

    # Second pass: collect exports and import edges
    for path in _python_files(project_root, cfg):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                src = f.read()
            tree = ast.parse(src, filename=path)
        except SyntaxError:
            continue

        pkg_id = _package_id(path, project_root)
        pkg_label = _package_label(path, project_root)

        # Exports: public function and class names
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith("_"):
                    if pkg_id in nodes and node.name not in nodes[pkg_id]["exports"]:
                        nodes[pkg_id]["exports"].append(node.name)

        # Imports → edges
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target_id = _sanitize(alias.name.split(".")[0])
                    if target_id in known_internal and target_id != pkg_id:
                        edges.add((pkg_id, target_id))
                    elif target_id not in known_internal:
                        # External dependency
                        if target_id not in nodes:
                            nodes[target_id] = {
                                "id": target_id,
                                "package": alias.name,
                                "trust_level": "external",
                                "exports": [],
                            }
                        edges.add((pkg_id, target_id))
            elif isinstance(node, ast.ImportFrom) and node.module:
                target_id = _sanitize(node.module.split(".")[0])
                if target_id not in nodes:
                    nodes[target_id] = {
                        "id": target_id,
                        "package": node.module,
                        "trust_level": "external"
                        if target_id not in known_internal
                        else "internal",
                        "exports": [],
                    }
                if target_id != pkg_id:
                    edges.add((pkg_id, target_id))

    return {
        "nodes": list(nodes.values()),
        "edges": [{"from": f, "to": t} for f, t in sorted(edges)],
    }


# fusa:req REQ-CLI009
def to_dict(graph: dict, project_root: str, cfg: Config) -> dict:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    return {
        "schemaVersion": pyfusa.SPEC_VERSION,
        "kind": "boundary",
        "tool": pyfusa.TOOL,
        "toolVersion": pyfusa.VERSION,
        "language": pyfusa.LANGUAGE,
        "generatedAt": now,
        "format": "py-FuSa Boundary v1",
        "module": module,
        "nodes": graph["nodes"],
        "edges": graph["edges"],
    }


# fusa:req REQ-CLI009
def to_mermaid(graph: dict, module: str) -> str:
    lines = ["graph TD", f"    %% {module} component boundary"]
    for node in graph["nodes"]:
        label = node["package"]
        style = ":::external" if node["trust_level"] == "external" else ""
        lines.append(f'    {node["id"]}["{label}"]{style}')
    for edge in graph["edges"]:
        lines.append(f"    {edge['from']} --> {edge['to']}")
    lines.append("    classDef external fill:#f9f,stroke:#333,stroke-dasharray: 5 5")
    return "\n".join(lines)


# fusa:req REQ-CLI009
def to_dot(graph: dict, module: str) -> str:
    lines = ["digraph boundary {", f'  label="{module}";', "  rankdir=LR;"]
    for node in graph["nodes"]:
        shape = "box" if node["trust_level"] == "internal" else "ellipse"
        lines.append(f'  {node["id"]} [label="{node["package"]}" shape={shape}];')
    for edge in graph["edges"]:
        lines.append(f"  {edge['from']} -> {edge['to']};")
    lines.append("}")
    return "\n".join(lines)
