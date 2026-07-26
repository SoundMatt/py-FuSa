"""SBOM generation, provenance, and artifact manifest (§7)."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from typing import Optional

from pyfusa.config import Config


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _get_vcs_revision(project_root: str) -> tuple[str, bool]:
    """Return (commit_hash, is_modified) from git."""
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root, stderr=subprocess.DEVNULL, text=True
        ).strip()
        dirty = subprocess.call(
            ["git", "diff", "--quiet"],
            cwd=project_root, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        ) != 0
        return rev, dirty
    except (OSError, subprocess.CalledProcessError):
        return "", False


def _pkg_hash(dist_name: str) -> str:
    """Return sha256:<hex> of the package METADATA file (§2.7 hash convention)."""
    try:
        dist = importlib.metadata.distribution(dist_name)
        metadata_text = dist.read_text("METADATA")
        if metadata_text:
            h = hashlib.sha256(metadata_text.encode("utf-8", errors="replace")).hexdigest()
            return f"sha256:{h}"
    except Exception:
        pass
    return ""


def _collect_dependencies() -> list[dict]:
    """Collect installed Python package dependencies."""
    deps = []
    try:
        pkgs = importlib.metadata.packages_distributions()
        seen: set[str] = set()
        for dist_names in pkgs.values():
            for dist_name in dist_names:
                if dist_name in seen:
                    continue
                seen.add(dist_name)
                try:
                    meta = importlib.metadata.metadata(dist_name)
                    version = meta.get("Version", "")
                    if version:
                        pkg_hash = _pkg_hash(dist_name)
                        entry: dict = {"name": dist_name, "version": version}
                        if pkg_hash:
                            entry["hash"] = pkg_hash
                        deps.append(entry)
                except importlib.metadata.PackageNotFoundError:
                    pass
    except Exception:
        pass
    return sorted(deps, key=lambda d: d["name"].lower())


def generate_sbom(project_root: str, cfg: Config) -> dict:
    """§7 sbom.json payload."""
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))
    components = _collect_dependencies()

    return {
        "schemaVersion": SPEC_VERSION,
        "kind": "sbom",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "format": "x-FuSa SBOM v1",
        "module": module,
        "components": [
            {k: v for k, v in c.items() if k in ("name", "version", "hash")}
            for c in components
        ],
    }


def generate_provenance(project_root: str, cfg: Config) -> dict:
    """§7 provenance.json payload."""
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    rev, modified = _get_vcs_revision(project_root)
    module = cfg.project.name or os.path.basename(os.path.abspath(project_root))

    return {
        "schemaVersion": SPEC_VERSION,
        "kind": "provenance",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "format": "x-FuSa provenance v1",
        "module": module,
        "builder": os.environ.get("CI_SERVER_NAME", "local"),
        "vcsRevision": rev,
        "vcsModified": modified,
        "os": platform.system().lower(),
        "arch": platform.machine().lower(),
        "pythonVersion": platform.python_version(),
    }


def generate_artifact_manifest(output_dir: str, artifacts: list[str], project_root: str, cfg: Config) -> dict:
    """§7 artifact-manifest.json payload."""
    from pyfusa import LANGUAGE, SPEC_VERSION, TOOL, VERSION
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    artifact_entries = []
    for artifact in artifacts:
        abs_path = os.path.join(output_dir, artifact) if not os.path.isabs(artifact) else artifact
        sha = _sha256_file(abs_path)
        rel = os.path.relpath(abs_path, output_dir).replace("\\", "/")
        if sha:
            artifact_entries.append({"path": rel, "sha256": sha})

    return {
        "schemaVersion": SPEC_VERSION,
        "kind": "artifact-manifest",
        "tool": TOOL,
        "toolVersion": VERSION,
        "language": LANGUAGE,
        "generatedAt": now,
        "format": "x-FuSa manifest v1",
        "artifacts": artifact_entries,
    }


def run_release(project_root: str, cfg: Config, output_dir: Optional[str] = None) -> list[str]:
    """Generate sbom.json, provenance.json, artifact-manifest.json. Returns list of written paths."""
    if output_dir is None:
        output_dir = project_root
    os.makedirs(output_dir, exist_ok=True)

    written: list[str] = []

    sbom = generate_sbom(project_root, cfg)
    sbom_path = os.path.join(output_dir, "sbom.json")
    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)
        f.write("\n")
    written.append(sbom_path)

    prov = generate_provenance(project_root, cfg)
    prov_path = os.path.join(output_dir, "provenance.json")
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(prov, f, indent=2, ensure_ascii=False)
        f.write("\n")
    written.append(prov_path)

    manifest = generate_artifact_manifest(output_dir, ["sbom.json", "provenance.json"], project_root, cfg)
    manifest_path = os.path.join(output_dir, "artifact-manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    written.append(manifest_path)

    return written
