"""Tests for compliance/iec62443.py and compliance/slsa.py — coverage boost."""

from __future__ import annotations

import json
import os
import tempfile

from pyfusa.config import default
from pyfusa.cli.main import run
import io


# ---------------------------------------------------------------------------
# compliance/iec62443.py
# ---------------------------------------------------------------------------

def test_iec62443_run_empty_dir():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg)
        assert doc["kind"] == "iec62443-gap-report"
        assert doc["standard"] == "iec62443"
        assert doc["sl"] == "SL-2"
        assert doc["summary"]["total"] == 12
        assert doc["summary"]["gaps"] > 0
        assert isinstance(doc["objectives"], list)
        assert len(doc["objectives"]) == 12


def test_iec62443_run_sl1():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg, sl="SL-1")
        assert doc["sl"] == "SL-1"
        # SL-2/SL-3 objectives are "partial" when project is only SL-1
        partials = [o for o in doc["objectives"] if o["status"] == "partial"]
        assert len(partials) > 0


def test_iec62443_run_sl4():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg, sl="SL-4")
        assert doc["sl"] == "SL-4"
        partials = [o for o in doc["objectives"] if o["status"] == "partial"]
        assert len(partials) == 0  # at highest level, nothing is partial


def test_iec62443_run_with_evidence():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        # Create several evidence files
        for name in [".fusa.json", ".fusa-reqs.json", "SECURITY.md", "check-report.json"]:
            open(os.path.join(tmpdir, name), "w").close()
        doc = iec_run(tmpdir, cfg)
        satisfied = [o for o in doc["objectives"] if o["status"] == "satisfied"]
        assert len(satisfied) >= 3


def test_iec62443_run_full_evidence():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        for name in [".fusa-iec62443.json", "vuln.json", "tara.json",
                     "check-report.json", ".fusa.json", ".fusa-reqs.json",
                     "boundary.json", "SECURITY.md", "INCIDENT-RESPONSE.md",
                     "sbom.json", "qualify-report.json", "audit-pack.zip"]:
            open(os.path.join(tmpdir, name), "w").close()
        doc = iec_run(tmpdir, cfg)
        satisfied = [o for o in doc["objectives"] if o["status"] == "satisfied"]
        # SL-3 objectives (62443-11, 62443-12) are "partial" at SL-2 regardless of evidence
        assert len(satisfied) == 10


def test_iec62443_run_sl3_partials():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg, sl="SL-2")
        # SL-3/SL-4 objectives should be partial at SL-2
        partials = [o for o in doc["objectives"] if o["status"] == "partial"]
        assert len(partials) >= 1


def test_iec62443_render_text():
    from pyfusa.compliance.iec62443 import run as iec_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="testproj")
        doc = iec_run(tmpdir, cfg)
        text = render_text(doc)
        assert "IEC 62443" in text
        assert "testproj" in text
        assert "SL-2" in text
        assert "satisfied=" in text
        assert "gaps=" in text


def test_iec62443_render_text_satisfied_marker():
    from pyfusa.compliance.iec62443 import run as iec_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        for name in [".fusa.json", ".fusa-reqs.json", "SECURITY.md"]:
            open(os.path.join(tmpdir, name), "w").close()
        doc = iec_run(tmpdir, cfg)
        text = render_text(doc)
        assert "✓" in text
        assert "✗" in text


def test_iec62443_render_text_partial_marker():
    from pyfusa.compliance.iec62443 import run as iec_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg, sl="SL-2")
        text = render_text(doc)
        assert "–" in text  # partial marker


def test_iec62443_schema_fields():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg)
        assert "schemaVersion" in doc
        assert "tool" in doc
        assert "toolVersion" in doc
        assert "generatedAt" in doc
        assert "projectRoot" in doc
        for obj in doc["objectives"]:
            assert "id" in obj
            assert "clause" in obj
            assert "title" in obj
            assert "slMin" in obj
            assert "status" in obj
            assert "evidence" in obj


def test_iec62443_gap_has_remediation():
    from pyfusa.compliance.iec62443 import run as iec_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = iec_run(tmpdir, cfg)
        gaps = [o for o in doc["objectives"] if o["status"] == "gap"]
        assert all("remediation" in g for g in gaps)


def test_iec62443_cli_text():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["iec62443", "--dir", tmpdir], stdout=out, stderr=err)
    assert code in (0, 1, 3)
    assert "IEC 62443" in out.getvalue()


def test_iec62443_cli_json():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["iec62443", "--dir", tmpdir, "--format", "json"], stdout=out, stderr=err)
    assert code in (0, 1, 3)
    doc = json.loads(out.getvalue())
    assert doc["kind"] == "iec62443-gap-report"


def test_iec62443_cli_sl_flag():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["iec62443", "--dir", tmpdir, "--sl", "SL-1", "--format", "json"],
                   stdout=out, stderr=err)
    assert code in (0, 1, 3)
    doc = json.loads(out.getvalue())
    assert doc["sl"] == "SL-1"


def test_iec62443_cli_output_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "iec62443.json")
        out = io.StringIO()
        err = io.StringIO()
        code = run(["iec62443", "--dir", tmpdir, "--format", "json", "--output", out_path],
                   stdout=out, stderr=err)
        assert code in (0, 1, 3)
        with open(out_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "iec62443-gap-report"


# ---------------------------------------------------------------------------
# compliance/slsa.py
# ---------------------------------------------------------------------------

def test_slsa_run_empty_dir():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg)
        assert doc["kind"] == "slsa-gap-report"
        assert doc["standard"] == "slsa"
        assert doc["level"] == "L2"
        assert doc["summary"]["total"] == 10
        assert isinstance(doc["objectives"], list)
        assert len(doc["objectives"]) == 10


def test_slsa_run_l1():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg, level="L1")
        assert doc["level"] == "L1"
        # L2/L3/L4 objectives are "partial" when project is only L1
        partials = [o for o in doc["objectives"] if o["status"] == "partial"]
        assert len(partials) > 0


def test_slsa_run_l4():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg, level="L4")
        assert doc["level"] == "L4"


def test_slsa_run_with_basic_evidence():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        open(os.path.join(tmpdir, "pyproject.toml"), "w").close()
        os.makedirs(os.path.join(tmpdir, ".git"), exist_ok=True)
        open(os.path.join(tmpdir, "provenance.json"), "w").write(
            json.dumps({"builder": "github-actions", "vcsRevision": "abc123"})
        )
        doc = slsa_run(tmpdir, cfg)
        satisfied = [o for o in doc["objectives"] if o["status"] == "satisfied"]
        assert len(satisfied) >= 3


def test_slsa_run_with_l2_evidence():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        open(os.path.join(tmpdir, "pyproject.toml"), "w").close()
        os.makedirs(os.path.join(tmpdir, ".git"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, ".github/workflows"), exist_ok=True)
        open(os.path.join(tmpdir, "provenance.json"), "w").write(
            json.dumps({"builder": "github-actions", "vcsRevision": "abc123"})
        )
        open(os.path.join(tmpdir, "sbom.json"), "w").close()
        open(os.path.join(tmpdir, "qualify-report.json"), "w").close()
        doc = slsa_run(tmpdir, cfg)
        satisfied = [o for o in doc["objectives"] if o["status"] == "satisfied"]
        assert len(satisfied) >= 5


def test_slsa_run_codeowners():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        os.makedirs(os.path.join(tmpdir, ".github"), exist_ok=True)
        open(os.path.join(tmpdir, ".github", "CODEOWNERS"), "w").close()
        doc = slsa_run(tmpdir, cfg, level="L3")
        slsa7 = next(o for o in doc["objectives"] if o["id"] == "SLSA-7")
        assert slsa7["status"] == "satisfied"


def test_slsa_run_branch_protection():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        os.makedirs(os.path.join(tmpdir, ".github"), exist_ok=True)
        open(os.path.join(tmpdir, ".github", "branch-protection.json"), "w").close()
        doc = slsa_run(tmpdir, cfg, level="L4")
        slsa9 = next(o for o in doc["objectives"] if o["id"] == "SLSA-9")
        assert slsa9["status"] == "satisfied"


def test_slsa_run_provenance_no_builder():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        open(os.path.join(tmpdir, "provenance.json"), "w").write(
            json.dumps({"vcsRevision": "abc"})
        )
        doc = slsa_run(tmpdir, cfg, level="L2")
        slsa5 = next(o for o in doc["objectives"] if o["id"] == "SLSA-5")
        assert slsa5["status"] == "gap"


def test_slsa_run_provenance_missing_file():
    from pyfusa.compliance.slsa import _provenance_has_builder
    with tempfile.TemporaryDirectory() as tmpdir:
        assert _provenance_has_builder(tmpdir) is False


def test_slsa_run_provenance_bad_json():
    from pyfusa.compliance.slsa import _provenance_has_builder
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, "provenance.json"), "w").write("not json")
        assert _provenance_has_builder(tmpdir) is False


def test_slsa_codeowners_variants():
    from pyfusa.compliance.slsa import _codeowners_present
    with tempfile.TemporaryDirectory() as tmpdir:
        assert not _codeowners_present(tmpdir)
        open(os.path.join(tmpdir, "CODEOWNERS"), "w").close()
        assert _codeowners_present(tmpdir)


def test_slsa_branch_prot_rulesets():
    from pyfusa.compliance.slsa import _branch_prot_present
    with tempfile.TemporaryDirectory() as tmpdir:
        assert not _branch_prot_present(tmpdir)
        os.makedirs(os.path.join(tmpdir, ".github"), exist_ok=True)
        open(os.path.join(tmpdir, ".github", "rulesets.json"), "w").close()
        assert _branch_prot_present(tmpdir)


def test_slsa_render_text():
    from pyfusa.compliance.slsa import run as slsa_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="testproj")
        doc = slsa_run(tmpdir, cfg)
        text = render_text(doc)
        assert "SLSA" in text
        assert "testproj" in text
        assert "L2" in text
        assert "satisfied=" in text
        assert "gaps=" in text


def test_slsa_render_text_markers():
    from pyfusa.compliance.slsa import run as slsa_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        os.makedirs(os.path.join(tmpdir, ".git"), exist_ok=True)
        open(os.path.join(tmpdir, "pyproject.toml"), "w").close()
        doc = slsa_run(tmpdir, cfg)
        text = render_text(doc)
        assert "✓" in text
        assert "✗" in text


def test_slsa_render_text_partial():
    from pyfusa.compliance.slsa import run as slsa_run, render_text
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg, level="L2")
        text = render_text(doc)
        assert "–" in text


def test_slsa_schema_fields():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg)
        assert "schemaVersion" in doc
        assert "tool" in doc
        assert "toolVersion" in doc
        assert "generatedAt" in doc
        assert "projectRoot" in doc
        for obj in doc["objectives"]:
            assert "id" in obj
            assert "level" in obj
            assert "title" in obj
            assert "status" in obj
            assert "evidence" in obj


def test_slsa_gap_has_remediation():
    from pyfusa.compliance.slsa import run as slsa_run
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="proj")
        doc = slsa_run(tmpdir, cfg)
        gaps = [o for o in doc["objectives"] if o["status"] == "gap"]
        assert all("remediation" in g for g in gaps)


def test_slsa_cli_text():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["slsa", "--dir", tmpdir], stdout=out, stderr=err)
    assert code in (0, 1, 3)
    assert "SLSA" in out.getvalue()


def test_slsa_cli_json():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["slsa", "--dir", tmpdir, "--format", "json"], stdout=out, stderr=err)
    assert code in (0, 1, 3)
    doc = json.loads(out.getvalue())
    assert doc["kind"] == "slsa-gap-report"


def test_slsa_cli_level_flag():
    out = io.StringIO()
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(["slsa", "--dir", tmpdir, "--level", "L1", "--format", "json"],
                   stdout=out, stderr=err)
    assert code in (0, 1, 3)
    doc = json.loads(out.getvalue())
    assert doc["level"] == "L1"


def test_slsa_cli_output_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "slsa.json")
        out = io.StringIO()
        err = io.StringIO()
        code = run(["slsa", "--dir", tmpdir, "--format", "json", "--output", out_path],
                   stdout=out, stderr=err)
        assert code in (0, 1, 3)
        with open(out_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "slsa-gap-report"
