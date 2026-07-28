"""Content-quality baseline (x-FuSa spec §1.6/§1.6.1/§1.6.2) — FUSA-STUB001/002
detection, attestation, and the per-command --min-coverage/--strict/
--require-attestation gating it feeds."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
import pyfusa.content_quality as cq
from pyfusa.cli.main import run
from pyfusa.config import default

# ---------------------------------------------------------------------------
# Rule A — FUSA-STUB001 placeholder text
# ---------------------------------------------------------------------------


# fusa:test REQ-QUALBASE001
def test_is_placeholder_bracket_text():
    assert cq.is_placeholder("[describe the asset here]") is True


# fusa:test REQ-QUALBASE001
def test_is_placeholder_denylist_substrings():
    assert cq.is_placeholder("Example hazard — replace with real content") is True
    assert cq.is_placeholder("TBD") is True
    assert cq.is_placeholder("lorem ipsum dolor sit amet") is True
    assert cq.is_placeholder("please fill in this field") is True


# fusa:test REQ-QUALBASE001
def test_is_placeholder_real_text_not_flagged():
    assert cq.is_placeholder("uncaught exception propagates to caller") is False
    assert cq.is_placeholder("") is False


# fusa:test REQ-QUALBASE001
def test_scan_placeholder_always_error():
    entries = [{"id": "E-1", "failureMode": "TBD", "effect": "loss of service"}]
    findings = cq.scan_placeholder(entries, ["failureMode", "effect"], "fmea.json")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "FUSA-STUB001"
    assert f.severity == pyfusa.SEVERITY_ERROR
    assert f.category == pyfusa.CATEGORY_SAFETY
    assert f.location.file == "fmea.json"


# ---------------------------------------------------------------------------
# Rule B — FUSA-STUB002 blanket qualitative fallback
# ---------------------------------------------------------------------------


# fusa:test REQ-QUALBASE002
def test_distinct_value_ratio():
    assert cq.distinct_value_ratio(["a", "a", "a", "a"]) == 0.25
    assert cq.distinct_value_ratio(["a", "b", "c", "d"]) == 1.0
    assert cq.distinct_value_ratio([]) == 1.0
    assert cq.distinct_value_ratio(["", "", ""]) == 1.0


# fusa:test REQ-QUALBASE002
def test_scan_blanket_fallback_below_threshold_entries_not_flagged():
    """Fewer than 10 entries is never flagged, even with a single repeated value."""
    entries = [{"failureMode": "same"} for _ in range(9)]
    assert cq.scan_blanket_fallback(entries, ["failureMode"], "fmea.json") == []


# fusa:test REQ-QUALBASE002
def test_scan_blanket_fallback_flags_low_ratio():
    entries = [{"failureMode": "same"} for _ in range(12)]
    findings = cq.scan_blanket_fallback(entries, ["failureMode"], "fmea.json")
    assert len(findings) == 1
    assert findings[0].rule_id == "FUSA-STUB002"
    assert findings[0].severity == pyfusa.SEVERITY_WARNING


# fusa:test REQ-QUALBASE002
def test_scan_blanket_fallback_genuine_variety_not_flagged():
    entries = [{"failureMode": f"failure mode {i}"} for i in range(12)]
    assert cq.scan_blanket_fallback(entries, ["failureMode"], "fmea.json") == []


# ---------------------------------------------------------------------------
# §1.6.2 attestation
# ---------------------------------------------------------------------------


# fusa:test REQ-ATTEST001
def test_content_hash_excludes_header_and_attestation():
    doc_a = {
        "schemaVersion": "1.14",
        "generatedAt": "2026-01-01T00:00:00Z",
        "entries": [1, 2, 3],
        "attestation": {"status": "reviewed"},
    }
    doc_b = {
        "schemaVersion": "1.14",
        "generatedAt": "2026-07-27T00:00:00Z",
        "entries": [1, 2, 3],
        "attestation": {"status": "heuristic"},
    }
    assert cq.content_hash(doc_a) == cq.content_hash(doc_b)


# fusa:test REQ-ATTEST001
def test_content_hash_changes_with_content():
    doc_a = {"entries": [1, 2, 3]}
    doc_b = {"entries": [1, 2, 4]}
    assert cq.content_hash(doc_a) != cq.content_hash(doc_b)
    assert cq.content_hash(doc_a).startswith("sha256:")


# fusa:test REQ-ATTEST002
def test_attestation_valid_true():
    doc = {"entries": [1]}
    h = cq.content_hash(doc)
    attestation = {
        "status": "reviewed",
        "implementationAuthor": "auto",
        "independentReviewer": "Jane Doe <jane@example.com>",
        "reviewedAt": "2026-07-28T00:00:00Z",
        "contentHash": h,
    }
    assert cq.attestation_valid(attestation, h) is True


# fusa:test REQ-ATTEST002
def test_attestation_valid_heuristic_status_is_invalid():
    h = cq.content_hash({"entries": [1]})
    assert cq.attestation_valid({"status": "heuristic", "contentHash": h}, h) is False


# fusa:test REQ-ATTEST002
def test_attestation_valid_absent_status_defaults_invalid():
    h = cq.content_hash({"entries": [1]})
    assert cq.attestation_valid({"contentHash": h}, h) is False
    assert cq.attestation_valid(None, h) is False


# fusa:test REQ-ATTEST002
def test_attestation_valid_self_attestation_is_invalid():
    h = cq.content_hash({"entries": [1]})
    attestation = {
        "status": "reviewed",
        "implementationAuthor": "Jane Doe <jane@example.com>",
        "independentReviewer": "Jane Doe <jane@example.com>",
        "contentHash": h,
    }
    assert cq.attestation_valid(attestation, h) is False


# fusa:test REQ-ATTEST002
def test_attestation_valid_stale_hash_is_invalid():
    old_hash = cq.content_hash({"entries": [1]})
    new_hash = cq.content_hash({"entries": [1, 2]})
    attestation = {
        "status": "reviewed",
        "independentReviewer": "Jane Doe <jane@example.com>",
        "contentHash": old_hash,
    }
    assert cq.attestation_valid(attestation, new_hash) is False


# fusa:test REQ-ATTEST002
def test_attestation_valid_empty_reviewer_is_invalid():
    h = cq.content_hash({"entries": [1]})
    assert cq.attestation_valid({"status": "reviewed", "contentHash": h}, h) is False


# fusa:test REQ-ATTEST003
def test_load_existing_attestation_absent_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert cq.load_existing_attestation(tmpdir, "fmea.json") is None


# fusa:test REQ-ATTEST003
def test_load_existing_attestation_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "fmea.json"), "w") as f:
            json.dump({"attestation": {"status": "reviewed"}}, f)
        got = cq.load_existing_attestation(tmpdir, "fmea.json")
        assert got == {"status": "reviewed"}


# fusa:test REQ-ATTEST003
def test_load_existing_attestation_malformed_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "fmea.json"), "w") as f:
            f.write("{not valid json")
        assert cq.load_existing_attestation(tmpdir, "fmea.json") is None


# ---------------------------------------------------------------------------
# §1.6.2 attestation carry-forward across regeneration (MUST, x-FuSa spec
# v1.15.0 §1.6.2) — an artifact-producing command must not silently wipe a
# human's prior "reviewed" attestation the next time it rebuilds the
# artifact from scratch.
# ---------------------------------------------------------------------------


# fusa:test REQ-ATTEST003
def test_fmea_cli_carries_forward_reviewed_attestation_on_regeneration():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def only(x):\n    return x\n")
        fmea_path = os.path.join(tmpdir, "fmea.json")

        out1 = io.StringIO()
        run(["fmea", "--dir", tmpdir, "--format", "json", "--output", fmea_path],
            stdout=out1)
        with open(fmea_path, encoding="utf-8") as f:
            doc = json.load(f)
        current_hash = cq.content_hash(doc)
        doc["attestation"] = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "reviewedAt": "2026-07-28T00:00:00Z",
            "contentHash": current_hash,
        }
        with open(fmea_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

        # Regenerate against the *unchanged* source — a naive "always
        # rebuild from scratch" implementation would drop the attestation
        # here; the fix must carry it forward untouched.
        out2 = io.StringIO()
        run(["fmea", "--dir", tmpdir, "--format", "json", "--output", fmea_path],
            stdout=out2)
        with open(fmea_path, encoding="utf-8") as f:
            regenerated = json.load(f)
        assert regenerated.get("attestation", {}).get("status") == "reviewed"
        assert regenerated["attestation"]["contentHash"] == current_hash
        assert cq.attestation_valid(regenerated["attestation"], current_hash)


# fusa:test REQ-ATTEST003
def test_tara_cli_carries_forward_attestation_and_it_goes_stale_on_content_change():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "vuln.py"), "w") as f:
            f.write(
                "import subprocess\n"
                "def run_cmd(user_input):\n"
                "    subprocess.call(user_input, shell=True)\n"
            )
        tara_path = os.path.join(tmpdir, "tara.json")
        out1 = io.StringIO()
        run(["tara", "--dir", tmpdir, "--format", "json", "--output", tara_path],
            stdout=out1)
        with open(tara_path, encoding="utf-8") as f:
            doc = json.load(f)
        current_hash = cq.content_hash(doc)
        doc["attestation"] = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "reviewedAt": "2026-07-28T00:00:00Z",
            "contentHash": current_hash,
        }
        with open(tara_path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

        # Content changes (a second finding appears) — the carried-forward
        # attestation's contentHash no longer matches, so it must read as
        # stale (falls back to "heuristic" per §1.6.2), not silently valid.
        with open(os.path.join(tmpdir, "vuln.py"), "a") as f:
            f.write(
                "def run_cmd2(user_input):\n    subprocess.call(user_input, shell=True)\n"
            )
        out2 = io.StringIO()
        run(["tara", "--dir", tmpdir, "--format", "json", "--output", tara_path],
            stdout=out2)
        with open(tara_path, encoding="utf-8") as f:
            regenerated = json.load(f)
        # attestation object itself is preserved (never erased)...
        assert regenerated.get("attestation", {}).get("status") == "reviewed"
        # ...but is now stale against the freshly-generated content.
        new_hash = cq.content_hash(
            {k: v for k, v in regenerated.items() if k != "attestation"}
        )
        assert not cq.attestation_valid(regenerated["attestation"], new_hash)


# ---------------------------------------------------------------------------
# gate() — dispositions + attestation suppression + --require-attestation
# ---------------------------------------------------------------------------


# fusa:test REQ-QUALBASE003
# fusa:test REQ-QUALBASE004
def test_gate_stub001_always_fails_without_disposition():
    with tempfile.TemporaryDirectory() as tmpdir:
        findings = [
            pyfusa.Finding(
                rule_id="FUSA-STUB001",
                severity=pyfusa.SEVERITY_ERROR,
                message="placeholder",
                location=pyfusa.Location(file="fmea.json"),
            )
        ]
        kept, gate_failed = cq.gate(findings, tmpdir, None, "sha256:x", False)
        assert gate_failed is True
        assert len(kept) == 1


# fusa:test REQ-QUALBASE003
def test_gate_stub001_suppressed_by_disposition():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = pyfusa.Finding(
            rule_id="FUSA-STUB001",
            severity=pyfusa.SEVERITY_ERROR,
            message="placeholder",
            location=pyfusa.Location(file="fmea.json"),
        )
        with open(os.path.join(tmpdir, ".fusa-dispositions.json"), "w") as fh:
            json.dump(
                {
                    "dispositions": [
                        {"fingerprint": f.fingerprint, "status": "accepted"}
                    ]
                },
                fh,
            )
        kept, gate_failed = cq.gate([f], tmpdir, None, "sha256:x", False)
        assert gate_failed is False
        assert kept[0].disposition == "accepted"


# fusa:test REQ-QUALBASE004
def test_gate_stub002_advisory_by_default():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = pyfusa.Finding(
            rule_id="FUSA-STUB002",
            severity=pyfusa.SEVERITY_WARNING,
            message="blanket fallback",
            location=pyfusa.Location(file="fmea.json"),
        )
        kept, gate_failed = cq.gate([f], tmpdir, None, "sha256:x", False)
        assert gate_failed is False
        assert kept == [f]


# fusa:test REQ-QUALBASE004
def test_gate_stub002_escalates_under_require_attestation():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = pyfusa.Finding(
            rule_id="FUSA-STUB002",
            severity=pyfusa.SEVERITY_WARNING,
            message="blanket fallback",
            location=pyfusa.Location(file="fmea.json"),
        )
        kept, gate_failed = cq.gate([f], tmpdir, None, "sha256:x", True)
        assert gate_failed is True


# fusa:test REQ-QUALBASE004
def test_gate_stub002_suppressed_by_valid_attestation():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = pyfusa.Finding(
            rule_id="FUSA-STUB002",
            severity=pyfusa.SEVERITY_WARNING,
            message="blanket fallback",
            location=pyfusa.Location(file="fmea.json"),
        )
        current_hash = "sha256:abc123"
        attestation = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "contentHash": current_hash,
        }
        kept, gate_failed = cq.gate([f], tmpdir, attestation, current_hash, True)
        assert gate_failed is False
        assert kept == []


# ---------------------------------------------------------------------------
# End-to-end CLI: fmea/tara --min-coverage, --require-attestation
# ---------------------------------------------------------------------------


# fusa:test REQ-DFMEA006
def test_fmea_min_coverage_gate():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            # 1 analyzed public function, but let's make sure coveragePct < 100
            # is only possible if there are more public functions than analyzed;
            # here there's exactly one, so coveragePct is 100 and --min-coverage
            # 100 should pass, 101 is unreachable so use a value just below 100
            # after asserting the coverage is indeed 100 for a single function.
            f.write("def only(x):\n    return x\n")
        out = io.StringIO()
        code = run(
            ["fmea", "--dir", tmpdir, "--format", "json", "--min-coverage", "100"],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-DFMEA006
def test_fmea_coverage_pct_reflects_uncovered_functions():
    """componentsInProject counts every public function even when fmea only
    analyzes a subset (there is no subsetting today, but the denominator
    must still be independently correct)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def a():\n    return 1\ndef b():\n    return 2\n")
        out = io.StringIO()
        run(["fmea", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        assert doc["summary"]["componentsInProject"] == 2
        assert doc["summary"]["componentsAnalyzed"] == 2
        assert doc["summary"]["coveragePct"] == 100.0


# fusa:test REQ-DFMEA006
def test_fmea_excludes_test_tree_from_entries_and_denominator():
    """x-FuSa spec §9.2 fmea + §1.6 rule 4: a project whose sourceDirs
    resolve to a directory containing a nested test tree must not have its
    test functions counted as `entries[]` (componentsAnalyzed) while
    `componentsInProject` (trace --func-coverage's denominator) excludes
    that same tree — the mismatch inflates coveragePct past 100%. This is a
    non-trivial test-source tree fixture (x-FuSa spec §9.2's own note: a
    fixture with no src/test-equivalent directory cannot exercise the bug)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("def real_function(x):\n    return x + 1\n")
        tests_dir = os.path.join(tmpdir, "tests")
        os.makedirs(tests_dir)
        with open(os.path.join(tests_dir, "test_main.py"), "w") as f:
            f.write(
                "def test_something():\n    assert True\n"
                "def fixture_helper():\n    return 1\n"
                "def test_a():\n    assert True\n"
                "def test_b():\n    assert True\n"
            )
        out = io.StringIO()
        run(["fmea", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        items = {e["item"] for e in doc["entries"]}
        assert items == {"real_function"}
        s = doc["summary"]
        assert s["componentsAnalyzed"] == 1
        assert s["componentsInProject"] == 1
        assert s["coveragePct"] == 100.0
        assert s["coveragePct"] <= 100.0


# fusa:test REQ-DFMEA006
def test_fmea_coverage_pct_defensive_clamp():
    """x-FuSa spec §9.2 fmea MUST: coveragePct must never exceed 100 — a
    defensive backstop distinct from the exclusion-list fix above, covering
    any other future path that could over-count the numerator."""
    import pyfusa.fmea as fmea

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def only(x):\n    return x\n")
        cfg = default(project_name="p")
        summary = fmea._coverage(tmpdir, cfg, analyzed=999)
        assert summary["coveragePct"] == 100.0


# fusa:test REQ-TARA006
def test_tara_coverage_fields_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        run(["tara", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        s = doc["summary"]
        assert "assetsAnalyzed" in s
        assert "assetsInProject" in s
        assert "coveragePct" in s
        assert "assetInventoryMethod" in s


# fusa:test REQ-TARA006
def test_tara_impact_is_sfop_object():
    import pyfusa.tara as tara

    cfg = default(project_name="p")
    findings = [
        {
            "ruleId": "CYBER005",
            "message": "command injection",
            "location": {"file": "a.py", "line": 1},
        }
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = tara.build(findings, tmpdir, cfg)
    assert len(entries) == 1
    impact = entries[0]["impact"]
    assert set(impact.keys()) == {"safety", "financial", "operational", "privacy"}
    assert entries[0]["attackFeasibility"] in ("low", "medium", "high", "very-low")
    assert entries[0]["risk"] in ("low", "medium", "high", "critical")
    assert entries[0]["treatment"] in ("mitigate", "accept", "transfer", "avoid")


# fusa:test REQ-TARA006
def test_tara_impact_uses_closed_sfop_enum():
    """x-FuSa spec §9.2 tara closed enums (MUST): impact.{safety,financial,
    operational,privacy} MUST use critical|major|moderate|negligible — never
    the high/medium/low vocabulary reserved for attackFeasibility."""
    import pyfusa.tara as tara

    cfg = default(project_name="p")
    findings = [
        {
            "ruleId": rid,
            "message": "msg",
            "location": {"file": "a.py", "line": 1},
        }
        for rid in ("CYBER005", "CYBER015", "CYBER011", "CYBER016")
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = tara.build(findings, tmpdir, cfg)
    allowed = {"critical", "major", "moderate", "negligible"}
    for entry in entries:
        for axis in ("safety", "financial", "operational", "privacy"):
            assert entry["impact"][axis] in allowed, (entry["id"], axis)


# fusa:test REQ-TARA006
def test_tara_risk_critical_impact_not_downgraded_to_low():
    """x-FuSa spec §9.2 tara risk combination table (SHOULD): a threat whose
    worst SFOP axis is "critical" combined with "high" attackFeasibility
    (e.g. command/SQL injection) must rate "critical" risk, never fall
    through to the "low" default via a reversed matrix lookup."""
    import pyfusa.tara as tara

    cfg = default(project_name="p")
    findings = [
        {
            "ruleId": rid,
            "message": "msg",
            "location": {"file": "a.py", "line": 1},
        }
        for rid in ("CYBER005", "CYBER015")
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = tara.build(findings, tmpdir, cfg)
    for entry in entries:
        assert entry["attackFeasibility"] == "high"
        assert any(v == "critical" for v in entry["impact"].values())
        assert entry["risk"] == "critical", entry


# fusa:test REQ-TARA006
def test_tara_compute_risk_matrix_matches_spec_table():
    """Direct table check against x-FuSa spec §9.2's canonical risk
    combination table (Highest SFOP impact / attackFeasibility)."""
    from pyfusa.tara import _compute_risk

    cases = {
        ("critical", "high"): "critical",
        ("critical", "medium"): "critical",
        ("critical", "low"): "high",
        ("critical", "very-low"): "medium",
        ("major", "high"): "high",
        ("major", "medium"): "high",
        ("major", "low"): "medium",
        ("major", "very-low"): "medium",
        ("moderate", "high"): "medium",
        ("moderate", "medium"): "medium",
        ("moderate", "low"): "low",
        ("moderate", "very-low"): "low",
        ("negligible", "high"): "low",
        ("negligible", "very-low"): "low",
    }
    for (worst, feasibility), want in cases.items():
        impact = {"safety": worst, "financial": "negligible",
                   "operational": "negligible", "privacy": "negligible"}
        assert _compute_risk(impact, feasibility) == want, (worst, feasibility)


# fusa:test REQ-TARA006
def test_tara_coverage_pct_defensive_clamp():
    """x-FuSa spec §9.2 tara MUST: coveragePct must never exceed 100 — a
    defensive backstop over `_coverage`'s own computation."""
    import pyfusa.tara as tara

    cfg = default(project_name="p")
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def only(x):\n    return x\n")
        entries = [
            {"location": {"file": "mod.py", "line": 1}},
            {"location": {"file": "nonexistent_extra.py", "line": 1}},
        ]
        summary = tara._coverage(tmpdir, cfg, entries)
        assert summary["coveragePct"] == 100.0


# fusa:test REQ-QUALBASE005
# fusa:test REQ-QUALBASE006
def test_tara_stub002_real_trigger_from_repeated_rule():
    """10+ findings from the same CYBER rule id share one fixed `threat`
    string by construction — a real (not synthetic) trigger of rule B."""
    import pyfusa.tara as tara

    cfg = default(project_name="p")
    findings = [
        {
            "ruleId": "CYBER005",
            "message": f"command injection in file {i}",
            "location": {"file": f"f{i}.py", "line": 1},
        }
        for i in range(12)
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        entries = tara.build(findings, tmpdir, cfg)
        doc = tara.to_dict(entries, tmpdir, cfg)
        findings_out = tara.quality_findings(doc)
    assert any(f.rule_id == "FUSA-STUB002" for f in findings_out)


# fusa:test REQ-QUALBASE006
def test_tara_cli_require_attestation_gates_on_stub002():
    with tempfile.TemporaryDirectory() as tmpdir:
        report = {
            "kind": "check-report",
            "findings": [
                {
                    "ruleId": "CYBER005",
                    "severity": "WARNING",
                    "message": f"command injection {i}",
                    "location": {"file": f"f{i}.py", "line": 1},
                }
                for i in range(12)
            ],
        }
        report_path = os.path.join(tmpdir, "check-report.json")
        with open(report_path, "w") as f:
            json.dump(report, f)

        out = io.StringIO()
        code = run(
            ["tara", "--dir", tmpdir, "--format", "json", "--output", ""], stdout=out
        )
        assert code == pyfusa.EXIT_OK  # advisory by default

        out2 = io.StringIO()
        err2 = io.StringIO()
        code2 = run(
            [
                "tara",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--output",
                "",
                "--require-attestation",
            ],
            stdout=out2,
            stderr=err2,
        )
        assert code2 == pyfusa.EXIT_GATE_FAIL
        assert "FUSA-STUB002" in err2.getvalue()


# fusa:test REQ-ATTEST003
# fusa:test REQ-QUALBASE006
def test_fmea_cli_valid_attestation_suppresses_stub002():
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(12):
            with open(os.path.join(tmpdir, f"m{i}.py"), "w") as f:
                # Every function is niladic (no signals) so _derive_analysis
                # produces the identical fallback failureMode/effect/cause for
                # all of them — a real (not synthetic) rule-B trigger.
                f.write(f"def fn{i}():\n    pass\n")

        fmea_path = os.path.join(tmpdir, "fmea.json")
        out = io.StringIO()
        run(["fmea", "--dir", tmpdir, "--format", "json", "--output", fmea_path])

        with open(fmea_path, encoding="utf-8") as f:
            doc = json.load(f)

        current_hash = cq.content_hash(doc)
        doc["attestation"] = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "reviewedAt": "2026-07-28T00:00:00Z",
            "contentHash": current_hash,
        }
        with open(fmea_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)

        out2 = io.StringIO()
        err2 = io.StringIO()
        code2 = run(
            [
                "fmea",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--output",
                fmea_path,
                "--require-attestation",
            ],
            stdout=out2,
            stderr=err2,
        )
        assert code2 == pyfusa.EXIT_OK
        assert "FUSA-STUB002" not in err2.getvalue()


# ---------------------------------------------------------------------------
# `check` does NOT gate on FUSA-STUB001/002 (x-FuSa spec §1.6.1 "Who runs
# this" — MUST). Detection runs inside each artifact-producing command
# (fmea/hara/tara/safety-case/sas — see the per-command
# quality_findings()/quality_gate tests above), gating that command's own
# exit code. `check` analyzes source/config; it does not read sibling
# evidence artifacts like fmea.json/tara.json/safety-case.json as part of
# this section — a stale/stub artifact committed to the repo must not fail
# an unrelated `check` run.
# ---------------------------------------------------------------------------


# fusa:test REQ-QUALBASE001
# fusa:test REQ-QUALBASE002
def test_check_command_does_not_surface_stub_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write(
                '{"project":{"name":"t"},"standard":"iso26262","asil":"ASIL-B"}'
            )
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            f.write('{"requirements": []}')
        with open(os.path.join(tmpdir, "safety-case.json"), "w") as f:
            json.dump(
                {"nodes": [{"id": "G1", "type": "goal", "text": "TBD"}]}, f
            )
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        rule_ids = {f["ruleId"] for f in doc["findings"]}
        assert "FUSA-STUB001" not in rule_ids
        assert "FUSA-STUB002" not in rule_ids
