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

        with open(fmea_path) as f:
            doc = json.load(f)

        current_hash = cq.content_hash(doc)
        doc["attestation"] = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "reviewedAt": "2026-07-28T00:00:00Z",
            "contentHash": current_hash,
        }
        with open(fmea_path, "w") as f:
            json.dump(doc, f)

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
# check-engine FUSA-STUB001/002 rules (defense-in-depth over committed files)
# ---------------------------------------------------------------------------


# fusa:test REQ-QUALBASE007
def test_evidence_fusastub001_rule_flags_committed_placeholder():
    from pyfusa.rules.evidence import FUSASTUB001

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "fmea.json"), "w") as f:
            json.dump(
                {
                    "entries": [
                        {"id": "FMEA-001", "failureMode": "TBD", "effect": "x"}
                    ]
                },
                f,
            )
        cfg = default()
        findings = FUSASTUB001().run(tmpdir, cfg)
        assert any(f.rule_id == "FUSA-STUB001" for f in findings)


# fusa:test REQ-QUALBASE007
def test_evidence_fusastub001_rule_no_artifacts_present():
    from pyfusa.rules.evidence import FUSASTUB001

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        assert FUSASTUB001().run(tmpdir, cfg) == []


# fusa:test REQ-QUALBASE008
def test_evidence_fusastub002_rule_flags_committed_blanket_fallback():
    from pyfusa.rules.evidence import FUSASTUB002

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "tara.json"), "w") as f:
            json.dump(
                {
                    "threats": [
                        {"id": f"TARA-{i:03d}", "threat": "same threat"}
                        for i in range(12)
                    ]
                },
                f,
            )
        cfg = default()
        findings = FUSASTUB002().run(tmpdir, cfg)
        assert any(f.rule_id == "FUSA-STUB002" for f in findings)


# fusa:test REQ-QUALBASE008
def test_evidence_fusastub002_rule_suppressed_by_attestation():
    from pyfusa.rules.evidence import FUSASTUB002

    with tempfile.TemporaryDirectory() as tmpdir:
        doc = {
            "threats": [
                {"id": f"TARA-{i:03d}", "threat": "same threat"} for i in range(12)
            ]
        }
        current_hash = cq.content_hash(doc)
        doc["attestation"] = {
            "status": "reviewed",
            "implementationAuthor": "auto",
            "independentReviewer": "Jane Doe <jane@example.com>",
            "contentHash": current_hash,
        }
        with open(os.path.join(tmpdir, "tara.json"), "w") as f:
            json.dump(doc, f)
        cfg = default()
        assert FUSASTUB002().run(tmpdir, cfg) == []


# fusa:test REQ-QUALBASE007
# fusa:test REQ-QUALBASE008
def test_check_command_surfaces_stub_findings():
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
        assert "FUSA-STUB001" in rule_ids
