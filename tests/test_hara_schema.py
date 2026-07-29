"""HARA (.fusa-hara.json / `hara` command) schema conformance — x-FuSa spec
§1.2.5 / §9.2 hara."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
import pyfusa.hara as hara
from pyfusa.cli.main import run
from pyfusa.config import default


def _base_data():
    return {
        "project": "p",
        "standard": "iso26262",
        "operationalSituations": [{"id": "OS-001", "description": "normal operation"}],
        "hazards": [
            {
                "id": "H-001",
                "description": "specific hazard description",
                "situations": ["OS-001"],
                "risk": {
                    "severity": "S2",
                    "exposure": "E2",
                    "controllability": "C2",
                    "asil": "ASIL-B",
                },
                "safetyGoals": ["SG-001"],
            }
        ],
        "safetyGoals": [
            {
                "id": "SG-001",
                "description": "specific safety goal",
                "hazards": ["H-001"],
                "asil": "ASIL-B",
                "fssrRefs": ["REQ-001"],
            }
        ],
    }


# fusa:test REQ-HARA006
def test_init_template_is_empty_never_dummy_rows():
    data = hara.init_template("proj", "iso26262")
    assert data["operationalSituations"] == []
    assert data["hazards"] == []
    assert data["safetyGoals"] == []


# fusa:test REQ-HARA006
def test_validate_findings_clean_file_no_findings():
    data = _base_data()
    findings = hara.validate_findings(data, "ASIL-C", {"REQ-001"})
    assert findings == []


# fusa:test REQ-HARA006
def test_validate_findings_incomplete_risk_rating():
    data = _base_data()
    del data["hazards"][0]["risk"]["exposure"]
    findings = hara.validate_findings(data, "ASIL-C")
    assert any(f.rule_id == "HARA002" for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_asil_exceeds_project_ceiling():
    data = _base_data()
    data["hazards"][0]["risk"] = {
        "severity": "S3",
        "exposure": "E4",
        "controllability": "C3",
    }  # -> ASIL-D
    findings = hara.validate_findings(data, "ASIL-B")
    assert any(f.rule_id == "HARA005" for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_hazard_no_safety_goals():
    data = _base_data()
    data["hazards"][0]["safetyGoals"] = []
    findings = hara.validate_findings(data, "ASIL-C")
    assert any(f.rule_id == "HARA003" for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_dangling_safety_goal_reference():
    data = _base_data()
    data["hazards"][0]["safetyGoals"] = ["SG-999"]
    findings = hara.validate_findings(data, "ASIL-C")
    assert any(f.rule_id == "HARA003" and "SG-999" in f.message for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_dangling_situation_reference():
    data = _base_data()
    data["hazards"][0]["situations"] = ["OS-999"]
    findings = hara.validate_findings(data, "ASIL-C")
    assert any(f.rule_id == "HARA008" for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_safety_goal_no_asil():
    data = _base_data()
    del data["safetyGoals"][0]["asil"]
    findings = hara.validate_findings(data, "ASIL-C")
    assert any(f.rule_id == "HARA004" for f in findings)


# fusa:test REQ-HARA006
def test_validate_findings_missing_fssr_refs_is_error():
    data = _base_data()
    data["safetyGoals"][0]["fssrRefs"] = []
    findings = hara.validate_findings(data, "ASIL-C")
    hara006 = [f for f in findings if f.rule_id == "HARA006"]
    assert hara006
    assert hara006[0].severity == pyfusa.SEVERITY_ERROR
    assert hara006[0].category == pyfusa.CATEGORY_REQUIREMENT


# fusa:test REQ-HARA006
def test_validate_findings_dangling_fssr_ref():
    data = _base_data()
    findings = hara.validate_findings(data, "ASIL-C", req_ids={"REQ-999"})
    hara007 = [f for f in findings if f.rule_id == "HARA007"]
    assert hara007
    assert hara007[0].severity == pyfusa.SEVERITY_WARNING


# fusa:test REQ-HARA006
def test_validate_findings_no_req_ids_skips_dangling_check():
    """When req_ids is None (caller didn't load .fusa-reqs.json), the
    fssrRefs-dangling check (HARA007) is skipped rather than false-flagging
    every reference."""
    data = _base_data()
    findings = hara.validate_findings(data, "ASIL-C", req_ids=None)
    assert not any(f.rule_id == "HARA007" for f in findings)


# fusa:test REQ-HARA009
def test_completeness_fields():
    data = _base_data()
    comp = hara.completeness(data, {"REQ-001"})
    assert comp["totalHazards"] == 1
    assert comp["hazardsWithAsil"] == 1
    assert comp["hazardsWithSafetyGoal"] == 1
    assert comp["safetyGoalsWithFssrRefs"] == 1
    assert comp["danglingReferences"] == 0


# fusa:test REQ-HARA009
def test_completeness_counts_dangling_references():
    data = _base_data()
    data["hazards"][0]["situations"] = ["OS-999"]
    comp = hara.completeness(data, {"REQ-001"})
    assert comp["danglingReferences"] == 1


# fusa:test REQ-HARA009
def test_to_report_dict_shape():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        data = _base_data()
        doc = hara.to_report_dict(data, tmpdir, cfg)
        assert doc["kind"] == "hara-report"
        assert doc["operationalSituations"] == data["operationalSituations"]
        assert doc["hazards"] == data["hazards"]
        assert doc["safetyGoals"] == data["safetyGoals"]
        assert "completeness" in doc


# fusa:test REQ-HARA009
def test_to_report_dict_carries_attestation():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="p")
        data = _base_data()
        data["attestation"] = {"status": "reviewed"}
        doc = hara.to_report_dict(data, tmpdir, cfg)
        assert doc["attestation"] == {"status": "reviewed"}


# fusa:test REQ-QUALBASE005
def test_quality_findings_flags_placeholder_hazard_description():
    data = _base_data()
    data["hazards"][0]["description"] = "[describe the hazard]"
    findings = hara.quality_findings(data)
    assert any(f.rule_id == "FUSA-STUB001" for f in findings)


# fusa:test REQ-CLI009
def test_hara_cli_validate_reports_hara006_and_gates():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = _base_data()
        data["safetyGoals"][0]["fssrRefs"] = []
        hara.save(tmpdir, data)
        out = io.StringIO()
        code = run(["hara", "validate", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_GATE_FAIL
        assert "HARA006" in out.getvalue()


# fusa:test REQ-HARA009
def test_hara_cli_show_json_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        data = _base_data()
        hara.save(tmpdir, data)
        out = io.StringIO()
        code = run(
            ["hara", "show", "--dir", tmpdir, "--format", "json", "--output", ""],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "hara-report"
        assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# Issue #33 — ASIL determination table (ISO 26262-3:2018 Table 4)
# ---------------------------------------------------------------------------


# fusa:test REQ-CLI009
def test_determine_asil_known_values_match_iso26262_table4():
    """Spot-check a representative sample of ISO 26262-3:2018 Table 4 cells
    that were previously wrong by exactly one ASIL step (issue #33) —
    S2/E2/C2 is the exact cell the issue's real-world-impact example uses."""
    cases = [
        ("S1", "E1", "C3", "QM"),
        ("S1", "E2", "C2", "QM"),
        ("S1", "E2", "C3", "QM"),
        ("S1", "E3", "C3", "ASIL-A"),
        ("S1", "E4", "C3", "ASIL-B"),
        ("S2", "E1", "C2", "QM"),
        ("S2", "E2", "C2", "ASIL-A"),  # the issue's headline example
        ("S2", "E2", "C3", "ASIL-B"),
        ("S2", "E3", "C3", "ASIL-C"),
        ("S2", "E4", "C2", "ASIL-C"),
        ("S3", "E1", "C3", "ASIL-C"),
        ("S3", "E4", "C3", "ASIL-D"),
        # ISO 26262-3 Table 4: E0 (incredible exposure) is always QM,
        # regardless of severity/controllability.
        ("S3", "E0", "C3", "QM"),
    ]
    for s, e, c, expected in cases:
        assert hara.determine_asil(s, e, c) == expected, (s, e, c)


# fusa:test REQ-HARA006
def test_validate_findings_writes_back_corrected_asil():
    """Issue #33 real-world impact: validate_findings() overwrites
    risk['asil'] with the *derived* value — for S2/E2/C2 that MUST now be
    ASIL-A, not the previously-computed ASIL-B."""
    data = _base_data()
    data["hazards"][0]["risk"] = {
        "severity": "S2",
        "exposure": "E2",
        "controllability": "C2",
    }
    hara.validate_findings(data, "ASIL-C")
    assert data["hazards"][0]["risk"]["asil"] == "ASIL-A"
