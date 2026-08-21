"""x-FuSa spec conformance tests — §2.2 (--output no-stdout) and §2.9 (format-invariant identifiers)."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
from pyfusa.cli.main import run

# ---------------------------------------------------------------------------
# Shared test project factory
# ---------------------------------------------------------------------------


def _make_project(tmpdir: str) -> str:
    """Create a minimal project that will always produce at least one finding."""
    open(os.path.join(tmpdir, ".fusa.json"), "w").write(
        '{"project":{"name":"conformance-test"},"standard":"iso26262","asil":"ASIL-B"}'
    )
    open(os.path.join(tmpdir, ".fusa-reqs.json"), "w").write('{"requirements":[]}')
    return tmpdir


# ---------------------------------------------------------------------------
# §2.2 — --output must suppress stdout (no double-write)
# ---------------------------------------------------------------------------


def test_check_output_no_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "check.json")
        out = io.StringIO()
        run(
            ["check", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert out.getvalue() == "", "check --output must not write to stdout"
        assert os.path.exists(out_file)


def test_report_output_no_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "report.json")
        out = io.StringIO()
        run(
            ["report", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert out.getvalue() == "", "report --output must not write to stdout"
        assert os.path.exists(out_file)


def test_trace_output_no_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "trace.json")
        out = io.StringIO()
        run(
            ["trace", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert out.getvalue() == "", "trace --output must not write to stdout"
        assert os.path.exists(out_file)


def test_qualify_output_no_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "qualify.json")
        out = io.StringIO()
        run(
            ["qualify", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert out.getvalue() == "", "qualify --output must not write to stdout"
        assert os.path.exists(out_file)


def test_iso26262_gap_output_no_document_on_stdout():
    """Gap report JSON document must not appear on stdout when --output is given (§2.2)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "iso26262-gap.json")
        out = io.StringIO()
        run(
            ["iso26262", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        # Document must be in the file, not on stdout (status messages on stdout are OK)
        assert os.path.exists(out_file)
        with open(out_file) as f:
            doc = json.load(f)
        assert "kind" in doc
        assert '"kind"' not in out.getvalue(), "JSON document must not appear in stdout"


def test_iec62443_gap_output_no_document_on_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "iec62443-gap.json")
        out = io.StringIO()
        run(
            ["iec62443", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert os.path.exists(out_file)
        with open(out_file) as f:
            doc = json.load(f)
        assert "kind" in doc
        assert '"kind"' not in out.getvalue()


def test_slsa_gap_output_no_document_on_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out_file = os.path.join(tmpdir, "slsa-gap.json")
        out = io.StringIO()
        run(
            ["slsa", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        assert os.path.exists(out_file)
        with open(out_file) as f:
            doc = json.load(f)
        assert "kind" in doc
        assert '"kind"' not in out.getvalue()


def test_comp_output_no_stdout_suppresses_json_to_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        open(os.path.join(tmpdir, "mod.py"), "w").write(
            "def simple(x):\n    return x\n"
        )
        out_file = os.path.join(tmpdir, "comp.json")
        out = io.StringIO()
        run(
            ["comp", "--dir", tmpdir, "--format", "json", "--output", out_file],
            stdout=out,
        )
        # stdout gets the text summary; the JSON document goes to the file
        assert os.path.exists(out_file)
        with open(out_file) as f:
            doc = json.load(f)
        assert doc["kind"] == "comp-report"
        # §9.2/§13 canonical shape — the fields FuSaOps's comp.Report decodes.
        # A prior revision emitted summary:{total,pass,fail}/functions[] with
        # {function,status} instead; this only checking `kind` let that ship.
        assert "totalFunctions" in doc
        assert "violations" in doc
        assert isinstance(doc["results"], list)
        if doc["results"]:
            fn = doc["results"][0]
            assert {"file", "line", "name", "complexity", "exceedsThreshold"} <= set(
                fn
            )


# fusa:test §9.2/§13 — FuSaOps's Comp() calls `comp --format json` with no
# --output and decodes the report straight off stdout (adapter/capabilities.go).
def test_comp_json_no_output_goes_to_stdout():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        open(os.path.join(tmpdir, "mod.py"), "w").write(
            "def simple(x):\n    return x\n"
        )
        out = io.StringIO()
        code = run(["comp", "--dir", tmpdir, "--format", "json"], stdout=out)
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "comp-report"
        assert "totalFunctions" in doc
        assert "violations" in doc
        # This invocation must NOT also write comp-report.json to disk —
        # that was the previous (broken) behavior FuSaOps never saw.
        assert not os.path.exists(os.path.join(tmpdir, "comp-report.json"))


# fusa:test §9.2 — --dal overrides --threshold and both are real CLI flags.
def test_comp_dal_and_threshold_flags():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        open(os.path.join(tmpdir, "mod.py"), "w").write(
            "def simple(x):\n    return x\n"
        )
        out = io.StringIO()
        run(
            ["comp", "--dir", tmpdir, "--format", "json", "--threshold", "2"],
            stdout=out,
        )
        assert json.loads(out.getvalue())["threshold"] == 2

        out = io.StringIO()
        run(
            [
                "comp",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--threshold",
                "2",
                "--dal",
                "DAL-C",
            ],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert doc["threshold"] == 15  # DAL-C overrides the --threshold 2
        assert doc["dal"] == "DAL-C"


# ---------------------------------------------------------------------------
# §3.1 — gap-report kind must be "gap-report" (not "<std>-gap-report")
# ---------------------------------------------------------------------------


def test_gap_report_kind_is_canonical():
    """All compliance gap-report commands must emit kind='gap-report' (§3.1 MUST)."""
    import tempfile

    _GAP_CMDS = [
        "iso26262",
        "iec62443",
        "slsa",
        "iec61508",
        "do178",
        "iso21434",
        "unece",
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        for cmd in _GAP_CMDS:
            out_file = os.path.join(tmpdir, f"{cmd}.json")
            run([cmd, "--dir", tmpdir, "--format", "json", "--output", out_file])
            with open(out_file) as f:
                doc = json.load(f)
            assert doc.get("kind") == "gap-report", (
                f"pyfusa {cmd}: expected kind='gap-report', got '{doc.get('kind')}'"
            )


# ---------------------------------------------------------------------------
# §2.9 — format-invariant identifiers (ruleId/severity/category)
#         JSON findings must match SARIF results on same project
# ---------------------------------------------------------------------------


def test_format_invariant_ruleid_json_vs_sarif():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        json_out = io.StringIO()
        sarif_out = io.StringIO()

        run(["check", "--dir", tmpdir, "--format", "json"], stdout=json_out)
        run(["check", "--dir", tmpdir, "--format", "sarif"], stdout=sarif_out)

        doc = json.loads(json_out.getvalue())
        sarif = json.loads(sarif_out.getvalue())

        json_ids = sorted(f["ruleId"] for f in doc.get("findings", []))
        results = sarif.get("runs", [{}])[0].get("results", [])
        sarif_ids = sorted(r["ruleId"] for r in results)

        assert json_ids == sarif_ids, (
            f"ruleId mismatch between json and sarif formats:\n"
            f"  json:  {sorted(set(json_ids))}\n"
            f"  sarif: {sorted(set(sarif_ids))}"
        )


def test_format_invariant_severity_json_vs_sarif():
    """SARIF severity levels must correspond to JSON severity values."""
    _SARIF_MAP = {
        "error": "ERROR",
        "warning": "WARNING",
        "note": "INFO",
        "none": "INFO",
    }
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        json_out = io.StringIO()
        sarif_out = io.StringIO()

        run(["check", "--dir", tmpdir, "--format", "json"], stdout=json_out)
        run(["check", "--dir", tmpdir, "--format", "sarif"], stdout=sarif_out)

        doc = json.loads(json_out.getvalue())
        sarif = json.loads(sarif_out.getvalue())

        json_by_fp = {f["fingerprint"]: f["severity"] for f in doc.get("findings", [])}
        results = sarif.get("runs", [{}])[0].get("results", [])

        mismatches = []
        for r in results:
            fp = r.get("fingerprints", {}).get("sha256/v1", "")
            if not fp:
                # Try getting from related locations or correlationGuid
                continue
            sarif_sev = _SARIF_MAP.get(r.get("level", "warning"), "WARNING")
            json_sev = json_by_fp.get(fp)
            if json_sev and sarif_sev != json_sev:
                mismatches.append((r.get("ruleId"), json_sev, sarif_sev))

        assert mismatches == [], f"Severity mismatches between json/sarif: {mismatches}"


def test_format_invariant_findings_in_text():
    """Every ruleId in JSON output must also appear somewhere in text output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        json_out = io.StringIO()
        text_out = io.StringIO()

        run(["check", "--dir", tmpdir, "--format", "json"], stdout=json_out)
        run(["check", "--dir", tmpdir, "--format", "text"], stdout=text_out)

        doc = json.loads(json_out.getvalue())
        text = text_out.getvalue()

        missing = []
        for f in doc.get("findings", []):
            if f["ruleId"] not in text:
                missing.append(f["ruleId"])

        assert missing == [], f"ruleIds absent from text output: {sorted(set(missing))}"


def test_format_invariant_category_present_in_json():
    """All findings in JSON must have a non-empty category field (§4 MUST)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        missing_cat = [
            f["ruleId"] for f in doc.get("findings", []) if not f.get("category")
        ]
        assert missing_cat == [], (
            f"findings missing category: {sorted(set(missing_cat))}"
        )


def test_format_invariant_remediation_present_in_json():
    """All findings in JSON must have a non-empty remediation field (§4 MUST)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        missing_rem = [
            f["ruleId"] for f in doc.get("findings", []) if not f.get("remediation")
        ]
        assert missing_rem == [], (
            f"findings missing remediation: {sorted(set(missing_rem))}"
        )


def test_format_invariant_standard_clause_present_in_json():
    """All findings in JSON must have standard and clause fields (§4 SHOULD — tracked here)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        missing_std = [
            f["ruleId"] for f in doc.get("findings", []) if not f.get("standard")
        ]
        missing_clause = [
            f["ruleId"] for f in doc.get("findings", []) if not f.get("clause")
        ]
        assert missing_std == [], (
            f"findings missing standard: {sorted(set(missing_std))}"
        )
        assert missing_clause == [], (
            f"findings missing clause: {sorted(set(missing_clause))}"
        )


# ---------------------------------------------------------------------------
# §4 MAY — endLine/endColumn on AST-based findings
# ---------------------------------------------------------------------------


def test_endline_on_ast_findings():
    """AST-based findings (e.g. LINT001) must carry endLine (§4 MAY)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        # Write a function long enough to trigger LINT001
        with open(os.path.join(tmpdir, "big.py"), "w") as f:
            f.write("def big_func(x):\n")
            for i in range(65):
                f.write(f"    x = x + {i}\n")
            f.write("    return x\n")
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        lint1 = [f for f in doc.get("findings", []) if f["ruleId"] == "LINT001"]
        assert lint1, "Expected at least one LINT001 finding"
        for f in lint1:
            loc = f["location"]
            assert "endLine" in loc, f"LINT001 finding missing endLine: {loc}"
            assert loc["endLine"] >= loc["line"], "endLine must be >= line"


def test_endline_omitted_for_file_level_findings():
    """File-level findings (LINT002, FUSA001) must NOT have endLine."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Don't call _make_project so FUSA001 fires (no .fusa.json)
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        fusa1 = [f for f in doc.get("findings", []) if f["ruleId"] == "FUSA001"]
        for f in fusa1:
            loc = f["location"]
            assert "endLine" not in loc, f"FUSA001 should not have endLine: {loc}"


# ---------------------------------------------------------------------------
# §2.7 — sbom components[].hash must be sha256:<hex>
# ---------------------------------------------------------------------------


def test_sbom_components_hash_format():
    """sbom.json components with hash must use sha256:<hex> format (§2.7)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        out = io.StringIO()
        run(["release", "--dir", tmpdir], stdout=out)
        sbom_path = os.path.join(tmpdir, "sbom.json")
        assert os.path.exists(sbom_path)
        with open(sbom_path) as f:
            doc = json.load(f)
        for comp in doc.get("components", []):
            if "hash" in comp:
                h = comp["hash"]
                assert h.startswith("sha256:"), (
                    f"hash must start with 'sha256:', got: {h[:30]}"
                )
                hex_part = h[7:]
                assert len(hex_part) == 64, (
                    f"sha256 hex must be 64 chars, got {len(hex_part)}"
                )
                assert all(c in "0123456789abcdef" for c in hex_part), (
                    f"non-hex in hash: {h}"
                )


# ---------------------------------------------------------------------------
# §3.2 — structured error on exit-3 when --format json
# ---------------------------------------------------------------------------


def test_exit3_json_error_envelope():
    """check --format json on engine failure must emit error envelope with exit 3."""
    import pyfusa.engine as eng

    orig = eng.Default.run

    def fail(*a, **kw):
        raise RuntimeError("injected failure")

    eng.Default.run = fail
    try:
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["check", "--dir", "/tmp", "--format", "json"], stdout=out, stderr=err
        )
        assert code == pyfusa.EXIT_RUNTIME
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "check-report"
        assert "error" in doc
        assert doc["error"]["code"] == "internal"
        assert "injected failure" in doc["error"]["message"]
    finally:
        eng.Default.run = orig


# ---------------------------------------------------------------------------
# §2.3 — an unrecognized --format is a usage error (exit 2), on every command
# ---------------------------------------------------------------------------


def test_check_invalid_format_is_usage_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        err = io.StringIO()
        code = run(
            ["check", "--dir", tmpdir, "--format", "bogus"],
            stdout=io.StringIO(),
            stderr=err,
        )
        assert code == pyfusa.EXIT_USAGE
        assert "bogus" in err.getvalue()


def test_report_invalid_format_is_usage_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        err = io.StringIO()
        code = run(
            ["report", "--dir", tmpdir, "--format", "bogus"],
            stdout=io.StringIO(),
            stderr=err,
        )
        assert code == pyfusa.EXIT_USAGE
        assert "bogus" in err.getvalue()


def test_check_format_is_case_insensitive():
    """A valid format in a different case is still accepted (only an
    unrecognized value is a usage error)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir)
        code = run(
            ["check", "--dir", tmpdir, "--format", "JSON"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code != pyfusa.EXIT_USAGE
