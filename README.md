# py-FuSa — v0.3.2

A functional safety enablement toolkit for Python projects. py-FuSa provides static checks,
coding rules, traceability helpers, CI evidence bundles, and tool qualification support to help
teams build safety cases for ISO 26262, IEC 61508, ISO 21434, and DO-178C.

[![CI](https://github.com/SoundMatt/py-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/SoundMatt/py-FuSa/actions/workflows/ci.yml)

> **Not a certification product.** py-FuSa is an engineering accelerator that reduces
> the cost of producing functional safety evidence throughout the SDLC.

## Install

```bash
pip install pyfusa
```

Or from source:

```bash
git clone https://github.com/SoundMatt/py-FuSa
cd py-FuSa
pip install -e .
```

## Quick start

```bash
# Initialise a project
pyfusa init

# Run all safety checks (exit 1 on ERROR; --strict exits 1 on WARNING too)
pyfusa check
pyfusa check --strict

# Show the requirements traceability matrix
pyfusa trace
pyfusa trace --gaps        # show only requirements with no test coverage
pyfusa trace --format json

# Run the tool qualification suite
pyfusa qualify
pyfusa qualify --format json --output qualify-report.json

# Generate SBOM, build provenance, and artifact manifest
pyfusa release

# Bundle all evidence into a single ZIP for auditors
pyfusa audit-pack

# Run the test suite and save evidence bundle (.fusa-evidence.json)
pyfusa verify

# Generate a compliance report (always exits 0)
pyfusa report
pyfusa report --format html --output safety-report.html

# Compliance gap reports
pyfusa iso26262 --format json --output iso26262-gap.json
pyfusa iec61508
pyfusa do178
pyfusa iso21434
pyfusa unece
pyfusa iec62443
pyfusa slsa

# Generate cyclomatic complexity report (DO-178C §6.3.4)
pyfusa comp
pyfusa comp --format json --output comp-report.json

# Query tool capabilities
pyfusa capabilities --format json

# Print version
pyfusa version
```

## Safety rules

### Project structure (FUSA-series)

| Rule | Severity | Description |
|---|---|---|
| FUSA001 | ERROR | `.fusa.json` configuration file must be present |
| FUSA002 | ERROR | Python packaging file (pyproject.toml/setup.py/setup.cfg) must be present |
| FUSA003 | WARNING | LICENSE file must be present |
| FUSA004 | WARNING | README file must be present |
| FUSA005 | WARNING | CI configuration must be present |
| FUSA006 | WARNING | `.fusa-reqs.json` requirements registry should be present |

### Python coding standards (LINT-series)

| Rule | Severity | Description |
|---|---|---|
| LINT001 | WARNING | Functions must not exceed 60 lines |
| LINT002 | WARNING | Files must not exceed 500 lines |
| LINT003 | WARNING | Block nesting depth must not exceed 4 levels |
| LINT004 | WARNING | Cyclomatic complexity must not exceed 10 |
| LINT005 | WARNING | Mutable default arguments (list, dict, set) |
| LINT006 | WARNING | Wildcard imports (`from x import *`) |
| LINT007 | WARNING | `assert` statements removed by `-O`; use explicit checks |

### Security (SEC-series, CWE-mapped)

| Rule | Severity | CWE | Description |
|---|---|---|---|
| SEC001 | ERROR | CWE-703 | Bare `except:` catches all exceptions |
| SEC002 | ERROR | CWE-95 | `eval()` executes arbitrary code |
| SEC003 | ERROR | CWE-78 | `exec()` executes arbitrary code |
| SEC004 | ERROR | CWE-502 | `pickle.load/loads` deserialises arbitrary objects |
| SEC005 | ERROR | CWE-78 | `os.system()` shell injection risk |
| SEC006 | ERROR | CWE-78 | `subprocess` called with `shell=True` |
| SEC007 | ERROR | CWE-312 | Hardcoded credentials or secrets |
| SEC008 | ERROR | CWE-377 | `tempfile.mktemp()` TOCTOU race condition |
| SEC009 | WARNING | CWE-330 | `random` module used for security values |

### Concurrency (CONC-series)

| Rule | Severity | Description |
|---|---|---|
| CONC001 | WARNING | Thread creation without apparent synchronization |
| CONC002 | WARNING | `global` mutation in functions (shared-state hazard) |
| CONC003 | INFO | `async` function contains no `await` expressions |

### Static analysis (ANA-series)

| Rule | Severity | Description |
|---|---|---|
| ANA001 | WARNING | Thread/task created without a stop-event signal |
| ANA002 | WARNING | Thread/task spawned inside a loop without concurrency bound |
| ANA003 | WARNING | `time.sleep()` inside thread worker cannot be interrupted |
| ANA004 | WARNING | `except`/`finally` block that may raise swallows original exception |
| ANA005 | WARNING | Mutable global mutated without a lock |
| ANA006 | WARNING | Potential `None` dereference without null-guard |
| ANA007 | WARNING | `asyncio.create_task` called without storing or awaiting the result |
| ANA008 | WARNING | `__del__` finaliser contains I/O that may fail at shutdown |
| ANA009 | WARNING | Class defines `__eq__` without `__hash__` (implicit unhashable) |

### Complexity (COMP-series, DO-178C §6.3.4)

| Rule | Severity | Description |
|---|---|---|
| COMP001 | WARNING | Cyclomatic complexity V(G) exceeds ASIL/DAL threshold |

Use `pyfusa comp` to generate a full per-function complexity report (`comp-report.json`) without running all checks:

```bash
pyfusa comp                          # writes comp-report.json, exits 1 if any FAIL
pyfusa comp --format json            # JSON report
```

### Evidence presence (RELEASE / QUALIFY / HARA / VERIFY / DISP series)

| Rule | Severity | Description |
|---|---|---|
| RELEASE001 | WARNING | `sbom.json` Software Bill of Materials not found |
| RELEASE002 | WARNING | `provenance.json` build provenance not found |
| QUALIFY001 | INFO | `qualify-report.json` tool qualification evidence absent |
| FMEA001 | INFO | `fmea.json` dFMEA analysis absent |
| TARA001 | INFO | `tara.json` TARA cybersecurity analysis absent |
| BOUNDARY001 | INFO | System boundary diagram absent |
| SAFETYCASE001 | INFO | `safety-case.json` not assembled |
| AUDITPACK001 | INFO | `audit-pack.zip` not bundled |
| VERIFY001 | INFO | `.fusa-evidence.json` test evidence bundle absent |
| VERIFY002 | WARNING | Test evidence bundle reports failed tests |
| HARA001 | WARNING/INFO | `.fusa-hara.json` hazard analysis absent |
| HARA002 | WARNING | Hazard has incomplete risk rating (S/E/C) |
| HARA003 | WARNING | Hazard not linked to a safety goal |
| HARA004 | WARNING | Safety goal has no ASIL assigned |
| HARA005 | WARNING | Safety goal ASIL exceeds project ASIL ceiling |
| DISP001 | WARNING | ERROR finding in `check-report.json` has no disposition entry |

### Supply-chain integrity (SLSA-series)

| Rule | Severity | Description |
|---|---|---|
| SLSA001 | INFO | `provenance.json` missing `vcsRevision` (SLSA L1) |
| SLSA002 | INFO | `provenance.json` missing `builder` field (SLSA L2) |
| SLSA003 | INFO | No CODEOWNERS or branch-protection policy found (SLSA L3) |

### Industrial cybersecurity (IEC 62443-series)

| Rule | Severity | Description |
|---|---|---|
| IEC62443-001 | INFO | `.fusa-iec62443.json` Security Level declaration absent |
| IEC62443-002 | WARNING | `target_sl` not in range 1–4 |
| IEC62443-003 | INFO | No security policy document (`SECURITY.md`) found |
| IEC62443-004 | INFO | No cyber incident response plan found |

## Compliance gap reports

Two §9.3 gap reports surface structured coverage for supply-chain and IACS security standards:

| Command | Standard | Level flag | Default |
|---|---|---|---|
| `pyfusa iec62443` | IEC 62443 IACS cybersecurity (12 objectives) | `--sl` | `SL-2` |
| `pyfusa slsa` | SLSA supply-chain levels (10 objectives) | `--level` | `L2` |

```bash
pyfusa iec62443 --sl SL-3 --format json --output iec62443-gap.json
pyfusa slsa --level L3 --format json --output slsa-gap.json
```

## Source annotations

Mark requirements and tests in your Python source with `#fusa:` comments:

```python
# fusa:req REQ-001
def safety_function():
    """This function implements REQ-001."""
    ...


# fusa:test REQ-001
def test_safety_function(): ...


# fusa:sec-test REQ-SEC001
def test_injection_prevention(): ...
```

## Findings output

Every finding carries the §4.2 canonical SHA-256 fingerprint for stable cross-tool identification, along with `standard`, `clause`, and `remediation` fields:

```json
{
  "ruleId": "SEC001",
  "severity": "ERROR",
  "message": "bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
  "location": { "file": "src/handler.py", "line": 42 },
  "category": "security",
  "standard": "iso26262",
  "clause": "7.4.4",
  "remediation": "specify the exception type(s) to catch: 'except (ValueError, TypeError):'",
  "fingerprint": "sha256:a1b2c3..."
}
```

## x-FuSa spec conformance

py-FuSa implements x-FuSa spec **v1.15.2**. All §9.1 required commands are implemented:
`version`, `capabilities`, `init`, `check`, `report`, `trace`, `verify`, `qualify`, `release`, `audit-pack`.

| Item | Status |
|---|---|
| Exit codes 0/1/2/3 | ✅ |
| `--no-color` / `NO_COLOR` | ✅ |
| `--format json/text/html/sarif/md` on check/report | ✅ |
| `--output` redirects (no stdout copy) | ✅ |
| §3.1 common header on all documents | ✅ |
| §3.2 `projectRoot` + `asil\|sil\|dal` on reports | ✅ |
| §4.2 fingerprint (MUST) | ✅ |
| `category` (MUST) | ✅ |
| `remediation` (MUST) | ✅ |
| `capabilities` command (MUST) | ✅ |
| SARIF 2.1.0 with physicalLocation | ✅ |
| `sbom.json` with `module` + `components` + `hash` (§2.7) | ✅ |
| `audit-pack.zip` flat ZIP + `manifest.json` | ✅ |
| `qualify` with `total/passed/failed` + `hash` | ✅ |
| `trace` with `requirements/tags/coverage` schema | ✅ |
| `verify` saves `.fusa-evidence.json` (§9.2) | ✅ |
| §9.3 gap-report schema: `satisfied\|gap\|partial` status | ✅ |
| §9.3 `evidence` field as array | ✅ |
| §9.3 summary keys `satisfied/partial/gaps` | ✅ |
| `standard` + `clause` on all findings (§4) | ✅ |
| §3.2 structured `error: {code, message}` on exit-3 (json format) | ✅ |
| Disposition support (§4.1) | ✅ |
| Project-relative `location.file` | ✅ |
| `location.endLine` / `endColumn` on AST findings (§4 MAY) | ✅ |
| gap-report `kind` = `"gap-report"` on all 7 compliance reports (§3.1) | ✅ |
| §1.2.5 `.fusa-hara.json` schema (`operationalSituations`/`hazards`/`safetyGoals`, `fssrRefs` MUST ≥1) | ✅ |
| §9.2 `fmea`/`tara`/`safety-case` canonical schemas (SFOP impact, GSN node types) | ✅ |
| §9.3 `sas`/`sci` canonical schemas (`checklist[]`, `artifacts[].hash`) | ✅ |
| §2.7 hash conventions on all evidence artifacts (`hash` → `sha256:`-prefixed) | ✅ |
| §1.6.1 `FUSA-STUB001`/`FUSA-STUB002` content-quality detection | ✅ |
| §1.6.2 attestation (`--require-attestation`, `--strict`) | ✅ |
| `fmea`/`tara` `summary.coveragePct` + `--min-coverage N` | ✅ |

## Standards

py-FuSa is itself developed as an ISO 26262 ASIL-B tool. See `.fusa.json` and `.fusa-hara.json`.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
