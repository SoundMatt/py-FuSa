# py-FuSa — v0.1.0

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

# Generate a compliance report (always exits 0)
pyfusa report
pyfusa report --format html --output safety-report.html

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

## Source annotations

Mark requirements and tests in your Python source with `#fusa:` comments:

```python
#fusa:req REQ-001
def safety_function():
    """This function implements REQ-001."""
    ...

#fusa:test REQ-001
def test_safety_function():
    ...

#fusa:sec-test REQ-SEC001
def test_injection_prevention():
    ...
```

## Findings output

Every finding carries the §4.2 canonical SHA-256 fingerprint for stable cross-tool identification:

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

py-FuSa implements x-FuSa spec **v1.9**. All §9.1 required commands are implemented:
`version`, `capabilities`, `init`, `check`, `report`, `trace`, `qualify`, `release`, `audit-pack`.

| Item | Status |
|---|---|
| Exit codes 0/1/2/3 | ✅ |
| `--no-color` / `NO_COLOR` | ✅ |
| `--format json/text/html/sarif/md` on check/report | ✅ |
| `--output` redirects (no stdout copy) | ✅ |
| §3.1 common header on all documents | ✅ |
| §4.2 fingerprint (MUST) | ✅ |
| `category` (MUST) | ✅ |
| `remediation` (MUST) | ✅ |
| `capabilities` command (MUST) | ✅ |
| SARIF 2.1.0 with physicalLocation | ✅ |
| `sbom.json` with `module` + `components` | ✅ |
| `audit-pack.zip` flat ZIP + `manifest.json` | ✅ |
| `qualify` with `total/passed/failed` + `hash` | ✅ |
| `trace` with `requirements/tags/coverage` schema | ✅ |
| Disposition support (§4.1) | ✅ |
| Project-relative `location.file` | ✅ |

## Standards

py-FuSa is itself developed as an ISO 26262 ASIL-B tool. See `.fusa.json` and `.fusa-hara.json`.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
