# Changelog

## v0.2.0 — 2026-07-26

### Added

- **Feature 1 — HLR/LLR Decomposition (`trace`):** Added `parent_id` field to
  requirements in `.fusa-reqs.json`. `pyfusa trace` now validates that every LLR
  references a valid HLR via `parent_id` and every HLR has at least one LLR
  child. Violations are WARNING at DAL-C/ASIL-C and below, ERROR at DAL-A/ASIL-D
  or with the new `--strict-hlr-llr` flag. Text and JSON renderers show the
  hierarchy. JSON output includes `hlrViolations` and `coverage.hlrCount /
  llrCount / hlrWithLlr` metrics. Closes #9.

- **Feature 2 — Tool Qualification Display (`qualify`):** `pyfusa qualify` now
  accepts `--qualification-method` (`self` | `independent`), `--qualifier`
  (name/org), and `--record-uri` (URI to dossier). JSON output includes a
  `qualificationBadge` field (`independently-qualified` / `self-qualified` /
  `unqualified`). Closes #10.

- **Feature 3 — MC/DC Coverage (`coverage`):** `pyfusa coverage` now accepts
  `--mcdc`, `--mcdc-file`, and `--mcdc-threshold` flags. Parses LLVM coverage
  JSON to extract MC/DC condition coverage per function. A condition is covered
  iff `covered_true_count > 0` AND `covered_false_count > 0`. Hard gate: any
  function with uncovered conditions fails the overall report. JSON output
  includes a structured `mcdc` sub-object. Closes #11.

- **Feature 4 — V&V Independence (`qualify`):** `pyfusa qualify` now accepts
  `--implementation-author`, `--independent-reviewer`,
  `--independent-test-executor`, and `--achievable-asil` flags. JSON output
  includes `independenceStatus` (`independent` / `same-author` / `unknown`) and
  the corresponding fields. Closes #12.

- **14 new requirements** added to `.fusa-reqs.json` (REQ-TRACE001 with 3 LLRs,
  REQ-QUAL001 with 2 LLRs, REQ-QUAL002 with 2 LLRs, REQ-COV001 with 2 LLRs).

- **36 new tests** in `tests/test_hlr_llr_qualify_mcdc_vv.py`.

---

## v0.1.9 — 2026-07-25

- Fix SPEC_VERSION from "1.10.8" to "1.10.4"
- Add docker-publish.yml — publish ghcr.io/soundmatt/py-fusa on tag push
- First tagged release

---

## 0.1.8 — 2026-06-13

### Added

- **DCO check in CI:** New `dco` job in `.github/workflows/ci.yml` enforces Developer Certificate of Origin sign-off (`Signed-off-by:`) on all commits in pull requests.

---

## 0.1.7 — 2026-06-13

### Changed

- Bumped SPEC_VERSION to 1.10.8 (was 1.10.7). Spec update covers c-FuSa v0.5.16 exit-code fixes only; no new MUST gaps for py-FuSa.

---

## 0.1.6 — 2026-06-13

### Changed

- Bumped SPEC_VERSION to 1.10.7 (was 1.10.6). No new MUST gaps for py-FuSa — spec update covers cpp-FuSa v0.12.5 location.file fix and c-FuSa v0.5.14 hara command only.

---

## 0.1.5 — 2026-06-13

### Fixed

- **§3.1 gap-report `kind` (MUST):** All 7 compliance gap-report modules now emit `"kind": "gap-report"` instead of `"kind": "<std>-gap-report"`. This was the last open MUST conformance gap against x-FuSa spec v1.10.6.

### Changed

- Bumped SPEC_VERSION to 1.10.6 (was 1.10).

---

## 0.1.4 — 2026-06-12

### Added

- **§4 MAY — endLine/endColumn:** All AST-based findings now carry `endLine` and `endColumn` in their `location` object. File-level findings (no AST node) correctly omit these fields. 186/234 findings in a typical scan carry span info.
- **`pyfusa.ast_loc(file, node)`:** New public helper that constructs a `Location` from a file path and an `ast.AST` node, including `end_line`/`end_column`.
- **Conformance tests:** `tests/test_spec_conformance.py` now covers §4 MAY endLine presence (LINT001) and correct omission for file-level findings (FUSA001).

---

## 0.1.3 — 2026-06-12

### Changed

- Bumped SPEC_VERSION to 1.10 (was 1.9) to match current x-FuSa spec

### Fixed

- **§4 findings:** All rule classes now emit `standard` and `clause` fields via engine injection — every finding has a traceable standard reference
- **§2.7 sbom components:** `sbom.json` now includes `hash: "sha256:<hex>"` for each component (METADATA hash)
- **§3.2 structured error:** `check --format json` now emits a JSON error envelope with `error: {code, message}` on exit-3 runtime failures

---

## 0.1.2 — 2026-06-12

### Added

- `pyfusa comp` — standalone cyclomatic complexity report → `comp-report.json` (DO-178C §6.3.4). Scans all non-test Python functions, reports V(G) per function, exits 1 if any exceed the ASIL/DAL threshold. Achieves full feature parity with java-FuSa.

---

## 0.1.1 — 2026-06-12

### Added

- `pyfusa iec62443` — IEC 62443 IACS cybersecurity compliance gap report (12 objectives, SL-1 to SL-4, spec §9.3)
- `pyfusa slsa` — SLSA supply-chain levels compliance gap report (10 objectives, L1 to L4, spec §9.3)

### Fixed

- CI: `tara` uses `--from-report` not `--from`
- CI: `sign keygen/sign/verify` use `--key`/`--file` flags
- CI: `metrics record` not `metrics collect`
- Dockerfile OCI version label was stuck at `0.1.0`

---

## 0.1.0 — 2026-06-11

Initial release. Implements x-FuSa spec v1.9.

### Features

- **Required commands (§9.1):** `version`, `capabilities`, `init`, `check`, `report`,
  `trace`, `qualify`, `release`, `audit-pack`
- **Safety rules:** FUSA001–006 (project structure), LINT001–007 (Python coding standards),
  SEC001–009 (security/CWE-mapped), CONC001–003 (concurrency)
- **§4.2 fingerprinting:** deterministic SHA-256 fingerprints on every finding
- **Dispositions (§4.1):** `.fusa-dispositions.json` support with orphan warnings
- **Formats:** `text`, `json`, `html`, `sarif` (2.1.0), `md`
- **SBOM (§7):** `sbom.json` with module + components
- **Audit pack (§8):** flat ZIP with `manifest.json` and SHA-256 per file
- **Qualification (§6):** 15 known-answer tests with JCS-canonical hash
- **Trace (§5):** `#fusa:req`, `#fusa:test`, `#fusa:sec-test` annotation scanning
- **Exit codes:** 0/1/2/3 per §2.3
- **`--no-color` / `NO_COLOR`:** §2.6 compliance
- **Docker image:** alpine base, OCI labels, `io.x-fusa.*` labels per §15
