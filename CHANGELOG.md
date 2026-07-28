# Changelog

## v0.2.8 — 2026-07-27

### Added
- `docker-publish.yml` now notifies `SoundMatt/FuSaOps` via `repository_dispatch`
  (`xfusa-released`) after a successful image push, so FuSaOps rebuilds its
  bundled image promptly instead of waiting for its weekly cron. Requires a
  `FUSAOPS_DISPATCH_TOKEN` secret in this repo; falls back silently
  (`continue-on-error`) to the weekly rebuild if it's not set.

### Fixed
- `qualify --output <file>` (#22) wrote the human-readable text report to the
  output file when `--format` was omitted, instead of the JSON qualification
  record documented as the only artifact schema in spec §6. `--output` now
  always writes JSON regardless of `--format`, which continues to control
  only the optional human-readable stdout rendering. This was silently
  breaking FuSaOps's `conform` §6 check and its production `Qualifier`
  adapter capability, which both invoke `qualify --output` without an
  explicit `--format json`.

## v0.2.7 — 2026-07-27

### Fixed

- Orphan release cleanup (#19): created the missing `v0.2.4` GitHub release
  (commit `c1a3c78`, reusing the original release body) and removed the
  stray no-prefix `0.2.4` tag/release that an earlier orchestration bug
  had created alongside it. Both pointed at the same commit; `v0.2.4` is
  now the sole release for that commit.
- Dockerfile no longer hardcodes stale `org.opencontainers.image.version`
  and `io.x-fusa.spec-version` OCI labels (#19). They are now templated
  from new `PYFUSA_VERSION` / `SPEC_VERSION` build-args, and
  `docker-publish.yml` derives both at build time from
  `pyfusa/__init__.py`'s `VERSION` / `SPEC_VERSION` constants, so the
  published image's labels can never drift from the package again.
- README's "x-FuSa spec conformance" section referenced the stale spec
  version **v1.10.8**; updated to match `pyfusa/__init__.py`'s
  `SPEC_VERSION` (**1.10.12**) (#19). The CI "Doc version check" job now
  also greps for `SPEC_VERSION`, not just the package version, so this
  class of drift fails CI going forward instead of going unnoticed.

## v0.2.6 — 2026-07-27

### Tests

- Boosted function-tag coverage (`pyfusa trace --func-coverage`) from
  **42% to 100%** (253/253 public module-level functions and class methods
  under `pyfusa/` now carry a `#fusa:req` tag on themselves or their
  containing class).
- Registered 22 new requirement IDs in `.fusa-reqs.json` for previously
  untagged behaviour, each backed by a genuine `#fusa:test` tag on an
  existing or newly-written test — no fabricated coverage:
  - `REQ-ANA001..009` — the 9 static-analysis rule classes in
    `pyfusa/rules/analyze.py` (thread/task lifecycle, sleep-in-thread,
    finally-raises, redundant lookups, discarded returns, None deref,
    thread-unsafe mutation, dead code) plus their (some dead-code) helper
    `ast.NodeVisitor` classes; all had existing dedicated tests in
    `tests/test_coverage_boost4.py`, just missing tags.
  - `REQ-SLSA001..003` and `REQ-ICS001..004` — the SLSA and IEC 62443
    engine rule classes in `pyfusa/rules/slsa.py` /
    `pyfusa/rules/iec62443.py`; existing tests in
    `tests/test_coverage_boost.py` tagged.
  - `REQ-COMP001` — the cyclomatic-complexity engine rule
    (`pyfusa/rules/comp.py:COMP001`), distinct from the standalone
    `pyfusa comp` report command (folded into `REQ-CLI009`).
  - `REQ-COUP001..003` — the coupling engine rules
    (`pyfusa/rules/coupling.py`). `COUP001` already had an exercising test;
    `COUP002`/`COUP003` had none, so new
    `test_coup002_callable_parameter_flagged` and
    `test_coup003_missing_report_flagged` (plus negative-case siblings)
    were added to `tests/test_coverage_boost5.py`.
  - `REQ-CONFIG001` — `pyfusa/config.py`'s `Config`/`default`/`load`/
    `load_dispositions`/`load_requirements`, tagged onto the existing
    `test_config_load_full`.
  - `REQ-COMPLY001` — the 7 standard-specific compliance gap-report
    generators (`pyfusa/compliance/{iso26262,iec61508,do178,iso21434,
    unece,slsa,iec62443}.py`), tagged onto their existing
    `tests/test_new_commands.py` / `tests/test_coverage_boost3.py` tests.
- The remaining untagged functions were folded under existing,
  already-tested requirements where the behaviour clearly matched:
  `REQ-FUSA001` (core types/fingerprint helpers in `pyfusa/__init__.py`,
  `auditpack.create`, `release.py`'s SBOM/provenance/manifest generators),
  `REQ-ENGINE001` (`Rule` ABC, `RunResult`), `REQ-TRACE001` (`Tag`/
  `Coverage` dataclasses, `trace.build/to_dict/render_text/
  compute_func_coverage` — these already carried a `#fusa:req` comment but
  as a trailing inline comment on a later line of a multi-line signature,
  which the strict `--func-coverage` scanner doesn't recognise; moved to a
  standalone line directly above each `def`), `REQ-QUAL001`/`REQ-QUAL002`
  (same inline→standalone fix in `qualify.py`/`verify.py`), `REQ-COV001`
  (same fix in `coverage.py`), `REQ-SCI001`/`REQ-DFMEA001` (sibling
  functions in the same file as an already-tagged one), and `REQ-CLI009`
  (the ~20 CLI-subcommand-backing library modules — `disposition_mgmt`,
  `metrics`, `pr`, `req_mgmt`, `hara`, `tara`, `badge`, `template`, `diff`,
  `misra`, `vuln`, `sign`, `sas`, `boundary`, `safetycase`, `comp.py`,
  `report.py`, `verify.py`'s `load`/`save`/`render_text`, and `cli/main.py`'s
  top-level `run()` dispatcher — REQ-CLI009's own requirement text already
  names each of these subcommands explicitly).
- `pyfusa trace --dir .` now reports `99/99 traced, 99/99 tested` (up from
  77/77 before the 22 new IDs were added) with no dangling `#fusa:test`
  tags and no regression in the pre-existing HLR/LLR violation set.

## v0.2.5 — 2026-07-27

### Tests

- Closed all 17 requirements left untested by the v0.2.4 `#fusa:req`
  annotation retrofit of `pyfusa/rules/evidence.py` and the remaining
  `cmd_*` handlers in `pyfusa/cli/main.py`:
  - `REQ-EVIDENCE001..016` (the 16 evidence-presence rule classes —
    `RELEASE001/002`, `QUALIFY001`, `FMEA001`, `TARA001`, `BOUNDARY001`,
    `SAFETYCASE001`, `AUDITPACK001`, `VERIFY001/002`, `HARA001..005`,
    `DISP001`): 9 already had exercising tests in
    `tests/test_coverage_boost.py` and just needed a `#fusa:test` tag;
    7 (`RELEASE002`, `QUALIFY001`, `FMEA001`, `TARA001`, `BOUNDARY001`,
    `SAFETYCASE001`, `AUDITPACK001`) had no test at all and got new
    missing/present pairs following the existing `RELEASE001`/`DISP001`
    style.
  - `REQ-CLI009` (the 30 additional CLI subcommands): 29 already had
    CLI-level tests across `tests/test_new_commands.py`,
    `tests/test_coverage_boost.py`, `tests/test_coverage_boost2.py`,
    `tests/test_comp_command.py`, and `tests/test_e2e.py` — each got a
    stacked `#fusa:test REQ-CLI009` tag alongside its existing tag. `hooks`
    had no test; added `test_hooks_install_creates_pre_commit`,
    `test_hooks_remove_deletes_pre_commit`, and
    `test_hooks_remove_when_absent` to `tests/test_new_commands.py`.
  - `pyfusa trace --dir . --gaps` now reports zero gaps (77/77 requirements
    traced and tested, up from 60/77).

## v0.2.4 — 2026-07-27

### Fixed

- **Scan-path completeness (x-FuSa spec §1.4.1, MUST):** `.fusa.json` sets
  `sourceDirs: ["pyfusa"]`, so `trace`'s annotation scan never looked in
  `tests/` for `#fusa:test` tags — `pyfusa trace --gaps` reported
  `testedRequirements: 0` when the true figure was much higher (issue #16).
  `trace.build()` now always includes `tests/`/`test/` in the scan regardless
  of `sourceDirs`, via a new `_dirs_to_scan()` helper that adds either
  directory when it exists on disk and isn't already covered.
- **Dangling requirement IDs reconciled:** 7 `#fusa:test` tags referenced
  requirement IDs absent from `.fusa-reqs.json`. `REQ-001` (in
  `tests/test_trace.py`) was a scanner self-reference artifact — literal
  annotation-shaped text in a test fixture string was being picked up by the
  now-broader tests/ scan; the fixtures are rewritten via adjacent string
  concatenation so they no longer look like real annotations in this file's
  own source. The other 6 (`REQ-PY-COU001`, `REQ-PY-CYB001`, `REQ-PY-ENG001`,
  `REQ-PY-FMA001`, `REQ-PY-IMP001`, `REQ-PY-SCI001`) were genuinely missing
  requirements for `coupling_analysis.py`, `rules/cyber.py`, `engine.py`,
  `fmea.py`, `impact.py`, and `sci.py` — now registered as `REQ-COUPLING001`,
  `REQ-CYBER001..020`, `REQ-ENGINE001`, `REQ-DFMEA001`, `REQ-IMPACT001`, and
  `REQ-SCI001`, with the stale test tags renamed to match and module/class
  `#fusa:req` impl tags added.

### Added

- **`--func-coverage N` (x-FuSa spec §1.4.1.2 / §5):** new `trace` flag,
  mirroring `--req-coverage`. Gates on the percentage of public (non-`_`
  prefixed) functions/methods under `pyfusa/` carrying a `#fusa:req` tag on
  themselves or their containing class (this project's class-level tagging
  convention); `N=0` disables. Implemented via
  `trace.compute_func_coverage()`.
- **Dangling test-tag detection (REQ004, WARNING, category `requirement`):**
  `trace.build()` now flags any `#fusa:test`/`#fusa:sec-test` tag whose
  requirement ID isn't registered in `.fusa-reqs.json`, per spec §1.4.1.3.
  `trace`'s text/JSON output now also surfaces `matrix.findings` (malformed
  and dangling annotations) that were previously collected but never shown.

### Requirement annotation retrofit

- `pyfusa/rules/cyber.py` (20 rule classes) and `pyfusa/rules/evidence.py`
  (16 rule classes) had zero `#fusa:req` tags; each rule class is now tagged
  and registered (`REQ-CYBER001..020`, `REQ-EVIDENCE001..016`).
- `pyfusa/cli/main.py` had zero `#fusa:req` tags; `cmd_version`, `cmd_check`,
  `cmd_trace`, etc. are now tagged against their existing `REQ-CLI002..008`
  requirements, `main()` against `REQ-CLI001`, and the remaining `cmd_*`
  handlers against a new `REQ-CLI009` ("additional CLI subcommands").

### Tests

- Added tests for previously-untested requirements `REQ-LINT004`, `REQ-NF001`,
  and tagged existing passing tests for `REQ-LINT002`, `REQ-LINT003`,
  `REQ-CLI002..008`, `REQ-TRACE001-LLR1..3`, `REQ-QUAL001-LLR1..2`,
  `REQ-QUAL002-LLR1..2`, and `REQ-COV001-LLR1..2`.
- New tests for scan-path completeness, dangling-tag detection, and
  `--func-coverage` in `tests/test_trace.py`.

## v0.2.3 — 2026-07-27

### Fixed

- **Doc version check:** `README.md` still referenced `v0.2.1` after the
  v0.2.2 bump, failing CI's version-consistency gate. `README.md`,
  `pyproject.toml`, and `pyfusa/__init__.py` now all reference `0.2.3`.

## v0.2.2 — 2026-07-27

### Fixed

- **SPEC_VERSION:** Updated `SPEC_VERSION` constant in `pyfusa/__init__.py` from
  `"1.10.4"` to `"1.10.12"` to match the current x-FuSa specification.

- **Formatting:** Applied `ruff format` to all 64 source and test files that had
  formatting issues, restoring consistency with the project's style rules.

### Tests

- **Coverage expansion:** Added 78 targeted tests in `tests/test_coverage_boost5.py`
  covering `impact.py` (71% → 89%), `fmea.py` (75% → 98%), `engine.py` (76% → 100%),
  `coupling_analysis.py` (76% → 96%), `sci.py` (79% → 100%), and `rules/cyber.py`
  (78% → 93%). Overall project coverage improved from 83.72% to 86.40%.

## v0.2.1 — 2026-07-26

### Fixed

- **P0 version-mismatch:** `pyproject.toml` now declares `version = "0.2.1"`,
  aligning package metadata with `pyfusa.VERSION` so `pip install`, PyPI, and
  `importlib.metadata` all report the correct version.

- **P1 missing-req-annotations:** Added `#fusa:req` annotations to every exported
  function implementing v0.2.0 requirements: `REQ-TRACE001` in `trace.build`,
  `trace.to_dict`, and `trace.render_text`; `REQ-COV001` in `coverage.run` and
  `coverage._parse_llvm_mcdc`; `REQ-QUAL001` in `qualify._qualification_badge`
  and `qualify.to_dict`; `REQ-QUAL002` in `qualify._independence_status` and
  `verify.run`. All four v0.2.0 requirements are now traced.

- **P1 lint-errors:** Fixed all critical ruff errors: removed `Config`
  forward-reference (F821) in `qualify.py` by adding module-level import; removed
  five unused variable assignments (F841) in `cli/main.py`, `coupling_analysis.py`,
  `impact.py`, `rules/analyze.py`, and `rules/cyber.py`; removed ~30 unused imports
  (F401) throughout via `ruff --fix`; stripped bare `f` prefix from seven f-strings
  (F541). Total fixable errors reduced from 363 to 275 (all critical ones resolved).

### Tests

- **P2 module coverage:** Added 45 targeted tests in `tests/test_coverage_boost4.py`
  covering `req_mgmt.py` persistence (save/load/add/CSV/render — now 100%),
  `sas.py` evidence-generation path (now 100%), and AST visitor branches in
  `rules/analyze.py` (ANA001–ANA009, now 83%). Overall coverage improved from
  82.68% to 83.72%.

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
