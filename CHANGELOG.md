# Changelog

## v0.4.0 — 2026-08-21

Two audit passes merged as 19 PRs (#41–#59): a cross-tool conformance audit
against the x-FuSa spec, c-FuSa, and FuSaOps, followed by a self-authenticity
audit checking that every py-FuSa feature does what it claims and every
detection rule is real rather than gameable.

### Added

- **`baseline` and `explain` commands (#45).** `pyfusa baseline` snapshots
  the current finding set so future `check` runs can suppress
  already-known findings via a new `disposition_source` field on `Finding`;
  `pyfusa explain <rule-id>` prints a rule's rationale, remediation, and
  standard clause without running a full scan.

### Fixed

- **`.fusa-dispositions.json` schema was incompatible across three call
  sites (Critical, #42).** `disposition_mgmt.py`, `config.py`, and
  `rules/evidence.py` each read/wrote a different shape for the same file,
  so dispositions recorded by one path were silently invisible to another.
  Unified on one schema.
- **`comp` command's output didn't match the spec-canonical schema, and
  FuSaOps' stdout integration broke on it (#43).** Rebuilt to conform.
- **`release --full`, `audit-pack`, and `--format` gaps against x-FuSa
  spec MUSTs (#44).** `release --full` now fans out to every sub-command;
  `audit-pack` includes `comp-report.json`; an invalid `--format` now
  exits with the correct usage-error code.
- **`coupling_analysis.py` silently swallowed exceptions from crashing
  rules (#46).**
- **Six compliance modules (`do178`/`iso26262`/`iec61508`/`iec62443`/
  `iso21434`/`unece`) treated a zero-byte or garbage-content evidence file
  identically to real evidence (#47, #58).** A new
  `pyfusa.compliance._evidence.evidence_present()` requires parseable,
  non-empty content; `rank_status()` further consolidates the
  near-duplicate rank-comparison logic four of these six modules had each
  reimplemented separately.
- **Detection bugs in `analyze`/`cyber` rules (#48, #49, #54).** ANA001
  attributed a "stop" signal found *anywhere in the file* to every thread
  in it, not just ones in its own scope; ANA005/ANA007 had similar
  scope-blindness; ANA008 only ever detected a `target=lambda: ...` thread
  worker, never the realistic `target=worker_function` pattern; CYBER002
  flagged a weak-cipher *import* alone, not just constructing one;
  CYBER004/CYBER017/CYBER018 had related false-positive/false-negative
  gaps. Six pieces of dead detection code (unused visitor classes, an
  unused rule factory) were also removed.
- **`tara`'s mitigations check and `sas`'s content verification accepted
  placeholder content (#53).**
- **`coverage.py` parsed XML coverage reports with regex instead of a
  real XML parser (#56).**
- **`verify` under/over-counted per-test results (#57).** Aggregate counts
  now always derive from pytest's own summary line.
- **Five CLI commands (`req`, `badge`, `impact`, `pr`, `verify`) had
  inconsistent or missing error handling around file I/O (#50).**
- **`qualify`'s qualification badge logic and `safety-case`'s GSN argument
  text (#51).** The badge could report "independently-qualified" from
  qualifier identity alone, without an independent reviewer; safety-case
  strategy nodes carried a fixed template string identical for every
  project regardless of its actual hazards/findings/coverage — a §9.2
  MUST violation ("`nodes[].text` MUST be specific to this tool's actual
  claims"). Strategy text now cites a real fact pulled from the project's
  own evidence files.

### Changed

- **Cyclomatic-complexity calculation, previously duplicated across rule
  modules, is now one shared `pyfusa.rules.comp.cyclomatic_complexity()`
  (#55).**
- **~20 duplicated "open --output, write, print confirmation" CLI call
  sites consolidated into one shared `_write_output()` helper (#59).**
  `check`/`report`/`qualify`/`trace`/`audit-pack` — the five commands
  §2.2 of the spec governs — remain verified byte-for-byte silent on
  stdout when `--output` is given.
- **README rule tables reconciled against actual rule implementations**
  (CYBER-series, COUP-series, ANA005-009, LINT001) and the fingerprint
  algorithm's deliberate line-number exclusion documented (#41, #52).

## v0.3.3 — 2026-07-30

Fixes an independently re-verified, third-party audit finding that the ASIL
determination table was **still wrong** after the v0.3.1 "fix" — plus seven
other defects from the same audit pass.

### Fixed

- **`hara`: `_ASIL_TABLE` inflated ASIL for S2 and S3 hazards (Critical).**
  The v0.3.1 changelog claimed the table had been "corrected" and
  "cross-checked against FuSaOps' tested reference" — both claims were
  false. FuSaOps carried the identical defect at the time, so that
  cross-check was circular, and the resulting table still inflated every S2
  cell by a uniform +1 ASIL rank across 9 of 12 S2 combinations, and
  inflated S3 by an effective +2 ranks in most cells (partially masked near
  the ASIL-D ceiling, where there is no higher rank left to reveal the full
  magnitude). `_ASIL_TABLE` is now derived directly and only from ISO
  26262-3:2018 Table 4's additive point model — `points = S + E + C`, with
  `S1=1/S2=2/S3=3`, `E1..E4=1..4`, `C1..C3=1..3`, and `points <= 6 -> QM`,
  `7 -> ASIL-A`, `8 -> ASIL-B`, `9 -> ASIL-C`, `10 -> ASIL-D` (reached only
  by S3+E4+C3). This derivation is standalone against the standard text; it
  makes **no claim of cross-validation against any other x-FuSa tool**,
  fixed or not — that claim is exactly what went wrong last time.
  `validate_findings()` still overwrites `risk["asil"]` unconditionally, but
  now with the correct value. `tests/test_hara_schema.py` replaces the
  wrong "known-good" vectors (including the literal S2/E2/C2 → ASIL-A
  assertion from the original bug report, which is actually QM) with values
  re-derived from the corrected table, and adds an exhaustive 36-cell test
  over every valid S×E×C combination so no future regression can hide in an
  untested cell. This repo's own `.fusa-hara.json` hazard ratings were
  re-derived and corrected to QM.
- **`hara`: HARA002–HARA006 emitted `SEVERITY_ERROR` while the README
  documented WARNING (Medium).** `pyfusa/hara.py:validate_findings` (used
  by `hara validate`) disagreed with both the README and with the
  equivalent `HARA002`–`HARA005` rules in `pyfusa/rules/evidence.py` (used
  by `check`), which were already WARNING. WARNING is correct — `hara
  validate` gates on the *presence* of any finding, not on its severity
  label, so ERROR bought no additional gating and only misrepresented these
  as blocking defects. All eight `HARA002`–`HARA008` findings emitted by
  `validate_findings` are now WARNING, and the README's evidence-presence
  table now documents all eight rules (`HARA006`/`HARA007`/`HARA008` were
  previously undocumented).
- **`trace`: `build()` bypassed the §1.2.2 duplicate-requirement-id check
  (Medium).** `build()` read `.fusa-reqs.json` directly instead of going
  through `config.load_requirements`, so `trace` silently accepted
  duplicate ids that `check` correctly flags. `build()` now loads
  requirements through the shared loader and folds its duplicate-id
  findings into the trace matrix.
- **`trace`: read `parent_id` instead of the spec's canonical `parent` key
  (Medium).** All three sites in `trace.py` that resolve an LLR's parent HLR
  now read `parent` first, falling back to the legacy `parent_id` alias, so
  a `.fusa-reqs.json` written to the x-FuSa spec's own `§1.2.2` schema no
  longer has every LLR misreported as orphaned/standalone.
- **`trace`: REQ002 flagged legitimate trailing prose as a malformed
  annotation (Medium/Low).** `_scan_annotations` treated any non-comment
  text after a valid requirement id as a second, malformed id. It now only
  flags a genuine second requirement-id-shaped token (e.g. a stray
  `REQ-CLI009`), not ordinary trailing comment prose.
- **CI: the 80% coverage gate was `continue-on-error: true` (Medium).** The
  gate ran but could never fail the build. `continue-on-error` is removed
  from `.github/workflows/ci.yml`'s coverage step so a real coverage
  shortfall now blocks CI, as the README has always implied it does.
- **`capabilities`: `ruleCount` was hardcoded to `47` (Low).** It now
  derives from `len(_engine.Default.rules)`, so it can't silently drift
  from the actual registered rule count again.
- **`impact`: `git diff` built its argument list without a `--` separator
  (Low, argument-injection hardening).** `_git_changed_files` used
  `subprocess.run([...], shell=False)`, which blocks shell-metacharacter
  injection but not argv-level injection into `git` itself — a ref
  beginning with `-` would still be parsed by `git` as an option. Refs
  starting with `-` are now rejected, and a `--` separator now terminates
  the revision list before the (implicit) pathspec.
- **`coverage`: hardcoded the literal `python3` instead of `sys.executable`
  (Low).** Non-`python3` interpreter names and virtualenv-relative
  invocations now work.

### Added

- **`docs/tool-safety-manual.md`.** A minimal, honest stub covering py-FuSa's
  tool classification and known limitations, following the structure used
  by the more mature x-FuSa tools. It explicitly tracks what is *not* yet
  written (`docs/qualification.md`, `ROADMAP.md`, an independent
  qualification report) rather than implying that gap is closed. The
  README now links to it and states the same gap directly.
- `.gitignore` now ignores the generated `qualify-report.json`; the
  previously checked-in copy has been removed from the repository.

## v0.3.2 — 2026-07-28

Adopts x-FuSa spec **v1.15.2** (`1.15.0` → `1.15.1` → `1.15.2`). Both intervening
bumps are pure documentation clarifications (schemaVersion/specVersion format
and an explicit Rule A false-positive example) with no required behavior or
wire-format change — a version-pin bump only.

## v0.3.1 — 2026-07-28

Fixes four defects found by a fresh deep-audit pass that built py-FuSa for
real, ran every command against its own codebase, and diffed the real output
against the x-FuSa spec (`SoundMatt/py-FuSa` #33–#36).

### Fixed

- **`hara`: ASIL determination table still diverged from ISO 26262-3:2018
  Table 4 (#33, reopened).** The earlier "fix" was itself wrong: it left
  every S2/S3 cell inflated by one ASIL step (e.g. it "corrected" S2/E2/C2 to
  `ASIL-A` when Table 4 gives **QM**), and cross-checked the table against
  FuSaOps' reference implementation which encodes the *same* defect. `_ASIL_TABLE`
  is now regenerated from the authoritative additive S+E+C point model
  (S1..3=1..3, E1..4=1..4, C1..3=1..3; ≤6 QM, 7 A, 8 B, 9 C, 10 D), verified
  directly against ISO 26262-3 Table 4 rather than against another tool. ASIL-D
  is now produced only by S3/E4/C3. This repo's own `.fusa-hara.json` ratings
  (H-001/H-003/H-004) were re-derived and are now QM.
- **`fmea`: `_has_args` counted `self`/`cls` as a real argument (#34).**
  Every class method with only `self`/`cls` counted as taking an argument,
  so `_derive_analysis()` emitted the fixed "invalid/out-of-range argument
  accepted without validation" triple for 96% of this repo's own fmea
  entries — exactly the blanket-fallback pattern the tool's own
  `FUSA-STUB002` content-quality check exists to catch. `_has_args` now
  drops the implicit `self`/`cls` parameter for methods.
- **`iec62443`: capabilities and gap-report emitted the non-canonical
  standard id `"iec62443"` (#35).** x-FuSa spec §2.4.1 defines
  `iec62443-4-1`/`iec62443-4-2` as the canonical ids; `"iec62443"` is a
  command name, never an id. `capabilities.standards[]`, the `iec62443`
  gap-report's `standard` field, and the four `IEC62443-*` check rules now
  emit `iec62443-4-1`/`iec62443-4-2` per their own clause.
- **`safety-case`: `completeness.undeveloped` measured per-strategy evidence
  presence, not GSN goal argument structure, and unconditionally gated the
  exit code (#36).** §9.2 defines `undeveloped` as goals with no supporting
  strategy/solution chain — not strategies whose cited evidence files are
  absent from disk. `totalGoals`/`undeveloped` are now derived from
  `nodes[]`/`edges[]`; the previous per-strategy signal survives as
  `goalsWithEvidence`. The exit-code gate on incompleteness is now opt-in
  via `--require-complete`, mirroring `--min-coverage`/`--strict` elsewhere.

## v0.3.0 — 2026-07-28

Adopts x-FuSa spec v1.15.0 and fixes five defects found by a deep-audit pass
that ran py-FuSa against its own codebase and diffed the real output against
the spec (`SoundMatt/py-FuSa` #26–#31).

### Fixed

- **`tara`: `impact` axes used the wrong enum vocabulary (#26).**
  `impact.{safety,financial,operational,privacy}` was emitted from a
  `low|medium|high|critical` scale — the same vocabulary reserved for
  `attackFeasibility` — instead of the spec's closed
  `critical|major|moderate|negligible` enum. Any consumer validating
  against the closed enum rejected every `tara.json` entry py-FuSa produced.
- **`tara`: risk computation silently defaulted to `"low"` for the
  highest-severity threats (#27).** `_compute_risk` looked up the risk
  combination table as `(feasibility, worst)` instead of `(worst,
  feasibility)`, and the table had no row for `worst == "critical"`. Command
  injection and SQL injection findings (feasibility `high`, impact
  `critical`) rated `risk: "low"` — the lowest possible value — instead of
  `"critical"`. Risk is now computed directly against the spec's canonical
  table, with every `worst` row covered so no combination falls through to
  a default.
- **`fmea`: test-fixture functions counted as project components, inflating
  `summary.coveragePct` past 100% (#28).** `fmea`'s file-discovery skip set
  didn't exclude the `tests`/`test` tree the way `trace --func-coverage`'s
  denominator already did, so a project with a nested test tree could see
  `coveragePct` values like `500%`. The two scanners now share one
  exclusion definition (`trace.EXCLUDED_SOURCE_DIRS`), and `fmea`/`tara`'s
  `coveragePct` also gained a defensive `min(pct, 100.0)` clamp per the
  spec's new §9.2 MUST.
- **`FUSA-STUB001`/`FUSA-STUB002` no longer gate `check`'s own exit code
  (#29).** These content-quality rules read committed sibling evidence
  artifacts (`fmea.json`, `tara.json`, `.fusa-hara.json`, `safety-case.json`,
  `sas.json`) and fed findings into `pyfusa check`'s result set — a
  committed-but-stale stub artifact could fail an unrelated `check` run.
  Per x-FuSa spec §1.6.1 ("Who runs this" — MUST), detection now runs only
  inside each artifact-producing command's own gate, which already
  implemented this correctly.
- **`sas`: the required `sas.md` companion was never written, and
  `--format` didn't accept `md` (#30).** `pyfusa sas --format json --output
  sas.json` — the exact invocation this project's own CI uses — produced
  only `sas.json`; the human-readable DO-178C §11.20 artifact was never
  generated. `sas` now always writes `sas.md` alongside whatever
  `--format`/`--output` was requested, and `--format md` is accepted.

### Added

- **x-FuSa spec v1.15.0 §1.6.2 attestation carry-forward (MUST).** Verified
  already correctly implemented across `fmea`/`tara`/`hara`/`safety-case`/
  `sas` (`content_quality.load_existing_attestation`, wired into each
  command's `to_dict`/`generate`) — added end-to-end regression tests
  covering both the carry-forward and the staleness-on-content-change path.

## v0.2.9 — 2026-07-28

Adopts x-FuSa spec v1.13.0/v1.14.0: real JSON schemas for the six evidence
commands, the cross-cutting content-quality baseline (§1.6), and coverage
metrics for `fmea`/`tara` (`SoundMatt/py-FuSa` #24).

### Added

- **`hara`/`fmea`/`tara`/`safety-case`/`sas`/`sci` schema conformance (§9.2/§9.3):**
  - `.fusa-hara.json`/`hara`: `safetyGoals[].fssrRefs` is now a **MUST, ≥1-entry
    array** (was a single optional `fssrRef` string); `init` scaffolds
    **empty** collections, never dummy rows; new referential-integrity checks
    (`HARA006`/`HARA007`/`HARA008`) for missing/dangling `fssrRefs` and
    dangling `operationalSituations` references; `hara --format json` now
    emits the §3.1 header, the file's content verbatim, and a `completeness`
    roll-up (`hara-report` kind).
  - `fmea`: canonical `entries[]` shape (`item` = `Component.Function`,
    `failureMode`/`effect`/`cause`/`actionPriority`/`mitigations`), each
    derived from the function's actual signature/behaviour rather than one
    fixed string per entry.
  - `tara`: canonical `threats[]` key (was `entries`); `impact` is now an
    **SFOP object** (`safety`/`financial`/`operational`/`privacy`, ISO 21434
    Clause 15.7) instead of one generic severity; adds `attackVector`,
    `attackFeasibility`, `risk`, `treatment`.
  - `safety-case`: real **GSN** (`nodes[]`/`edges[]`) with all six node types
    (`goal`/`strategy`/`solution`/`context`/`assumption`/`justification`) and
    edge types (`supportedBy`/`inContextOf`), plus a `completeness` block
    (was a bespoke `evidence[]`/`clauses[]`/`gaps[]` shape).
  - `sas`: `checklist[]`/`summary` per DO-178C §11.20 (was `sections[]`).
  - `sci`: `artifacts[]` with a **real per-file `sha256:`-prefixed hash** of
    current file content (was a presence-only `items[]` list) — closes a
    real gap where `sci` never actually hashed anything.
  - `kind` corrected to `fmea-report`/`tara-report` (was `fmea`/`tara`) per
    §3.1.
- **§1.6.1 content-quality baseline — `FUSA-STUB001`/`FUSA-STUB002`:** a new
  `pyfusa/content_quality.py` module implements both detection heuristics —
  a deny-list placeholder-text scan (`FUSA-STUB001`, always `ERROR`,
  disposition-suppressible only) and a distinct-value-ratio blanket-fallback
  scan (`FUSA-STUB002`, `WARNING` by default, ≥10 entries). Wired into
  `fmea`/`hara`/`tara`/`safety-case`/`sas` directly (scanning the
  just-generated document) and into `check` via two new engine rules
  (`FUSASTUB001`/`FUSASTUB002` in `pyfusa/rules/evidence.py`) that scan any
  already-committed evidence file.
- **§1.6.2 attestation:** an artifact may carry a document-level
  `attestation` object (`status`/`implementationAuthor`/`independentReviewer`/
  `reviewedAt`/`contentHash`); a non-stale, genuinely-independent `"reviewed"`
  attestation suppresses `FUSA-STUB002`. `fmea`/`hara`/`tara`/`safety-case`/
  `sas` gained `--require-attestation` (and `--strict` implies it), escalating
  an unsuppressed `FUSA-STUB002` to exit 1.
- **`fmea`/`tara` coverage metrics:** `summary.componentsAnalyzed` /
  `componentsInProject` / `coveragePct` (`fmea`, same denominator as
  `trace --func-coverage`) and `summary.assetsAnalyzed` / `assetsInProject` /
  `coveragePct` / `assetInventoryMethod` (`tara`, a documented file-level
  proxy — not a formal asset inventory), plus `--min-coverage N` on both.

### Fixed

- `.fusa-hara.json` (this project's own dogfooded file) carried
  severity/exposure/controllability ratings whose declared ASIL disagreed with
  the value derived from ISO 26262-3 Table 4 (the additive S+E+C point model;
  e.g. S2/E4/C2 = ASIL-B at point sum 8, and the shipped S2/E2/C2 hazards = QM
  at point sum 6). Corrected the four hazards' declared ASILs to the values that
  genuinely derive from their S/E/C ratings.

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
