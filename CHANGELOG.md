# Changelog

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
