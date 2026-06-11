# Changelog

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
