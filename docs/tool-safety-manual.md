# py-FuSa Tool Safety Manual

**Version:** 0.4.0
**Binary:** `pyfusa`
**Repository:** `github.com/SoundMatt/py-FuSa`
**License:** Mozilla Public License 2.0
**Standards addressed:** ISO 26262, IEC 61508, ISO 21434, UNECE R155/R156, DO-178C
**Spec conformance:** x-FuSa specification v1.15.2 (self-assessed, see README §x-FuSa spec conformance)

---

## 0. Status of this document

py-FuSa is a **`3 - Alpha`** tool (see `pyproject.toml` classifiers and the
README's self-assessed conformance disclaimer). This manual is a **minimal,
honest stub**, not a completed qualification package. It exists so that a
team evaluating py-FuSa has a single place to see what evidence already
exists and what is still outstanding, mirroring the structure of the
equivalent document in the more mature x-FuSa tools (e.g. `cpp-FuSa`,
`go-FuSa`).

**Not yet present, tracked as future work:**

- An independent tool-qualification report per ISO 26262-8 / IEC 61508-3
  criteria (`pyfusa qualify` produces self-test evidence today; it is not a
  substitute for an independent qualification argument).
- A `docs/qualification.md` walking through the qualification argument.
- A `ROADMAP.md`.

Until those exist, treat every claim below as "as implemented today," not as
a certification argument. Do not cite this document as evidence of
independent tool qualification.

## 1. Purpose

This document describes py-FuSa's tool classification and safety-relevant
behaviour for teams that want to reference it while building their own
safety case. It is intended for:

- Engineering teams assessing py-FuSa for use on safety-related Python code
- Auditors reviewing what py-FuSa does and does not verify
- Contributors who need to understand py-FuSa's own safety commitments to
  itself (`.fusa.json`, `.fusa-hara.json` — see README §Standards)

## 2. Tool overview

py-FuSa is a functional safety enablement toolkit for Python projects: static
checks, coding rules, traceability helpers, CI evidence bundles, and
compliance gap reporting across ISO 26262, IEC 61508, ISO 21434, and
DO-178C. It is **not** a certification product — it reduces the cost of
producing functional safety evidence; it does not itself certify anything.

Representative capabilities (see README §Quick start and §Safety rules for
the full, current command surface):

| Capability | Command |
|---|---|
| Project structure / evidence-presence checks | `pyfusa check` |
| Requirements traceability | `pyfusa trace` |
| Hazard Analysis and Risk Assessment (§1.2.5) | `pyfusa hara` |
| Tool qualification self-test suite | `pyfusa qualify` |
| SBOM / provenance / artifact manifest | `pyfusa release` |
| Evidence ZIP bundle | `pyfusa audit-pack` |
| Test evidence collection | `pyfusa verify` |
| Compliance gap reports | `pyfusa iso26262`, `iec61508`, `do178`, `iso21434`, `unece`, `iec62443`, `slsa` |
| Cyclomatic complexity (DO-178C §6.3.4) | `pyfusa comp` |
| Structural coverage report | `pyfusa coverage` |

## 3. Tool classification

### ISO 26262-8 / IEC 61508-3 assessment

py-FuSa is a **software development support tool**. Its potential impact on
software under development:

- **Indirect** — it reports findings but does not modify, compile, or
  execute the target software as part of its own analysis (the exception is
  `pyfusa verify`/`pyfusa coverage`, which do invoke the target project's own
  test suite; see §5 trust boundary note below).
- **No direct output** is incorporated into the analyzed software's runtime
  behaviour.

| Criterion | Assessment |
|---|---|
| Tool output directly in safety-critical code? | No |
| Tool failure could mask a real defect? | Possible (a false "no finding" is an error of omission) — see §4 |
| Tool failure could inject a new defect? | No — py-FuSa does not modify analyzed source |

A rigorous TCL (Tool Confidence Level) / T2/T3 classification per project
context is the responsibility of the adopting team; py-FuSa does not assert
one for itself here.

## 4. Known limitations (as of v0.3.3)

- The ASIL determination table (`pyfusa/hara.py:_S_POINTS`/`_E_POINTS`/
  `_C_POINTS`/`_POINT_ASIL`) was corrected in this release from a defective
  implementation that inflated ASIL ranks for S2/S3 hazards — see
  `CHANGELOG.md`. Projects that ran `pyfusa hara` before this fix should
  re-run it and review any `.fusa-hara.json` ASIL values that were
  previously derived by the tool.
- py-FuSa is self-assessed against the x-FuSa spec (README §x-FuSa spec
  conformance) — conformance has not been independently audited end-to-end
  beyond the third-party review that produced the fixes in this release.
- `pyfusa verify` and `pyfusa coverage` execute the target project's test
  suite as a subprocess; running either against an untrusted repository
  executes that repository's code with the invoking user's privileges.
  Treat these commands like any other "run the tests" step in CI.

## 5. Roadmap

See §0 above. This manual will grow alongside `docs/qualification.md` and
`ROADMAP.md` as py-FuSa moves out of alpha; contributions are welcome via
pull request.

## Standards

py-FuSa is itself developed as an ISO 26262 ASIL-B tool. See `.fusa.json` and
`.fusa-hara.json` in the repository root.
