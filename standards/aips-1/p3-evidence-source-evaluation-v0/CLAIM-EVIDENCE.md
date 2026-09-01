# Claim/evidence ledger

This ledger separates upstream facts, local test results, and proposal choices.
`Supported` means only that the cited artifact supports the bounded wording in
that row. It does not mean AIPS-1 has reviewed or accepted this package.

| ID | Claim | Type | Evidence | Assessment and limit |
|---|---|---|---|---|
| C01 | AIPS-1 identifies v0.1 as a draft for public comment and gives 30 November 2026 as the closing date. | Current first-party fact | `SOURCES.md` A1, A2; `source-lock.json` | Supported as of the 2026-09-01 source read. Recheck before submission. |
| C02 | P3 requires Trigger predicates evaluable against declared Evidence Sources and excludes triggers depending solely on issuer opinion or undefined external conditions. | Primary specification fact | `SOURCES.md` A2, Sections 2.2 and 4 | Supported. The local profile does not widen this into a coverage or liability rule. |
| C03 | AIPS-1 v0.1 describes `triggers` at a high level and gives one worked oracle predicate, but the pinned tree has no Trigger schema or reference verifier implementation. | Primary-source and repository-tree fact | `SOURCES.md` A2, A3; pinned `schemas/README.md`; pinned `reference/README.md` | Supported at upstream commit `280a8ba0e9c2658ee6af10778e0f6a2fb669661d`. Later upstream work may change this. |
| C04 | The official-site and commit-pinned v0.1 PDFs are not byte-identical. | Artifact comparison | `source-lock.json`; `SOURCES.md`, Upstream variance | Supported by the two recorded SHA-256 digests. The P3 passages used here have the same substantive wording in both reviewed copies. |
| C05 | The upstream repository uses CC0 1.0 Universal; this EMILIA package is under the repository's Apache-2.0 license. | License fact | Pinned upstream `LICENSE`; repository root `LICENSE`; `SOURCES.md` | Supported. CC0's express exclusions remain in the upstream legal text. |
| C06 | The local evaluator has exactly three verdicts and keeps them separate from authorization, coverage, liability, claim acceptance, and payout. | Local implementation claim | `evaluate.mjs`; `evaluation-report.schema.json`; self-test “exports exactly the three closed lab trigger verdicts”; scope self-test | Supported for this repository-local version. These are not native AIPS-1 or EP-AEC verdicts. |
| C07 | Missing, unavailable, stale, unsupported, unpinned, ambiguous, conflicting, sole-issuer-opinion, or value-missing evidence produces `INDETERMINATE`, not a false trigger result. | Local behavioral claim | `evaluate.selftest.mjs`; `vectors/cases.json`; `report.json` | Supported for the exercised local cases. The fixtures do not prove external source truth. |
| C08 | `NOT_SATISFIED` is returned only for a determinate false local comparison. | Local behavioral claim | determinate-false self-test; vector pair `indeterminate-dominance` | Supported. If another predicate is unevaluable, the case is instead `INDETERMINATE`. |
| C09 | The only local combiner is `ALL`, and indeterminacy dominates a determinate false predicate. | Local profile choice | `evaluate.mjs`; `SPECIFICATION.md`, Section 8; `indeterminate-dominance` vectors | By construction. This is not attributed to AIPS-1. |
| C10 | Profile and observation pins cover locator, revision, JSON format, basis, canonical parsed-data digest, and freshness. Reports bind the canonical profile and evidence set and include bounded source snapshots. | Local implementation claim | `evaluate.mjs`; `evaluation-profile.schema.json`; `evidence-set.schema.json`; `evaluation-report.schema.json`; digest-binding, pin, and freshness self-tests | Supported structurally. The evaluator does not retrieve a locator, authenticate metadata, or hash raw source-response bytes. |
| C11 | The checked vector corpus has 20 cases in 10 control/hostile pairs, and all expected verdicts and reason codes match. | Generated local result | `vectors/cases.json`; `report.json`; generator self-tests | Supported by `report.json`: 10 controls, 10 hostile cases, zero mismatches. |
| C12 | The generated corpus contains nine `SATISFIED`, one `NOT_SATISFIED`, and ten `INDETERMINATE` results. | Generated local result | `report.json` | Supported for corpus digest `sha256:92a80bc1b1739e892f01900f1026e91042f0a086cbd78e9bba3e92000b7d31d1`. This is test distribution, not an external performance rate. |
| C13 | The checked-in corpus report is byte-stable and binds the source lock, report schema, evaluator, and generator bytes. | Local reproducibility claim | `generate-report.mjs`; `corpus-report.schema.json`; artifact-binding and report-determinism self-tests; `node generate-report.mjs --check` | Supported for the named working-tree bytes. The binding is a digest link, not a signature or third-party attestation. |
| C14 | The self-test file contains 44 passing tests in the current local run. | Time-bounded local test result | `evaluate.selftest.mjs`; `node --test evaluate.selftest.mjs` on 2026-09-01 | Supported for the tested working tree. This is same-team test evidence, not independent implementation evidence. |
| C15 | The evaluator is offline and does not authenticate sources, verify signatures, establish evidence truth, or apply an AIPS Policy Certificate. | Negative implementation claim | `evaluate.mjs`; `README.md`; `SPECIFICATION.md`, Sections 1 and 12 | Supported by code inspection and scope fields. Supplied fixture metadata remains an assumption. |
| C16 | This package is not a native AIPS verifier, coverage decision, liability rule, AEB adapter, CAID mapping, adoption claim, or endorsement claim. | Normative scope choice | `README.md`; `SPECIFICATION.md`; report `scope`; `COMMENT.md` | By construction. Any excerpt or submission must preserve this boundary. |
| C17 | `COMMENT.md` is staged text and has not been submitted. | Local workflow state | `COMMENT.md` status; no outbound receipt in this package | Supported only as repository state. Submission is a separate external action. |
| C18 | The evaluator supports the RFC 6901 root pointer and rejects duplicate object members, impossible calendar dates, non-canonical array indexes, unsafe numeric tokens, mutable programmatic accessors, and inputs over explicit resource limits without producing a false result. The corpus generator rejects inherited and prototype-bearing mutation paths. | Local defensive-behavior claim | `evaluate.mjs`; `generate-report.mjs`; root-pointer, strict-parser, timestamp, pointer, numeric-alias, inert-input, bounded-input, and mutation-path self-tests | Supported for the exercised local cases. This is not an external security assessment. |

## Open evidence gaps

- No upstream review, acceptance, adoption, or endorsement of the proposal.
- No native AIPS-1 predicate schema or reference-verifier result against this
  package at the pinned upstream revision.
- No independent implementation or external reproduction of the local
  evaluator.
- No live retrieval, signature verification, trust-anchor validation, or
  evidence-truth check.
- No coverage, liability, claim-acceptance, settlement, or payout decision.
- The official-site PDF is mutable and differs from the pinned GitHub PDF;
  refresh both sources immediately before external submission.
