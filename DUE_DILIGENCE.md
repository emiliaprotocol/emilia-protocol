<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public Due-Diligence Evidence

This file maps the public evidence a technical, security, standards, or
procurement reviewer can reproduce. It is not a certification, legal opinion,
or substitute for the company's private corporate data room.

- **Reviewed technical baseline:** [`632c425b`](https://github.com/emiliaprotocol/emilia-protocol/commit/632c425b)
- **Reviewed:** 2026-08-07 PDT
- **Scope:** source, tests, conformance, formal models, executable security
  evidence, repository controls, release process, and attribution provenance
- **Not established:** production deployment parity, customer adoption,
  regulatory approval, IETF adoption, accredited assurance, legal chain of
  title, or physical truth outside an observed and signed evidence boundary

The commit containing this documentation may be newer than the reviewed
baseline. It changes the evidence map, not the reviewed implementation.

## Executive status

| Area | Current public evidence | Remaining diligence item |
| --- | --- | --- |
| Tests and build | **8,755 tests across 521 files** in [`lib/proof-stats.json`](lib/proof-stats.json); the production Next.js build passes. | Passing tests are scoped regression evidence, not whole-system proof. |
| Executable security case | **35 claims over 259 hashed evidence files**, execution passed, bundle SHA-256 `93c45678c5812ae07cb62a6eeb1f5193689589a2346887671db0c3425f5f6596`. | Repository-defined assurance is not an accredited audit. |
| Conformance | **21 suites and 331 vectors** across JavaScript, Python, and Go same-team ports; a source-free 30-file clean-room v2 kit rebuilds byte-for-byte. | Strict independent clean-room acceptance remains false until a separately attested implementation is accepted. |
| Formal evidence | 26 principal TLC invariants; 78 selected model/runtime scenarios with 51 paired negative controls; 20 Tamarin obligations and 8 deliberately unsafe counterexamples; 35 Alloy facts and 32 assertions. | These are bounded or symbolic models under stated assumptions, not mechanized whole-program refinement. |
| Dependencies and releases | Root and nested production audits report zero known vulnerabilities; release-chain validation covers **26 packages**; packed exports pass for 12 packages. | Publish an SBOM and third-party notice bundle with each release. |
| Secrets and licensing | Full-history Gitleaks scan found no secret; repository-boundary and Apache-2.0 header checks pass; every public package manifest declares a license. | Repeat scans in CI and during a transaction-specific data-room export. |
| GitHub controls | `main` has 16 strict required checks, one approval, Code Owner and latest-push review, stale-review dismissal, conversation resolution, no force-push, no deletion, read-only workflow tokens, and immutable release-tag rules. | Add a second human owner/reviewer, enforce rules for administrators, require signed commits, verify the organization domain, and then consider two approvals. |
| AI-assisted development | Human accountability and future attribution rules are public in [`docs/AI-ASSISTED-DEVELOPMENT.md`](docs/AI-ASSISTED-DEVELOPMENT.md). | Complete counsel-led chain-of-title review in the private data room. |

## Security hardening in this review

Commit [`40a4044c`](https://github.com/emiliaprotocol/emilia-protocol/commit/40a4044c)
closes a pre-authentication denial-of-service control defect: an unverified
Bearer prefix previously contributed to the edge rate-limit key, so an attacker
could rotate fake prefixes to obtain fresh buckets. The edge limiter now keys
on source IP before authentication; authenticated services may add a second
verified tenant or session limit. A regression proves two different fake
Bearer values resolve to the same pre-auth bucket.

The same commit:

- pins AES-256-GCM poll-token encryption and decryption to a 16-byte tag;
- makes A2A extension negotiation an explicit exact-string comparison; and
- adds a hostile lookalike-extension case.

At the start of this review, GitHub showed two open high-severity CodeQL alerts
for the former A2A `Array.includes` expressions. The expressions performed
exact array membership, not URL substring validation, but visible high alerts
are still diligence debt. The replacement preserves exact semantics and lets a
fresh CodeQL run close the false positives. Alert closure must be checked on the
live repository; this document does not predeclare it.

The regenerated assurance case is in commit
[`c8163a9c`](https://github.com/emiliaprotocol/emilia-protocol/commit/c8163a9c),
and the clean-room consumer pins are synchronized in
[`4d4aec96`](https://github.com/emiliaprotocol/emilia-protocol/commit/4d4aec96).

## Reproducible evidence

The authoritative generated summary is
[`lib/proof-stats.json`](lib/proof-stats.json). Review the underlying files and
boundaries rather than treating aggregate counts as proof.

Current measured evidence includes:

- 8,755 tests across 521 files;
- 35 executable claims over 259 content-addressed evidence files;
- 21 suites and 331 conformance vectors;
- 78 selected model/runtime scenarios, 51 paired negative controls, and 21
  claims under explicit projection relations;
- two formally verified obligations linked to runtime claims, 21 bounded
  runtime-traced claims, one bounded formal-evidence claim, and 11 executable
  operational-evidence claims; and
- 85 catalogued red-team cases.

The explicit boundary in the generated file is load-bearing: selected scenario
conformance is **not** a mechanized implementation-refinement proof.

The security-case generator re-executes evidence instead of trusting committed
verdicts. During this review it correctly refused to certify a dirty checkout,
a stale conformance manifest, and stale clean-room pins. After those inputs were
committed and synchronized, the same checks passed.

## Dependency, license, and release evidence

The review ran:

- `npm audit --omit=dev` at the root and in every nested production package;
- `npm run check:release-chain` across 20 npm, five PyPI, and one Go package;
- `npm run check:packed-package-exports` across 12 packed packages;
- `node scripts/check-license-headers.js`;
- `npm run check:repository-boundary`; and
- a full-history Gitleaks scan over all refs.

All passed. Package publication uses repository workflows with OIDC and
provenance, but source versions, Git tags, GitHub releases, candidate tarball
hashes, and registry publication are separate states. Verify the registry and
tag for every package included in a transaction; do not infer publication from
`package.json` alone.

The repository can emit a CycloneDX 1.5 SBOM, but no governed SBOM or complete
third-party notice bundle was found as a checked-in or release-attached artifact
in this review. Adding both is the remaining supply-chain documentation task.

## Repository governance

Live GitHub settings on 2026-08-07 established:

- 16 strict required checks on `main`;
- one approval, Code Owner review, latest-push approval, stale-review dismissal,
  and conversation resolution;
- force-push and branch deletion disabled;
- workflow tokens read-only and unable to approve pull requests; and
- immutable release-tag rules without a bypass actor.

The repository is not yet independently governed. The organization has one
member, administrator enforcement is disabled, required signed commits are
disabled, and the organization domain is not verified. These are governance
gaps, not cryptographic defects. Add a genuine second human maintainer before
turning on controls that would otherwise make the sole-owner workflow
inoperable.

Six pull requests were open at the start of the review. PRs #522 and #524 were
closed as superseded after their verified security and dependency changes were
confirmed on `main`. Four remain: #520 and #523 are conflicting review branches,
while #525 and #526 are draft branches behind `main`. Each should be resolved or
closed on its own technical merits so an acquirer does not have to infer status
from branch age.

## AI attribution and human responsibility

The tracked repository contains tool instructions such as `AGENTS.md`,
`CLAUDE.md`, and `GEMINI.md`. They are reproducibility and operating controls,
not corporate titles or ownership claims, and should remain public.

The history contains **1,141 commits** with a Claude or Anthropic
`Co-authored-by` trailer and no Codex or OpenAI co-author trailers as of this
review. Those trailers are conspicuous provenance metadata. They are not a
substitute for human authorship, DCO sign-off, invention records, or assignment.
Published history should not be rewritten to remove them: rewriting would
change commit and tag identities and weaken release provenance.

Going forward, commits must identify the accountable natural person, carry that
person's DCO sign-off, and must not name an AI system as co-author. Optional
`Assisted-by` metadata may disclose tool use without assigning authorship.
AI systems must never be listed as corporate officers, maintainers of record,
standards or scientific authors, patent inventors, copyright claimants,
reviewers, approvers, or DCO signers.

## Private corporate data-room checklist

The public repository cannot close corporate ownership diligence. Counsel and
the company should retain and review:

1. founder invention and IP assignment to the operating company;
2. employee and contractor confidentiality and invention-assignment agreements;
3. the founder's current-employer conflict disclosure, written carve-out, or
   other counsel-approved evidence that EMILIA was built outside employer scope;
4. contributor provenance and DCO records for non-founder contributions;
5. AI-tool commercial terms, account ownership, and payment records applicable
   when material code was generated;
6. patent inventorship files naming natural persons and documenting conception;
7. cap table, board approvals, officer records, and signing authority; and
8. customer, deployment, security-assessment, and regulatory claims with exact
   scope and issuer evidence.

This is the largest remaining diligence risk because it cannot be solved by a
clean GitHub repository alone.

## Standards, deployment, and adoption boundaries

`standards/posted/` is evidence of published text; the live IETF Datatracker is
authoritative for revision and adoption status. Individual Internet-Drafts are
not RFCs, working-group adoption, IETF consensus, or endorsement. Staged drafts
are not filings.

Repository migrations, examples, deployment code, and passing integration tests
do not prove that the same commit, schema, secrets, or configuration is live in
production. This review did not refresh private production state. Likewise,
control mappings and partner-facing material do not establish certification,
customer adoption, an independent operator network, or physical-hardware
attestation.

## Reproduction entry points

```bash
git fetch origin
git rev-parse origin/main
npm ci
npm run test:run
npm run build
npm run check:proof-stats
npm run check:security-case
npm run conformance:manifest:check
npm run conformance:clean-room:v2:selftest
npm run check:release-chain
npm run check:packed-package-exports
npm run check:repository-boundary
npm audit --omit=dev
```

Formal rerun instructions are in [`formal/RUN_TLC.md`](formal/RUN_TLC.md),
[`formal/RUN_ALLOY.md`](formal/RUN_ALLOY.md), and
[`formal/tamarin/README.md`](formal/tamarin/README.md). Some formal checks
require separately installed toolchains. Private deployment checks require
authorized read-only access and are intentionally not reproducible from this
public repository.
