<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public Due-Diligence Evidence

This is a point-in-time map of evidence a technical, security, standards, or
procurement reviewer can inspect without treating repository claims as
certification.

- **Source snapshot:** [`origin/main` at `1832dd0c`](https://github.com/emiliaprotocol/emilia-protocol/commit/1832dd0ce17e747ea8371d54d7e2752111b691cc)
- **Reviewed:** 2026-07-18 PDT / 2026-07-19 UTC
- **Scope:** public source, tests, conformance, formal models, security evidence,
  production migration state, and public releases
- **Not established by this document:** regulatory approval, IETF adoption,
  customer adoption, an independent-operator network, an accredited audit, or
  physical-hardware attestation

## Status summary

| Area | Evidence established | Boundary |
| --- | --- | --- |
| Source and CI | The reviewed commit is on `main`. Its [CI run](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618048), [security scan](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618050), [secret scan](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618016), [CodeQL](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618029), [Scorecard](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618011), [schema-security](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618042), and [security-kernel mutation gate](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29679618025) completed successfully. | Green repository checks do not prove that the same commit, configuration, or schema is serving every production request. |
| Automated tests | The checked-in Linux CI evidence records **6,872 tests across 359 files**. The head CI test, conformance, security-case, integration, build, E2E, and generated-proof-stat jobs passed. | Test counts and passing suites are scoped regression evidence, not proof that every possible input, deployment configuration, or downstream effect is safe. |
| Executable security case | [`security/security-case.json`](security/security-case.json) resolves **28 claims** over **140 hashed evidence files** and records a passing executed evidence set. The head CI `security-case` job passed. | This is a repository-defined assurance case with explicit assumptions and exclusions, not an accredited certification or a substitute for deployment testing. |
| Production database | A read-only check of the linked production migration ledger found **135 applied migrations**, latest `20260719043735_capability_operation_action_binding`. The corresponding `ep_capability_operations` columns and four named constraints were present in the production catalog. | This is maintainer-verifiable operational evidence, not publicly reproducible from GitHub alone. It proves migration/catalog state, not application deployment, secrets/configuration, data correctness, or closure of an external attack-chain retest. |
| GitHub security and governance | `main` requires 16 strict status checks, one approval, Code Owner review, approval of the latest push, stale-review dismissal, and conversation resolution. Force-pushes and branch deletion are disabled. Release-tag families are covered by an active immutable-tag ruleset. At review time, open CodeQL, Dependabot, and secret-scanning alert counts were all zero. | Administrator enforcement remains disabled while the organization has one owner. A genuine second owner/reviewer and verified organization domain remain open governance milestones; zero open platform alerts is not a guarantee that no vulnerability exists. |
| Releases | Public package registries and GitHub releases were checked separately from `main`; see [Release state](#release-state). | A package version in source, a candidate tarball hash, a Git tag, and a registry publication are four different states. |
| Standards | Public Datatracker documents are active **individual Internet-Drafts**. | They are not RFCs, working-group-adopted documents, standards-track approvals, or IETF endorsement. Staged repository drafts are not filings. |
| External milestones | A separately authored Rust verifier has pinned interoperability results, and two separately deployed EMILIA-operated federation endpoints exercise the cross-operator mechanism. | Strict independently attested clean-room acceptance is still zero, both federation operators have the same owner, and no independent third-party operator is established. |
| Hardware attestation | WebAuthn/mobile and TPM verification code is shipped and tested. | The public TPM fixture is software-TPM evidence, not physical hardware. No manufacturer/EK-backed TPM enrollment artifact or retained physical-device hostile-release record was found in this snapshot. |

## Tests, conformance, and security evidence

The repository's generated test count is in
[`lib/proof-stats.json`](lib/proof-stats.json). The reviewed head CI independently
ran the Vitest suite, package tests, cross-language conformance, Postgres
integration, schema contracts, fuzzing, E2E smoke tests, secret scanning, and a
production build.

The current same-team reference ports are JavaScript, Python, and Go. They agree
over **21 suites and 328 vectors** according to
[`conformance/conformance-manifest.json`](conformance/conformance-manifest.json).
That is a cross-language consistency result across one team's ports, not three
independent implementations.

The separately authored Rust verifier is pinned in
[`conformance/external/rust-cleanroom-jdieselny.v1.json`](conformance/external/rust-cleanroom-jdieselny.v1.json).
It records:

- 16 suites and 164 vectors passed against a time-pinned bundle;
- 359 structured and parser-hostility cases passed in the pinned evaluator run;
- `third_party_attestation: false`; and
- `strict_clean_room_acceptance: false`, because the available signed
  construction statement predates and does not attest the pinned hardening
  commit.

The executable security case is stronger than an undifferentiated test count:
each claim identifies enforcement paths, positive and negative vectors,
language coverage, formal coverage or a stated gap, trust assumptions,
exclusions, and content-addressed evidence. Reviewers should inspect the claim
record rather than infer whole-system security from the aggregate number.

The mutation baselines are also scoped regression oracles, not proofs:

- security kernel: **90.34%** total mutation score with a 90% breaking floor
  ([status](security/MUTATION_STATUS.md));
- Authorization Evidence Chain: **80.15%** with an 80% floor
  ([status](security/AEC_MUTATION_STATUS.md)); and
- Model-to-Matter reference implementation: **82.22%** with an 80% floor
  ([status](security/MODEL_TO_MATTER_MUTATION_STATUS.md)).

## Formal methods

The formal artifacts are checked into [`formal/`](formal/) and are CI-gated.
They prove properties of bounded or symbolic models under their stated
assumptions; they do not prove the deployed application as a whole.

| Method | Current public evidence | Important scope |
| --- | --- | --- |
| TLA+ / TLC | The handshake and identity-continuity configuration contains **26 invariants**. The capability configuration adds **10 invariants**. The [latest TLC run](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29669525965) completed successfully for both models. | The headline 26 in `lib/proof-stats.json` counts the handshake configuration only. The principal exhaustive result uses one handshake and one claim; multi-handshake exploration is bounded, not an unbounded concurrency proof. |
| Alloy | **35 facts and 32 assertions across four models**, plus satisfiability runs, execute headlessly under Alloy 6.2.0. The [latest Alloy run](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29672325113) completed successfully. | Alloy checks finite scopes (principally 6 or 8), so “no counterexample” means no counterexample within those scopes. |
| Tamarin | The composed Dolev-Yao model records **10 verified strict obligations** and **2 deliberately unsafe comparison obligations with concrete counterexample traces**. Standalone receipt and quorum models are gated in the [latest Tamarin run](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/29670362760). | The models abstract or scope out items including WebAuthn internals, hardware custody, canonical parser implementation, human perception, arbitrary quorum sizes, complete deployment configuration, and downstream physical effects. |

The detailed model claims, state counts, counterexamples, and exclusions are in
[`formal/PROOF_STATUS.md`](formal/PROOF_STATUS.md) and
[`formal/tamarin/README.md`](formal/tamarin/README.md).

## Security assessment boundary

The public repository supports these claims:

- a coordinated vulnerability-disclosure policy exists in
  [`SECURITY.md`](SECURITY.md);
- the security acknowledgments name one outside reporter whose two findings are
  recorded as remediated and production-retested by that reporter;
- a March 2026 Shannon-framework remediation summary records 31 findings and
  31 remediations in
  [`docs/security/PENTEST_REMEDIATION.md`](docs/security/PENTEST_REMEDIATION.md);
  and
- current repository CI, schema-security, CodeQL, secret-scanning, mutation,
  conformance, and security-case checks are green at the reviewed commit.

The public evidence does **not** justify calling the current system externally
certified or the latest hostile review closed. In particular,
[`docs/security/STRIX_REMEDIATION_2026-07-18.md`](docs/security/STRIX_REMEDIATION_2026-07-18.md)
labels itself an **active retest, not a closure memo**. It separates branch
controls from deployment and live retest. The successful production migration
check above closes the migration-ledger question for this snapshot, but it does
not establish application deployment or completion of the active external
retest.

The Shannon document is a remediation summary, not a raw signed third-party
report or accreditation artifact. It should be described as a recorded
framework assessment and remediation campaign unless independent provenance is
provided separately.

## Repository security and governance

The following settings were read from the live GitHub repository during this
review:

- `main` uses strict branch protection with 16 required checks;
- pull requests require one approval, Code Owner review, approval after the
  latest push, dismissal of stale approvals, and resolution of conversations;
- force-pushes and deletion of `main` are disabled;
- workflow tokens default to read-only and cannot approve pull requests;
- secret scanning, push protection, Dependabot security updates, and code
  scanning are enabled;
- open CodeQL, Dependabot, and secret-scanning alert counts were all zero; and
- the active release-tag ruleset blocks updates and deletion across every
  release/evidence tag family present at the time of review.

These are strong repository controls, not a claim of independent governance.
Administrator enforcement is not enabled because the organization currently
has one owner. The open governance milestone is to add a genuine independent
second owner/reviewer, then require administrator compliance and consider two
approvals. GitHub organization-domain verification also remains pending the
required DNS proof. The organization and repository descriptions, homepage,
license, and discoverability topics were updated to identify EMILIA as an
open-protocol consequence firewall without claiming certification, adoption, or
standards endorsement.

## Production-applied migrations

Repository migration files establish intended database changes; they do not by
themselves establish production application. For this review, a read-only query
was made against the linked production database:

```text
applied migration rows: 135
latest version: 20260719043735
latest name: capability_operation_action_binding
```

The catalog also contained the four columns introduced or reconciled by that
migration, with `action_digest` non-null, and these constraints:

```text
ep_capability_operations_action_digest_check
ep_capability_operations_reconciliation_complete_check
ep_capability_operations_reconciliation_evidence_digest_check
ep_capability_operations_reconciliation_outcome_check
```

The source migration is
[`supabase/migrations/20260719043735_capability_operation_action_binding.sql`](supabase/migrations/20260719043735_capability_operation_action_binding.sql).
No credentials, project identifier, customer data, or private configuration are
published here.

## Release state

The root repository's latest full GitHub Release is
[`v1.0.0`](https://github.com/emiliaprotocol/emilia-protocol/releases/tag/v1.0.0),
published 2026-03-27. The
[`clean-room-kit-v1`](https://github.com/emiliaprotocol/emilia-protocol/releases/tag/clean-room-kit-v1)
release is marked prerelease. The reviewed `main` is 1,438 commits ahead of the
root `v1.0.0` tag, so the root release must not be used as evidence that all
current `main` features are released.

| Component | Source at reviewed `main` | Public registry checked during review | Due-diligence conclusion |
| --- | --- | --- | --- |
| `@emilia-protocol/gate` | `0.12.0` | [`0.11.0` on npm](https://www.npmjs.com/package/@emilia-protocol/gate/v/0.11.0) | The current Gate/Marvel source is ahead of the published package. Candidate `0.12.0` tarball hashes in the security case are not registry publication evidence. |
| `@emilia-protocol/verify` | `3.11.0` | [`3.11.0` on npm](https://www.npmjs.com/package/@emilia-protocol/verify/v/3.11.0) | The version matches, but the package tree on `main` has changed since the release tag. Post-tag changes are not in the registry artifact merely because the version string is unchanged. |
| `@emilia-protocol/mobile` | `0.1.1` | [`0.1.1` on npm](https://www.npmjs.com/package/@emilia-protocol/mobile/v/0.1.1) | The package tree matched its release tag in this review. Publishing the server-side package does not publish the native apps. |
| `@emilia-protocol/mcp-server` | `1.1.1` | [`1.1.1` on npm](https://www.npmjs.com/package/@emilia-protocol/mcp-server/v/1.1.1) | The package tree matched its release tag in this review. |

The release manifest in
[`release/release-packages.v1.json`](release/release-packages.v1.json) maps
package paths to tag prefixes and publishing workflows. It is release-process
evidence, not proof that any individual workflow ran or that a registry accepted
the artifact. Registry state and tags were therefore checked independently.

## Standards status

The live IETF Datatracker, not a repository filename, is authoritative for
filing status. On July 19, 2026, the following published TXT artifacts were
verified byte-for-byte against their local snapshots:

- [CAID, revision 00](https://datatracker.ietf.org/doc/draft-schrock-canonical-action-identifier/)
- [Architecture, revision 01](https://datatracker.ietf.org/doc/draft-schrock-ep-architecture/)
- [Authority Introduction, revision 01](https://datatracker.ietf.org/doc/draft-schrock-ep-authority-introduction/)
- [Authorization Receipts, revision 07](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/)
- [EP-QUORUM, revision 03](https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/)
- [Bounded Capability Receipts, revision 00](https://datatracker.ietf.org/doc/draft-schrock-ep-bounded-capability-receipts/)
- [EP-AEC, revision 03](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-evidence-chain/)
- [Model-to-Matter, revision 00](https://datatracker.ietf.org/doc/draft-schrock-model-to-matter/)

Datatracker labels each as an **Active Internet-Draft (individual)** and states
that an Internet-Draft is not IETF-endorsed and has no formal standing in the
IETF standards process. No RFC stream, responsible Area Director, or working
group adoption is shown for these documents.

[`standards/STATUS.json`](standards/STATUS.json) is the repository's portfolio
inventory. Files under [`standards/staged/`](standards/staged/) are candidate
sources, not filed revisions. This due-diligence document intentionally does
not summarize staged or private draft contents. Architecture documents and
draft packets are design evidence, not proof of standards adoption or deployed
behavior.

## External and hardware milestones

### Independent operators

The federation mechanism has a live two-deployment proof documented in
[`docs/conformance/FEDERATION-PROOF.md`](docs/conformance/FEDERATION-PROOF.md).
The deployments use separate infrastructure and keys, but both are operated by
EMILIA. This proves the mechanism can cross deployment boundaries; it does not
establish a neutral or independently governed operator network.

**Open milestone:** a different organization operates an instance and passes
the live federation verification contract.

### Independent implementation

The external Rust result is meaningful interoperability evidence, but its
checked-in manifest explicitly records zero strict clean-room acceptance
pending a corrected third-party-attested construction record and independently
pinned attestor key.

**Open milestone:** third-party attestation covering the exact pinned source
commit and construction process.

### Real hardware attestation

The repository ships a strict TPM 2.0 quote parser/verifier and fail-closed
trust-input boundary in [`attestation/`](attestation/). Its checked-in quote
fixture was generated by `swtpm` and is explicitly marked
`hardware_backed: false`. The verifier checks a quote under a relying-party
pinned Attestation Key and PCR policy, but it does not prove that the key is in
physical hardware or chained to a manufacturer Endorsement Key.

The mobile code contains App Attest, Play Integrity, device-key, and WebAuthn
verification paths. The repository also records a maintainer-reported
real-device Touch ID acceptance. That is distinct from a retained,
independently verifiable platform-attestation and physical-device hostile-test
package. [`docs/mobile/RELEASE.md`](docs/mobile/RELEASE.md) still treats the
signed physical-device matrix as a release gate.

**Open milestone:** retain and publish an appropriately redacted evidence
package from physical hardware with independently pinned platform/manufacturer
roots, exact signed artifact hashes, challenge freshness, and the hostile
release matrix.

## Certification and adoption non-claims

The repository contains control mappings, deployment guidance, and evidence
formats. Those materials may support an assessment; they are not the
assessment. This review found no public evidence establishing:

- FedRAMP authorization, FIPS module validation, agency accreditation, or an
  operating EMILIA certification program;
- a SOC 2 report or other accredited assurance opinion over a defined
  production service boundary;
- IETF adoption, consensus, endorsement, or RFC status;
- an independent third-party production operator;
- public-store release of the native mobile applications;
- a production physical-hardware TPM attestation chain; or
- customer, regulator, bank, insurer, or standards-body adoption merely from
  the presence of examples, mappings, drafts, or partner-oriented documents.

Evidence for any of these milestones should be added only as a stable public
artifact with issuer, scope, date, subject, limitations, and a verifiable
binding to the exact release or deployment assessed.

## Reproduction entry points

```bash
git fetch origin
git rev-parse origin/main
npm run check:proof-stats
npm run check:security-case
npm run conformance
npm run check:release-chain
npm run test:mutation:security
```

Formal rerun instructions are in
[`formal/RUN_TLC.md`](formal/RUN_TLC.md),
[`formal/RUN_ALLOY.md`](formal/RUN_ALLOY.md), and
[`formal/tamarin/README.md`](formal/tamarin/README.md). Production migration
verification requires authorized read-only access to the deployment and cannot
be reproduced from the public repository alone.
