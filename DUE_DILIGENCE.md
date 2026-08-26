<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public due-diligence evidence

This page is the public, reproducible entry point for technical, security,
standards, and procurement review. It is not a certification, legal opinion,
customer reference, or substitute for the company's private corporate data
room.

- **Reviewed implementation baseline:**
  [`5d474fd240bc764fa41951c05c39130e38afa7ff`](https://github.com/emiliaprotocol/emilia-protocol/commit/5d474fd240bc764fa41951c05c39130e38afa7ff)
- **Reviewed:** 2026-08-26 PDT
- **Evidence run:** [CI 32985010425](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/32985010425)
- **Production schema run:** [schema-security 32986434917](https://github.com/emiliaprotocol/emilia-protocol/actions/runs/32986434917)
- **Scope:** public source, generated proof summaries, executable tests,
  conformance, formal models, security evidence, live repository controls, and
  a bounded production source/schema check

The commit containing this page may be newer than the reviewed baseline. It
updates the evidence map; it does not retroactively expand the reviewed
implementation.

## What the system claims

At a configured and completely mediated protected executor boundary, EMILIA
Gate evaluates one exact action against the customer's finite operating mandate
and pinned evidence requirements. It reserves accepted authority before
provider entry, admits at most one provider attempt for the covered
authorization instance inside the shared durable authority domain, refuses
blind replay, and preserves an uncertain provider result as `INDETERMINATE`
until authenticated reconciliation.

The claim stops at that boundary. EMILIA does not claim exactly-once physical
execution, protection for bypass paths, truth of an upstream assertion, a wise
or lawful human decision, provider success, or real-world effect merely because
authorization verified. See the canonical [threat model](THREAT_MODEL.md).

## Executive evidence map

| Area | Reproducible public evidence | Boundary or remaining diligence item |
| --- | --- | --- |
| Tests and build | [`lib/proof-stats.json`](lib/proof-stats.json) records **10,569 tests across 651 files**. The reviewed CI run completed test, build, typecheck, lint, Postgres integration, E2E, packaging, conformance, security-case, and product jobs. | Passing tests are scoped regression evidence, not whole-system proof or production adoption. |
| Executable security case | **35 claims over 259 content-addressed evidence files**; execution passed; bundle SHA-256 `88edc9cd71f370f3193a232aa94ffc178b37769640e863980e61917655fc1163`. | This is repository-defined executable assurance, not an accredited audit. |
| Conformance | **21 suites and 332 vectors** across JavaScript, Python, and Go same-team ports. A separately authored Rust implementation remains pinned to 164 vectors and passes 359 hostile cases. | Same-team ports are not independent implementations. Strict clean-room construction acceptance remains false. |
| Formal evidence | 26 principal TLC invariants; 78 selected model/runtime scenarios with 51 paired negative controls; 20 Tamarin obligations and 8 deliberately unsafe counterexamples; 35 Alloy facts and 32 assertions. | These are bounded or symbolic results under stated assumptions, not mechanized whole-program refinement. |
| Red-team corpus | **86 catalogued cases** plus the separately pinned external Rust hostility corpus. | A catalog is not a penetration-test opinion or evidence that every production path is mediated. |
| Security assessment | Strix reported a pass on the original 18 findings against its earlier tested deployment. The subsequent STRIX-25 through STRIX-48 remediation wave changed some execution paths; every affected original path and all 24 new findings remain pending exact-revision external retest. | Source remediation, deployment, and an external retest against the same revision are separate states. See the [finding register](docs/security/STRIX_REMEDIATION_2026-07-18.md). |
| Dependencies and alerts | The root audit policy and the `mcp-server` production-dependency audit in the reviewed security workflow passed. Live GitHub review on 2026-08-26 found zero open Dependabot, CodeQL, and secret-scanning alerts. | The reviewed workflow does not establish a repository-wide audit of every nested package. Alert counts are time-sensitive and may change without a source commit. |
| Repository controls | `main` has 16 strict required status contexts, conversation resolution, force-push disabled, and deletion disabled. The organization requires 2FA; immutable release-tag rules have no bypass actor. | No pull-request approval, Code Owner review, signed commit, or administrator enforcement is currently required. The organization domain is not GitHub-verified and governance remains single-maintainer. |
| AI-assisted development | [Human accountability and attribution rules](docs/AI-ASSISTED-DEVELOPMENT.md) are public. | Counsel-led chain-of-title, invention-assignment, and conflict review belong in the private data room. |

Quantitative evidence is generated. Reviewers should read the underlying files
and their limitations rather than treating an aggregate count as proof.

## Security-assessment state

The public [Strix remediation register](docs/security/STRIX_REMEDIATION_2026-07-18.md)
keeps four states separate:

1. reported;
2. source-remediated with a named regression;
3. deployed at an exact revision and schema state; and
4. independently retested by Strix.

No Strix report or export is checked into this public repository. The register
is a maintainer-authored mapping from reported findings to source controls and
regressions, not the external report itself. A reviewer relying on a Strix
result should obtain the corresponding report or export from the private data
room and verify its assessment identifier, target, date, tested revision, and
artifact SHA-256.

Strix reported a pass on the original 18 findings against its earlier tested
deployment on 2026-08-26. That result carries forward only for an execution path
that did not change in the later remediation wave. Any affected original path
and all STRIX-25 through STRIX-48 findings remain pending exact-revision
external retest.

The second report's 24 findings reached source-remediated and deployed state at
baseline `5d474fd2`: the production proof surface served that exact source
revision during this review, `/api/health` returned `ready`, and the protected
schema run passed both the live-schema and EMILIA production-schema contracts.
This establishes the observed source identity and schema contract, not every
production secret value, third-party dependency, installed-path non-bypass
claim, or external closure result.

GitHub's automated Vercel commit status for the baseline did not record the
successful alias promotion even though the public proof surface served the
baseline. Treat the source page plus schema run as the bounded evidence above,
and reconcile the deployment integration before relying on that status alone.

## Repository and release posture

The reviewed revision's required CI and security jobs passed, and live GitHub
reported no open code, dependency, or secret alert. Release tags matching the
repository's governed package families are immutable. Package publication uses
repository workflows with OIDC and provenance, but these states remain
separate:

- source version;
- reviewed commit;
- Git tag;
- GitHub release;
- candidate artifact hash;
- registry publication; and
- deployed revision.

Verify each state for every package or deployment included in a transaction.
The repository can emit a CycloneDX SBOM, but a governed SBOM and complete
third-party notice bundle are not yet attached to every release.

Work merged after the reviewed implementation baseline is outside this
evidence snapshot even when it is present on current `main`. Reviewers should
bind later changes to their own exact source revision and completed checks
rather than treating this page's baseline evidence as transitive.

## Standards and adoption boundary

Files under `standards/posted/` are evidence of text published as individual
Internet-Drafts. The live IETF Datatracker is authoritative for revision and
status. An individual Internet-Draft is not an RFC, working-group adoption,
IETF consensus, deployment, or endorsement. A staged draft is not a filing.

Repository code, examples, control mappings, passing tests, and a live reference
surface do not establish customer adoption, revenue, regulatory approval,
certification, accredited assurance, an independent operator network, or
physical-hardware attestation.

## AI attribution and human responsibility

Tracked operating files such as `AGENTS.md`, `CLAUDE.md`, and `GEMINI.md` are
development controls, not corporate titles, authorship assignments, or
ownership claims. The accountable natural person signs each contribution under
the DCO. AI systems must not be listed as corporate officers, maintainers of
record, standards or scientific authors, patent inventors, copyright claimants,
reviewers, approvers, or DCO signers.

Historical AI-assistance metadata is provenance and should not be erased by
rewriting published commit or tag identities. It does not replace human
authorship, conception records, assignment, or DCO sign-off.

## Private corporate data-room checklist

Public source cannot close corporate diligence. Counsel and the company should
retain and review:

1. founder invention and IP assignment to the operating company;
2. employee and contractor confidentiality and invention-assignment agreements;
3. any current-employer conflict disclosure, written carve-out, or other
   counsel-approved evidence that the work was built outside employer scope;
4. contributor provenance and DCO records for non-founder contributions;
5. material AI-tool terms, account ownership, and payment records;
6. patent inventorship files naming natural persons and documenting conception;
7. cap table, board approvals, officer records, and signing authority;
8. transaction-specific package, release, deployment, and security evidence;
   and
9. customer, standards, regulatory, and commercial claims tied to exact issuer
   evidence.

This checklist is intentionally not presented as complete legal advice.

## Reproduction entry points

```bash
git fetch origin
git checkout 5d474fd240bc764fa41951c05c39130e38afa7ff
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
npm run check:llm-context
npm audit --omit=dev
```

Formal rerun instructions are in [`formal/RUN_TLC.md`](formal/RUN_TLC.md),
[`formal/RUN_ALLOY.md`](formal/RUN_ALLOY.md), and
[`formal/tamarin/README.md`](formal/tamarin/README.md). Some checks require
separately installed toolchains. Private production checks require authorized
read-only access and are intentionally not reproducible from public source.
