<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol — protocol mapping table against draft-bu-agentproto-security-principal-binding-01

A complete worked mapping of the EMILIA Protocol (EP) artifact-layer
mechanisms against the claim registry and Protocol Mapping Template of
[draft-bu-agentproto-security-principal-binding-01]
(https://datatracker.ietf.org/doc/html/draft-bu-agentproto-security-principal-binding-01),
offered as an early test of the template (Section 12/14) and per Section 16:
EP is **not** an agent communication protocol; it is an artifact-layer
mechanism intended as an **inheritance target** — where a communication
protocol marks C-002, C-005, C-007, or C-008 rows "inherited," this table
supplies the inherited verifier, carrier, binding, freshness rule, failure
behavior, and evidence reference.

Status vocabulary is the draft's (Section 13). All EP Internet-Drafts are
active **individual** submissions, not IETF-adopted or endorsed. Reference
verifiers exist in JavaScript, Python, and Go in one repository — a
consistency check, **not** independent implementations; an independent
clean-room reimplementation (COSA) is underway and its result will be
recorded either way.

Repo root for evidence references:
`https://github.com/emiliaprotocol/emilia-protocol/blob/main/`

Per the acceptance-side convention announced for -02 (success behavior /
accepted result, name the editor's choice): each mapped row below states its
ACCEPTED RESULT — the constrained, verifier-produced output an application
may consume, never raw peer-provided claims — including what that output
does NOT authorize.

---

## C-002 — Human or organizational authority

- **Claim**: HUMAN authority, asserted explicitly (per the -02 direction that
  a mapping row names which of the two it carries): a named, accountable
  natural person — or an M-of-N (optionally ordered) quorum of distinct
  natural persons — authorized this exact action before execution.
  Organizational authority (policy/role grants) is NOT what this row
  asserts; EP consumes it as relying-party policy input.
- **Carrier**: EP-RECEIPT-v1 / EP-QUORUM: a self-contained signed JSON
  artifact; transport-agnostic (HTTP header, message field, file, SCITT
  Signed Statement).
- **Verifier and verification rule**: any conforming verifier, offline, no
  account: Ed25519 over RFC 8785/JCS canonical action bytes against a pinned
  issuer key; quorum: threshold met by DISTINCT principals over the same
  digest, order enforced when declared. Verified-vs-accepted kept separate:
  a valid signature proves VERIFIED; ACCEPTED is a relying-party key-pinning
  decision; neither implies sufficiency.
- **Binding and freshness**: signed payload covers the action digest — the
  same record cannot satisfy authority for a different action; digest
  equality itself neither authorizes nor proves completeness. Validity
  window (`not_before`/`expires_at`). One-time use is enforcement-point
  state (consumption committed before allow) — represented in the artifact,
  enforced at the gate, not offline-verifiable (see Dependency).
- **Layer**: application-layer artifact; rides any session/transport.
- **Failure behavior**: fail-closed. Missing/invalid/stale/replayed/
  out-of-scope → refuse + machine-readable challenge (HTTP 428,
  `application/authorization-evidence-challenge+json`).
- **Implementation status**: implemented.
- **Specification status**: specified — draft-schrock-ep-authorization-receipts,
  draft-schrock-human-authorization-binding (host-record binding profile).
- **Dependency**: one-time consumption requires an enforcement point
  (deployed by the resource owner); issuer-key pinning is a relying-party
  process. (Split per the registry's Section-14 direction: the semantic
  rule lives in binding-and-freshness above; the state holder here; and
  the evidence that the rule is actually checked: replay negatives in the
  receipts suite and `packages/gate/store.js` + `store-postgres.js` tests,
  where a replay and a concurrent duplicate consume are refused.)
- **Accepted result (success behavior)**: the verifier returns a constrained
  result object — VERIFIED/REFUSED plus named checks (version, signature,
  anchor) and, at the enforcement point, a reliance packet — never the raw
  presented claims. The result states scope: it establishes who authorized
  what, and does not establish correctness, sufficiency, or acceptance
  (a relying-party key-pinning decision). `ep-verify` (npm/PyPI) emits
  exactly this shape on stdout.
- **Evidence reference**: `conformance/vectors/receipts.v1.json`,
  `conformance/vectors/quorum.v1.json`, `conformance/vectors/signoffs.v1.json`
  (positive + negative; `node conformance/run.mjs`).

## C-005 — Action evidence

- **Claim**: what action was requested/blocked/completed, with evidence
  sufficient for a stated reliance purpose.
- **Carrier**: EP-AEG-v1 action evidence graph (content-addressed references
  to heterogeneous signed artifacts) + tamper-evident gate evidence log
  (every allow AND deny appended); signed EP-RELIANCE-RESULT-v1 verdict.
- **Verifier and verification rule**: offline replay: edges are presenter
  claims verified against artifact bytes (a lying edge → unverifiable; a
  required absent edge → missing_evidence); deterministic policy replay to a
  5-state verdict with a replay digest a third party recomputes.
- **Binding and freshness**: every node bound by content digest; graph
  digest disclosure-independent; staleness is a first-class verdict state.
- **Layer**: application-layer artifact.
- **Failure behavior**: fail-closed verdict precedence
  (unverifiable > conflicted > stale > missing_evidence > admissible —
  no failure ever degrades toward admissibility).
- **Implementation status**: implemented.
- **Specification status**: specified — draft-schrock-ep-action-evidence-graph.
- **Dependency**: reliance policy is supplied by the relying party, never
  read from the presented graph.
- **Accepted result (success behavior)**: a signed EP-RELIANCE-RESULT-v1 —
  the verdict, the policy identity applied, and a replay digest so a third
  party recomputes the same verdict. It is accountability, never authority:
  the artifact itself states that it confers no permission and does not
  establish the action's business correctness.
- **Evidence reference**: `examples/evidence-graph/evidence-graph-vector.mjs`
  + `.json` (deterministic, negatives enforced), `tests/evidence-graph.test.js`.

## C-007 — Evidence provenance

- **Claim**: the provenance of an evidence artifact itself — issuance chain,
  execution attestation, transparency registration — is verifiable.
- **Carrier**: EP provenance chains, evidence records (RFC 4998-style
  renewal), trust receipts, execution attestations; optional SCITT/COSE_Sign1
  registration (RFC 9943 architecture) with inclusion verified.
- **Verifier and verification rule**: chain verification against pinned
  roots; transparency-receipt validation kept SEPARATE from native signature
  validation (registration proves logging per service policy, never that a
  human authorized the action).
- **Binding and freshness**: digest-addressed chains; evidence-record
  renewal for long-term preservation.
- **Layer**: application-layer artifact.
- **Failure behavior**: broken chain/failed inclusion → that provenance leg
  fails closed; native verification result reported separately.
- **Implementation status**: implemented.
- **Specification status**: specified (EP-native); SCITT expression specified
  in draft-schrock-human-authorization-binding.
- **Dependency**: a transparency service, where registration is claimed.
- **Accepted result (success behavior)**: separate named results per leg
  (native signature, chain, transparency inclusion) — never one collapsed
  boolean, so registration can never silently stand in for authorization.
- **Evidence reference**: `conformance/vectors/provenance-chains.v1.json`,
  `provenance.exec.v1.json`, `evidence-record.v1.json`,
  `trust-receipt.exec.v1.json`.

## C-008 — Freshness or revocation

- **Claim**: the authority or artifact relied on is still current.
- **Carrier**: validity windows on every artifact; portable offline
  revocation statement + server-state revocation; signed time-attestation.
- **Verifier and verification rule**: offline revocation-statement
  verification with bounded-staleness semantics; JS/Python/Go verifiers agree
  on the revocation suites.
- **Binding and freshness**: revocation statements are digest-addressed to
  the artifact they revoke.
- **Layer**: application-layer artifact.
- **Failure behavior**: revoked or stale → fails closed.
- **Implementation status**: implemented.
- **Specification status**: specified for EP-native artifacts; a GENERALIZED
  credential-revocation statement (revoking any digest-addressed artifact)
  is **planned** — drafted, filing when the datatracker reopens; listed as
  planned, not a guarantee. **Becomes reviewable when**: the generalized
  revocation I-D posts and its vector file joins the revocation suites.
- **Evidence reference**: `conformance/vectors/revocation.v1.json`,
  `revocation.exec.v1.json`, `time-attestation.v1.json`.

## C-009 — Failure handling

- **Claim**: verifier failure paths are specified, machine-readable, and
  themselves evidenced.
- **Carrier**: AE-CHALLENGE-v1 (HTTP 428 challenge naming exactly the missing
  evidence; relying-party-computed action digest; single-use nonces); signed
  refusal receipts (grid-curtailment profile) — a refusal is evidence, not
  silence.
- **Verifier and verification rule**: deny-by-default at the enforcement
  point; every EP conformance suite requires negative vectors where the
  verifier MUST name the failing check.
- **Implementation status**: implemented.
- **Specification status**: specified —
  draft-schrock-authorization-evidence-challenge.
- **Evidence reference**: `conformance/vectors/aec.json`; negative cases in
  every suite.

## C-003 — Delegated scope (partial)

- **Claim**: bounded delegation from a named principal to a delegate, with
  scope and window.
- **Carrier / rule**: scoped delegation records verified like receipts;
  out-of-scope or expired fails closed.
- **Implementation status**: **partial** — implemented with single-repo tests
  (`lib/delegation.js`, `tests/delegation.test.js`); NOT yet in the
  cross-language conformance suite. Stated so the row cannot read as more
  than it is.
- **Specification status**: documented; not yet an I-D.
- **Becomes fully reviewable when**: a cross-language delegation vector
  file lands in `conformance/vectors/` and all three verifiers agree on it
  (per the registry's rule that non-implemented rows name the artifact
  that would make the claim reviewable).

## C-010 — Composition boundary

- **Claim**: which claims survive composition across agents, gateways, and
  hosts: an EP authorization binds by content digest into a host record
  (eleven host formats mapped), and verified-vs-accepted semantics are
  preserved — embedding never upgrades trust.
- **Carrier**: the binding profile's digest reference (embedded or
  referenced, consistency required); the action-digest join key at the
  composition seam.
- **Verifier and verification rule**: host-record verification and EP-native
  verification remain SEPARATE results; absence of a required authorization
  is an observed-absence statement, not silence.
- **Failure behavior**: embedded/referenced inconsistency or absent required
  binding → fail closed.
- **Implementation status**: implemented (binding vectors B1-B5).
- **Specification status**: specified — draft-schrock-human-authorization-binding;
  a co-authored composition profile (mih-sato agent-accountability
  composition) is in progress — listed as planned where it extends beyond
  binding-00.
- **Evidence reference**: `examples/binding/human-authorization-binding-vector.mjs`,
  `examples/scitt/observed-absence-vector.mjs`.

## Claims EP does not carry and does not rely on

Per Section 14's omission rule — stated rather than omitted, since reviewers
may expect them:

- **C-001 Instance identity**: not carried, not relied upon. EP receipts
  verify identically whichever agent/workload presents them; instance
  identity is WIMSE/communication-protocol territory. Composition happens
  through the action-digest join key.
- **C-004 Session continuity**: not carried, not relied upon. An EP receipt
  is deliberately valid for one exact action, not a session.
- **C-006 Tool or resource identity**: not carried as identity. The
  tool/resource appears inside the canonical action bytes the human signs
  (so it is bound, not identified). Adjacent, not a substitute: the
  agent-action manifest (`x-agent-action-control`) declares per-endpoint
  consequence metadata on the demand side.

---

*Maintained at `docs/standards-engagement/EP-CLAIM-MATRIX-MAPPING.md`.
Re-keyed to -01's C-IDs 2026-07-04; will be PR'd to the registry repo when
one exists.*
