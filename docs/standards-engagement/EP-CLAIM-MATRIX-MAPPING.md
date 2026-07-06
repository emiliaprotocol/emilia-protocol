<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol — protocol mapping table against draft-bu-agentproto-security-principal-binding-02

A complete worked mapping of the EMILIA Protocol (EP) artifact-layer
mechanisms against the claim registry and Protocol Mapping Template of
[draft-bu-agentproto-security-principal-binding-02]
(https://datatracker.ietf.org/doc/html/draft-bu-agentproto-security-principal-binding-02),
offered as an early test of the template (mapping-row fields, Sections 10
and 15) and of its inheritance framing: EP is **not** an agent
communication protocol; it is an artifact-layer mechanism intended as an
**inheritance target** — where a communication protocol marks C-002,
C-005, C-007, or C-008 rows "inherited," this table supplies the inherited
verifier, carrier, binding, freshness rule, failure behavior, accepted
result, and evidence reference.

Status vocabulary is the draft's (Section 14): specified / planned /
inherited / assumption for specification; implemented / partial / none /
external for implementation — two independent vocabularies. Evidence-type
labels follow the Section 10 field (e.g., source-level, unit-level,
local-harness, interop, deployment, document); per the draft, an evidence
type is a boundary, not an assurance level. All EP Internet-Drafts are
active **individual** submissions, not IETF-adopted or endorsed. Reference
verifiers exist in JavaScript, Python, and Go in one repository — a
consistency check, **not** independent implementations; an independent
clean-room reimplementation (COSA) is underway and its result will be
recorded either way.

Repo root for evidence references:
`https://github.com/emiliaprotocol/emilia-protocol/blob/main/`

Per -02's accepted-result machinery (the Section 3 definition, matrix
review rules 3 and 8, and the Security Considerations): each mapped row
below states its ACCEPTED RESULT — the constrained, verifier-produced
output an application may consume, never raw peer-provided claims —
including what that output does NOT authorize. Because the JS/Python/Go
verifiers live in one repository, EP labels its vector evidence
local-harness, **not** interop, until the independent COSA
reimplementation agrees on the same vectors.

---

## C-002 — Human or organizational authority

- **Claim**: HUMAN authority, asserted explicitly (the row names which of
  the two authorities it carries): a named, accountable
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
  process. (Split per the registry's template direction: the semantic
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
- **Evidence type**: local-harness — cross-language vectors, one
  repository (see the status note above).
- **Evidence reference**: `conformance/vectors/receipts.v1.json`,
  `conformance/vectors/quorum.v1.json`, `conformance/vectors/signoffs.v1.json`
  (positive + negative; `node conformance/run.mjs`).

## C-005 — Action evidence

- **Claim**: what action was requested/blocked/completed, with evidence
  sufficient for a stated reliance purpose.
- **Carrier**: EP-AEG-v1 action evidence graph (content-addressed references
  to heterogeneous signed artifacts) + tamper-evident gate evidence log
  (every allow AND deny appended); signed EP-RELIANCE-RESULT-v1 verdict. The
  graph now carries two additional node types: `ceremony_evidence`
  (signing-ceremony telemetry, the challenge issued/viewed/approved instants,
  enabling a minimum-review-latency rule that surfaces a below-floor approval
  as a conflict) and `effect_attestation` (executor-signed observed-effect
  digest bound to the receipt, mapped under C-012).
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
  read from the presented graph. The policy MAY be expressed as a named,
  content-addressed EP-ADMISSIBILITY-PROFILE (an `id` plus a `profile_hash`
  over its canonical bytes) that the relying party authors and pins; the
  verdict names which `profile_hash` was in force and carries a deterministic
  replay digest, so two parties that pin the same hash provably evaluate the
  same bar. EMILIA never authors the bar and is never in the trust path.
- **Accepted result (success behavior)**: a signed EP-RELIANCE-RESULT-v1 —
  the verdict, the policy identity applied, and a replay digest so a third
  party recomputes the same verdict. It is accountability, never authority:
  the artifact itself states that it confers no permission and does not
  establish the action's business correctness.
- **Evidence type**: local-harness — deterministic example vector plus
  unit test, one repository.
- **Evidence reference**: `examples/evidence-graph/evidence-graph-vector.mjs`
  + `.json` (deterministic, negatives enforced), `tests/evidence-graph.test.js`,
  `tests/admissibility-profiles.test.js` (same evidence bundle, two pinned
  profiles, one admissible and one missing_evidence, replay digests differ
  deterministically), `docs/EP-ADMISSIBILITY-PROFILE-SPEC.md`,
  `public/.well-known/ep-admissibility-profiles.json` (reference profiles,
  in-band non-authoritative-registry disclaimer).

## C-007 — Evidence provenance

- **Claim**: the provenance of an evidence artifact itself — issuance chain,
  execution attestation, transparency registration — is verifiable.
- **Carrier**: EP provenance chains, evidence records (RFC 4998-style
  renewal), trust receipts, execution attestations; optional SCITT/COSE_Sign1
  registration (RFC 9943 architecture) with inclusion verified; optional
  independent witness cosignatures (EP-WITNESS-v1: a domain-separated
  co-signature over the log's committed checkpoint bytes) so that log
  equivocation becomes detectable when several independent witnesses compare
  heads. A single witness detects nothing; this is stated as scope, not sold
  as split-view prevention.
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
- **Evidence type**: local-harness.
- **Evidence reference**: `conformance/vectors/provenance-chains.v1.json`,
  `provenance.exec.v1.json`, `evidence-record.v1.json`,
  `trust-receipt.exec.v1.json`.

## C-008 — Freshness or revocation

- **Claim**: the authority or artifact relied on is still current.
- **Carrier**: validity windows on every artifact; portable offline
  revocation statement + server-state revocation; signed time-attestation,
  including an RFC-3161 timestamp proof verified offline against a
  relying-party-pinned TSA key, so an artifact's existence-by-time no longer
  reduces to trusting the operator's clock (existence-by-time only, never
  correctness).
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
- **Evidence type**: local-harness.
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
- **Evidence type**: local-harness.
- **Evidence reference**: `conformance/vectors/aec.json`; negative cases in
  every suite.

## C-011 — Accepted result

- **Claim**: what an application may consume after successful verification
  is a constrained, verifier-produced result — never the raw receipt,
  quorum record, graph, or attestation — and that result names its scope
  and its non-claims.
- **Carrier**: the verifier output contracts: `{ valid, checks: { version,
  signature, anchor }, error }` from the receipt verifier
  (`packages/verify`); `{ verified, accepted, checks }` from the binding
  verifier; the signed EP-RELIANCE-RESULT-v1 verdict (C-005); the
  enforcement-point reliance packet (C-002); and, when a named bar is pinned,
  the EP-ADMISSIBILITY-PROFILE verdict, one of the closed 5-state set bound to
  the in-force `profile_hash` with a deterministic replay digest. The profile
  verdict is a constrained, relying-party-pinned result: the bar is authored
  and pinned by the relying party, evaluated offline, and confers no permission
  and no correctness by itself.
- **Verifier and verification rule**: VERIFIED and ACCEPTED are computed
  and reported separately, never collapsed into one boolean — a binding
  from an unpinned issuer reports verified but never accepted (B3); each
  check is named, so a consumer cannot mistake one passing check for
  another check's claim.
- **Failure behavior**: the failure result names the failing check (reason
  codes across every suite; see C-009) — a refusal is a constrained
  result too, not silence.
- **Implementation status**: implemented — `ep-verify` (npm/PyPI) emits
  the constrained result shape on stdout.
- **Specification status**: specified for the reliance result
  (draft-schrock-ep-action-evidence-graph) and verified-vs-accepted
  (draft-schrock-human-authorization-binding, B3); the receipt-verifier
  result-object shape itself is documented in-repo, **not** yet pinned in
  an I-D — stated so the row cannot read as more than it is.
- **Accepted result (success behavior)**: the result object states what
  one named check decided and nothing else — it never establishes
  authority, sufficiency, or correctness by itself.
- **Evidence type**: local-harness.
- **Evidence reference**: `examples/binding/human-authorization-binding-vector.mjs`
  (B3: verifies-but-never-accepted — the non-claim survives into the
  result), `examples/evidence-graph/evidence-graph-vector.mjs` (signed
  verdict + recomputable replay digest), named reason codes in
  `conformance/vectors/receipts.v1.json` (`wrong_key`, `tampered_payload`,
  `tampered_anchor`).
- **Cross-language vector**: `conformance/vectors/boundary.v1.json`
  case `raw_claim_pass_through` (the Section 20 raw-claim case): a payload
  self-asserting authority with an embedded forged verifier_result, over a
  signature that does not cover those bytes — expected reject. All three
  implementations (JS, Python, Go) agree; an implementation that consumed
  the raw claims would answer true and diverge.

## C-012 — Authorization and attribution boundary

- **Claim**: pre-execution authority and post-execution attribution are
  DIFFERENT claims, and EP keeps them separate. EP-RECEIPT-v1 / EP-QUORUM
  speak BEFORE execution — a named human (or quorum) authorized this
  exact action (C-002). EP-AEG-v1, the gate evidence log, and the
  executor execution-integrity attestation speak AFTER execution —
  attribution and evidence, never authority. This row claims both legs
  and the boundary between them; it does NOT claim delegated scope
  (C-003, partial) or relying-party acceptance.
- **Carrier**: pre-execution — EP-RECEIPT-v1 / EP-QUORUM (signature
  produced before execution; the verifier's validity-window rule
  enforces freshness in strict mode, `packages/verify/index.js`). Post-execution — EP-AEG-v1 + gate evidence log +
  EP-EXECUTION-INTEGRITY-v1, whose executor is identified but never
  trusted: its signature attributes the executed-action claim to a named
  key and grants no authority. The AEG `effect_attestation` node adds the
  observed-effect leg: the executor signs `{receipt_id, observed_effect_digest}`
  after execution, so divergence between the approved bytes and the observed
  effect is offline-checkable and surfaces as a conflict, never as authority;
  a bad or unpinned executor signature is inadmissible.
- **Verifier and verification rule**: each leg has its own verifier and
  its own accepted result. The shared action digest joins the legs (a
  binding and composition aid for C-005/C-010) and makes the join
  checkable — it never makes the legs interchangeable. A record from the
  wrong side of the boundary is refused: no resolvable pre-execution WHO
  evidence → `who_required_but_absent`; WHO evidence that is a refusal →
  `disposition_contradicts_receipt`.
- **Binding and freshness**: shared action digest as the join key; digest
  equality across legs neither authorizes nor proves completeness (the
  Section 20 digest-equality case).
- **Failure behavior**: fail-closed per leg; absence of required
  pre-execution authority becomes evidence only through a signed
  observed-absence statement naming the search performed.
- **Implementation status**: implemented for the boundary and the digest
  join; the execution-integrity leg is experimental (Extension-PIP
  governed) — cited here for the boundary rule, **not** as a production
  claim.
- **Specification status**: specified —
  draft-schrock-ep-authorization-receipts (pre-execution),
  draft-schrock-ep-action-evidence-graph (post-execution),
  draft-schrock-human-authorization-binding (the join). The temporal
  rule — pre-execution authorization and post-hoc ratification are both
  legitimate records; conflating them is not — is contributed from EP as WHO-leg
  requirement W3 (contribution text:
  `docs/standards-engagement/WHO-LEG-agent-accountability-composition.md`);
  the composition -00's WHO slot carries the corresponding reject rule.
- **Accepted result (success behavior)**: separate named results per
  leg — pre-execution authority and post-execution attribution are never
  merged into one accepted result, even when both verify over the same
  action digest.
- **Evidence type**: local-harness.
- **Evidence reference**: `examples/scitt/capsule-seam-vector.mjs` +
  `capsule-seam-vector.json` must-reject cases — `wrong_action`
  (`who_subject_mismatch`) and `replay_across_subject` (cross-leg digest
  mismatch and reuse across subjects), `approval_contradiction`
  (`disposition_contradicts_receipt`), `missing_who_when_required`
  (`who_required_but_absent`); `conformance/vectors/execution-integrity.v1.json`
  (`a_execution_drift`, `c_missing_attestation_irreversible` — the
  attestation is additive and grants no authority);
  `examples/scitt/observed-absence-vector.mjs` (a bare absence assertion
  is refused).
- **Cross-language vector**: `conformance/vectors/boundary.v1.json`
  case `attribution_substituted_for_authorization` (the Section 20
  substitution case): a validly signed post-execution attribution record
  (EP-ATTRIBUTION-v1) presented in the pre-execution authorization slot —
  expected reject at the artifact-class (version) gate, with the signature
  genuine, so the refusal is the boundary rule and not a broken signature.
  All three implementations (JS, Python, Go) agree. A post-hoc-ratification
  variant (a ratification record with pre-execution framing) remains future
  work; today it is covered by this class gate plus
  `missing_who_when_required` and `approval_contradiction` in the seam
  vector.

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
- **Evidence type**: unit-level (`tests/delegation.test.js`) — not vector
  evidence.
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
- **Implementation status**: implemented — the binding vector enforces
  B1-B4 by name; B5 (dual-form consistency) is specified in the I-D with
  **no vector case yet** — stated so the row cannot read as more than it
  is.
- **Specification status**: specified — draft-schrock-human-authorization-binding;
  the co-authored composition profile posted as
  draft-mih-sato-agent-accountability-composition-00 (2026-07-05) —
  still listed as planned where it extends beyond binding-00.
- **Evidence type**: local-harness.
- **Evidence reference**: `examples/binding/human-authorization-binding-vector.mjs`
  (B1-B4), `examples/scitt/observed-absence-vector.mjs`.

## Composition slots (Section 18)

Where review is slot-shaped rather than protocol-shaped: in
draft-mih-sato-agent-accountability-composition-00 (CAN / WHO / WHAT /
AUDIT joined by a shared action digest) EP maps to the WHO slot — the
WHO-leg text was contributed from EP and merged into composition-00;
the W1-W7 numbering (including the W3 temporal rule) follows EP's
contribution source,
`docs/standards-engagement/WHO-LEG-agent-accountability-composition.md`. Consistent with Section 18: the shared
digest is a binding and composition aid for C-005 and C-010, NOT an
accepted result for authority, completeness, or policy sufficiency — the
seam vector's reject cases (C-012 above) are the executable form of that
boundary. EP claims the WHO slot only; CAN, WHAT, and AUDIT are other
formats' rows.

## Claims EP does not carry and does not rely on

Per the registry's omission rule — stated rather than omitted, since
reviewers may expect them:

- **C-001 Instance identity**: not carried, not relied upon. EP receipts
  verify identically whichever agent/workload presents them; instance
  identity is WIMSE/communication-protocol territory. Composition happens
  through the action-digest join key. The Section 20
  possession-without-authority case is structural for EP: no possession
  check exists here to be mistaken for authority.
- **C-004 Session continuity**: not carried, not relied upon. An EP receipt
  is deliberately valid for one exact action, not a session.
- **C-006 Tool or resource identity**: not carried as identity. The
  tool/resource appears inside the canonical action bytes the human signs
  (so it is bound, not identified). Adjacent, not a substitute: the
  agent-action manifest (`x-agent-action-control`) declares per-endpoint
  consequence metadata on the demand side.

---

*Maintained at `docs/standards-engagement/EP-CLAIM-MATRIX-MAPPING.md`.
Re-keyed to -01's C-IDs 2026-07-04; updated to -02 (C-011, C-012,
accepted-result + evidence-type fields, Section 18 composition-slots note)
2026-07-05; boundary.v1.json cross-language cases landed 2026-07-05; new
carriers added 2026-07-06 (EP-ADMISSIBILITY-PROFILE named/pinnable reliance
bar under C-005/C-011; `effect_attestation` and `ceremony_evidence` AEG nodes
under C-005/C-012; EP-WITNESS-v1 witness cosignatures under C-007; RFC-3161
timestamp proof under C-008); will be PR'd to the registry repo when one exists.*
