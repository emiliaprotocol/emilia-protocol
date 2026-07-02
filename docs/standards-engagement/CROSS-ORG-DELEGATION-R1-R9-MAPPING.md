# Candidate mapping: EP authorization receipts vs draft-reece-wimse-cross-org-delegation-00 (R1–R9)

Status: proof-of-concept candidate mapping, offered to the WIMSE requirements
discussion at Morgan Reece's invitation (2026-07-02). Comparative frame: this
maps ONE candidate for ONE slice — the human-authorization-of-an-irreversible-
action layer — not a claim of general coverage of the delegation problem.

Discipline (per Morgan's framing request):

- Each requirement is graded **UNCONDITIONAL** (met offline, from the conveyed
  artifact alone), **CONDITIONAL** (met, but only under stated assumptions —
  the assumptions are the finding), or **PARTIAL / GAP** (the honest miss).
- R2/R3/R7/R8 are additionally evaluated under a **no-shared-operator**
  assumption: verifying org and issuing org are distinct trust domains with no
  shared operator.
- "Verified" vs "accepted" is used throughout in the EP federation sense:
  *verified* = signature + bindings hold from the artifact and a public key;
  *accepted* = the relying party additionally trusts the issuer via an
  out-of-band pinned key. Conflating these is how cross-domain designs
  overclaim; we won't.

The candidate artifact: EP-RECEIPT-v1 (draft-schrock-ep-authorization-receipts)
— Ed25519 over RFC 8785 (JCS) canonical bytes, binding a named human principal
to one exact action; plus its composition layers where a requirement is about
chains rather than single hops: provenance chain (delegation), EP-AEC
(heterogeneous evidence composition), revocation statements, admissibility
(freshness/sufficiency policy). Reference verifiers in JS/Python/Go agree on
shared conformance vectors (one repository — this is a multi-language
consistency check, not independent implementations; the independent data point
is a third party's execution and verification of the published artifacts
against a pinned commit, 2026-06-23).

---

## R1 — Recursive attenuation — CONDITIONAL (root-key trust only)

The EP provenance chain conveys authority hop-by-hop with explicit scope and
monotonic constraint containment: the verifier checks, offline and from the
chain alone, that every hop's scope/constraints are a subset of its
predecessor's (`Action ⊆ Constraints ⊆ Scope`, containment enforced
per hop, fail-closed). No hop can exceed its predecessor without breaking a
signature. Assumption carried: trust in the chain's *root* key (the human
authority anchor) — attenuation verification itself needs nothing else.

## R2 — Cross-organizational verification — CONDITIONAL, and the condition is the point

*Verification* is unconditional: any relying party with the issuer's public
key verifies signature and bindings with no bilateral agreement and no
contact with the issuing org. *Acceptance* is not: deciding to **rely** on the
artifact requires an out-of-band pinned issuer key — which is exactly the
"trust anchor distribution" assumption R2 gestures at. EP refuses to hide
that: the verifier returns verified and accepted separately, and a
self-consistent artifact from an unpinned issuer is never accepted. Honest
reading: R2 is met at the verification level; at the acceptance level *some*
pre-established trust (key pinning, a directory, a federation) is
irreducible, and we'd argue the requirement text should acknowledge that for
any candidate.

## R3 — No runtime callback — UNCONDITIONAL (verification); revocation material cached per R7

Core design property: the receipt is a self-contained signed object over
canonical bytes; the authorization decision is computable from the artifact +
locally held keys, with no synchronous call to the issuing org. Under
no-shared-operator this does not degrade — nothing in the verify path knows or
cares who operates what. The only cached material on the critical path is the
issuer key (R2) and revocation/freshness state (R7); staleness of the latter
fails safe, not open.

## R4 — Proof of possession — PARTIAL, by design; the gap is scoped by action binding

The receipt is *evidence of authorization*, not a bearer capability, and EP
should not pretend otherwise. What EP provides: (a) the authorizing human's
signature is device-bound (WebAuthn, user-verification-gated), so *issuance*
is possession-proven; (b) the receipt binds ONE exact action (canonical-bytes
digest), so a captured receipt conveys no authority beyond the single action
it names; (c) replay of that one action is prevented by one-time consumption
at the enforcement point. Honest condition: (c) is server-state at the
enforcement point, not offline-verifiable, and presenter-PoP at relay time
(the receipt-holder proving key control to the relying party) is out of
scope — that is workload-identity's job (WIMSE), and is precisely why this
layer composes with it rather than replacing it.

## R5 — Principal binding and invariance — UNCONDITIONAL

The named on-behalf-of principal is inside the signed canonical payload. No
intermediary can alter the principal without invalidating the signature; the
relying party verifies invariance from the artifact alone, offline. This is
the requirement the candidate exists for.

## R6 — Dual-axis authorization — CONDITIONAL (composition; each leg under its own verifier)

Met by composition, not by the receipt alone: EP-AEC binds heterogeneous legs
(agent's conveyed authority / delegation, policy permit, human authorization)
to one canonical action digest and evaluates a requirement expression that can
demand *both* axes — with the sufficiency bar supplied by the **relying
party**, never read from the presented bundle (presenter-chosen requirements
are recorded as claims only). Assumptions: each composed leg verifies under
its own type verifier; the digest discipline (same canonicalization) holds
across legs.

## R7 — Authentic, bounded-staleness revocation — CONDITIONAL; distribution is deferred and we say so

Authenticity offline: EP revocation statements are portable signed objects —
a relying party verifies a revocation's authenticity with a key, no callback.
Bounded staleness: freshness is a relying-party-configured policy input;
evidence older than the configured bound fails *safe* (the sufficiency verdict
degrades to `stale`, which does not authorize). Under no-shared-operator the
verification of revocation statements is unaffected. The honest gap:
**distribution** of revocation material (who ships you the latest statements,
CRL/OCSP-style) is explicitly deferred to the relying party's channel; EP does
not currently operate or specify a revocation-availability service, so
"absence of revocation" is only as fresh as the channel you built. That
matches R7's letter (bounded staleness + fail-safe) but a candidate comparison
should count the missing distribution profile as open work.

## R8 — Tamper-evident, composable audit — UNCONDITIONAL per-record; CONDITIONAL end-to-end

Per-participant records: each receipt/revocation/delegation hop is an
independently signed, self-contained object — alteration is detectable from
the object alone. Composition: AEC composes records for one action **by
digest, not containment**, so an end-to-end account is assembled without any
participant re-signing another's record; transparency-log inclusion proofs +
a signed checkpoint (SCITT-aligned) add non-equivocation. Under
no-shared-operator, the end-to-end account inherits one assumption:
inclusion/consistency proofs are only as strong as the log operator's
checkpoint, so genuinely mutually-distrusting domains need either cross-log
witnessing or each domain anchoring its own records — the per-record
tamper-evidence does not depend on this, the *global ordering* does.

## R9 — Format and transport agnosticism — UNCONDITIONAL

The artifacts are application-layer canonical-JSON (JCS) objects with no
presupposed transport; a COSE/SCITT profile exists for envelope contexts, and
an embeddable human-authorization *claim* exists so other receipt formats
(policy-permit, compliance receipts) can carry the primitive inside their own
envelopes rather than adopting a new one. Nothing in verification touches
transport.

---

## Summary table

| Req | Grade | The assumption that matters |
|---|---|---|
| R1 | CONDITIONAL | root (human-anchor) key trust; attenuation check itself is offline |
| R2 | CONDITIONAL | verified = unconditional; **accepted** requires out-of-band issuer pinning — irreducible for any candidate |
| R3 | UNCONDITIONAL | (cached key + revocation material, per R2/R7) |
| R4 | PARTIAL | issuance PoP + exact-action binding + one-time consumption; presenter-PoP at relay = workload identity's layer |
| R5 | UNCONDITIONAL | — |
| R6 | CONDITIONAL | composition (AEC); relying-party-supplied requirement; per-leg verifiers |
| R7 | CONDITIONAL | authenticity + bounded-staleness fail-safe met; **distribution channel deferred** (open work) |
| R8 | UNCONDITIONAL per-record | end-to-end ordering assumes log-operator checkpoint or cross-log witnessing |
| R9 | UNCONDITIONAL | — |

Independent-execution status, stated per the survey wording discipline: the
JS/Python/Go verifier agreement is a single-repository consistency property;
the independent data point is a third party's execution and verification of
the published artifacts against a pinned commit (2026-06-23). No claim of
independently developed implementations is made.
