# PIP-011: Instant Revocation + Continuous-Eval — Signed Revocation Statement + Eye Security Event Token

**Status:** Draft
**Type:** Extension (additive)
**Created:** 2026-06-14
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP defines an **additive profile** of two signed objects and their
fail-closed verifier checks that close the two gaps a one-time
authorization receipt cannot close by itself: **how a previously-valid
authorization is withdrawn** (instant revocation) and **how a relying
party learns mid-flight that the posture behind a long-lived
authorization has degraded** (continuous evaluation). The two wire tags
are:

- **`EP-REVOCATION-v1`** — a detached, signed revocation statement that
  binds a revoker's named, pinned key to an exact target
  `{ target_type, target_id, action_hash }`, so a relying party can be
  *handed* portable, offline-verifiable proof that a specific
  authorization is revoked; and
- **`EP-EYE-SET-v1`** — an Eye advisory emitted as a **Security Event
  Token (RFC 8417)** in JWS-compact serialization (EdDSA), carrying a
  CAEP-style posture-change event that is scope-bound, signed under a
  pinned emitter key, and carries the **never-the-sole-gate** invariant
  in-band, so a long-lived authorization can be tightened or revoked when
  posture drops.

Together they form the loop the agentic-trust roadmap names: *Eye detects
a posture drop → emits a signed SET → a relying party issues a revocation
→ verifiers that consult revocation fail closed.*

The profile is **purely additive and by-composition only**. It does
**not** modify `EP-RECEIPT-v1`, its JCS canonicalization, its Ed25519
signature, or the frozen §6.3 offline-verification algorithm; it touches
neither `packages/verify` nor `packages/issue`. Both objects live
**outside** the frozen receipt: a verifier that does not understand them
verifies the embedded receipt exactly as today. Verifying the profile
introduces **no new trust root** — it imports the frozen `canonicalize()`
as the single serialization source of truth and adds only local detached
EdDSA / JWS verification primitives, which grant no trust by themselves.
Both verifiers **fail closed**: a self-asserted, unpinned key confers
nothing (mirroring `executor_key_pinned` in PIP-010 and `signer_key_unpinned`
in the WYSIWYS profile).

## Motivation

EP receipts answer "did a named human authorize this exact action?" at a
point in time. Two things they do not answer on their own:

1. **Withdrawal.** Today revocation in EP is server-state only
   (`commit.revokeCommit`, signoff revocation). There is no portable
   artifact a relying party can be handed and check **offline** to prove
   a previously-valid authorization is now revoked. `EP-REVOCATION-v1`
   is that artifact.
2. **Drift of posture under a long-lived authorization.** An agent
   authorization that was sound when granted can become unsafe while it
   is still valid. `EP-EYE-SET-v1` lets Eye emit a verifiable, scope-bound
   posture-change signal a relying party can act on — without Eye ever
   becoming a gate.

## Specification (summary)

Normative detail lives in `docs/EP-REVOCATION-SPEC.md` and
`docs/EP-EYE-SET-SPEC.md`; the authoritative attack catalogues are
`conformance/vectors/revocation.v1.json` and
`conformance/vectors/eye-set.v1.json`.

### EP-REVOCATION-v1 (`lib/revocation/revocation.js`)

- `buildRevocation({ target, revoker_id, reason, signer })` mints a
  statement over `canonicalize({ @version, target_type, target_id,
  action_hash, revoker_id, revoked_at, reason })`, signed by the revoker.
- `verifyRevocation(target, statement, opts)` fails closed unless: the
  `@version` matches; the statement binds the **exact**
  `(target_type, target_id, action_hash)` the verifier holds (revoking A
  must never revoke B); `revoker_id` resolves to a key the verifier
  **pinned** and the proof key equals it; `revoked_at` is present and
  well-formed; the signature verifies under the pinned key over the
  verifier-recomputed bytes; and (when `opts.maxAgeSeconds` is set)
  freshness holds. `isRevoked(target, statements, opts)` returns true iff
  a valid binding statement exists.

### EP-EYE-SET-v1 (`lib/eye/eye-set.js`)

- `buildEyeSet(advisory, { signer, audience, ... })` emits a JWS-compact
  SET (`alg: EdDSA`, `typ: secevent+jwt`, `kid`) whose payload carries the
  scope-bound `sub_id` (the advisory's `scope_binding_hash`, never a raw
  ref) and a single CAEP-style event member with the non-attributable
  advisory facts plus `never_sole_gate: true`. A `clear` (or non-actionable)
  status is refused at build time.
- `verifyEyeSet(setCompact, opts)` fails closed on: a non-EdDSA `alg`
  (including `none` / algorithm confusion — checked first); a wrong `typ`;
  an unpinned or substituted emitter key; a forged signature or a payload
  tampered after signing (verified over the **presented** segments);
  missing/ill-typed claims; an audience mismatch when `opts.audience` is
  set; staleness when `opts.requireFresh` is set; a non-actionable status;
  or a missing/non-true `never_sole_gate` marker. It returns an advisory
  **posture** for the relying party to act on — never `allow`/`deny`,
  never an authorization.

## Honest residual (out of scope)

- **Revocation freshness/completeness.** Offline verification proves a
  revocation statement is authentic and binds its target. It does **not**
  prove the relying party holds the *latest* revocation state — "has this
  been revoked by a statement I do not hold?" is a freshness/transparency
  problem (revocation feed / transparency log / short receipt TTL), like
  OCSP/CRL, and is **out of scope** of the offline check. The artifact
  answers "is THIS revocation real and for THIS target", not "is the
  absence of a revocation trustworthy".
- **SSF/CAEP/SET are prior art.** This profile does not claim
  continuous-eval, the SET format, or the never-sole-gate invariant as
  novel. The only contribution is the verifiable, scope-bound SET that
  carries the invariant in-band, with the same redaction posture as the
  Eye webhook notifier.
- **A compromised emitter / revoker key** is out of scope; both rely on
  the relying party pinning the correct key (identified-but-not-trusted).

## Backwards compatibility

Fully backwards compatible. No change to `EP-RECEIPT-v1` or the frozen
verifier. Consumers that do not implement this PIP are unaffected; the
two objects are independent, opt-in artifacts a relying party chooses to
consult.

## Reference implementation + conformance

- `lib/revocation/revocation.js`, `lib/eye/eye-set.js`
- `conformance/vectors/revocation.v1.json`,
  `conformance/vectors/eye-set.v1.json`
- `tests/revocation.test.js`, `tests/eye-set.test.js` (live-crypto
  adversarial suites; every catalogued vector asserted by id)
