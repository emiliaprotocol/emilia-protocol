<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright EMILIA Protocol, Inc. -->

# EP-REVOCATION — Portable, Offline-Verifiable Revocation Statement (SPECIFICATION PROPOSAL)

**Status:** Draft / Experimental specification proposal
**Type:** Extension (additive over EP Core v1.0)
**Requires:** PIP-001 (EP Core v1.0 Freeze), EP-RECEIPT-v1
(`standards/draft-schrock-ep-authorization-receipts-03.md` §3, §6.3)
**Wire tag:** `EP-REVOCATION-v1`
**Reference implementation:** `lib/revocation/statement.js`
**Conformance vectors:** `conformance/vectors/revocation.v1.json`
**Conformance tests:** `tests/revocation.test.js`

> This is a **specification proposal** plus a reference implementation. It is
> **experimental**. It is **not** a production claim, asserts **no** customers,
> and reports **no** metrics. It MUST be ratified by a PIP before it can be
> called part of the protocol. It adds **no new trust assumptions** beyond those
> already required to verify an EP-RECEIPT-v1 receipt, plus a single detached
> Ed25519 verification of the revoker's claim — which grants no authority on its
> own.
>
> **Offline verification answers "is THIS revocation real and for THIS
> target." It does NOT answer "is the absence of a revocation trustworthy."**
> Read [§7 Residual Risk](#7-residual-risk--what-offline-revocation-does-not-prove)
> before relying on anything here. Treating absence-of-statement as
> proof-of-not-revoked is a relying-party error this profile **cannot** prevent.

---

## 1. Abstract

Revocation in EP today is **server-state only**. `revokeCommit()`
(`lib/commit.js`) flips a commit to `status:'revoked'`; `revokeAttestation()` /
`revokeChallenge()` (`lib/signoff/revoke.js`) do the same for signoff records.
All of these are *queries against a live datastore*. There is **no portable
artifact** a relying party can be **handed** to prove — offline, with no call
back to the issuer — that a previously-valid authorization is now revoked.

This profile defines that artifact: **`EP-REVOCATION-v1`**, a signed revocation
statement that **binds a target** and is **offline-verifiable**. A relying party
who is handed the statement plus the target it concerns can verify, with no
network and no trust in the bearer, that:

1. a **named, pinned** revoker signed it (identified-but-not-trusted), and
2. it binds the **exact** target the relying party is reasoning about.

It composes the **frozen** `canonicalize()` from `@emilia-protocol/issue` for the
signed bytes and touches no Core object. It does **not** replace server-state
revocation; it is the **portable, hand-it-to-someone** form of the same fact.

What this profile does **not** do is tell you whether a revocation you do **not
hold** exists — the freshness/liveness problem OCSP and CRLs exist to address.
That is stated plainly and kept out of scope in [§7](#7-residual-risk--what-offline-revocation-does-not-prove).

---

## 2. Relationship to the Frozen Core (additive, no modification)

The EP Core is frozen under **PIP-001**. This profile:

- **Does not** modify the `EP-RECEIPT-v1` wire format, canonicalization, or
  signature path.
- **Does not** modify `packages/verify` or `packages/issue`, nor the existing
  server-state revocation (`lib/commit.js`, `lib/signoff/revoke.js`).
- **Imports** the frozen `canonicalize()` as the single source of
  canonicalization truth (`lib/revocation/statement.js` →
  `../../packages/issue/index.js`), exactly as `lib/provenance/chain.js`,
  `lib/execution/integrity.js`, and `lib/wysiwys/render.js` do.
- Stores / transports the statement **alongside** the receipt (e.g. in a
  provenance bundle's optional block, an audit event, or a sidecar file),
  **never** inside the signed receipt body. Verifiers that predate this profile
  verify receipts unchanged; new verifiers add the revocation check.

This is the same composition pattern as the execution-integrity binding
(`lib/execution/integrity.js`, PIP-010) and the WYSIWYS display attestation
(`docs/EP-WYSIWYS-SPEC.md`): an **additive signed claim + a fail-closed verifier
check** over a key the verifier **pins**.

---

## 3. The revocation statement (`EP-REVOCATION-v1`)

A revocation statement is the revoker's signed claim that a named target is
revoked.

```json
{
  "@version": "EP-REVOCATION-v1",
  "target_type": "receipt",
  "target_id": "rcpt_01J...",
  "action_hash": "sha256:<hex>",
  "revoker_id": "ep:key:revoker#1",
  "revoked_at": "2026-06-14T20:41:00Z",
  "reason": "policy change — key compromise suspected",
  "proof": {
    "algorithm": "Ed25519",
    "revoker_key_id": "ep:key:revoker#1",
    "signed_payload_b64u": "<b64u canonicalize(SIGNED_FIELDS)>",
    "signature_b64u": "<b64u Ed25519 signature over signed_payload>",
    "public_key": "<b64u SPKI DER>"
  }
}
```

### 3.1 Target

| Field         | Meaning |
| ------------- | ------- |
| `target_type` | One of `receipt` \| `commit` \| `delegation`. |
| `target_id`   | The identifier of the thing being revoked (receipt id, commit id, delegation id). |
| `action_hash` | The `action_hash` the receipt committed to (the **frozen** `actionHash`, I-D §3), or the commit hash for a `commit` target. Binds the statement to the **exact** authorization, so a statement for action A cannot be replayed against action B. |

Both `target_id` **and** `action_hash` are part of the binding (§5). A statement
revokes the **(target_id, action_hash)** pair, never just an id.

### 3.2 Revoker + provenance

| Field        | Meaning |
| ------------ | ------- |
| `revoker_id` | The party asserting the revocation; the verifier **pins** the key for this id (§5.3). Identified, **not** trusted on assertion. |
| `revoked_at` | RFC 3339 instant the revocation took effect. **REQUIRED.** It is the freshness/replay anchor; a statement without it is rejected (§5.4). |
| `reason`     | Human-readable cause. Covered by the signature, so it cannot be edited after signing. |

### 3.3 Proof

- `proof` is **optional at the object level** but **REQUIRED** by the verifier:
  an unsigned statement is a bare claim that confers nothing and is rejected by
  `verifyRevocation()`.
- The signature covers the **canonical bytes** of the fixed **SIGNED_FIELDS**
  set:

  ```
  canonicalize({
    "@version":    "EP-REVOCATION-v1",
    target_type, target_id, action_hash,
    revoker_id, revoked_at, reason
  })
  ```

  Order is irrelevant — `canonicalize()` sorts keys. The verifier
  **independently recomputes** these bytes from the **presented** fields and
  rejects a signature over any other bytes (§5.5), so `revoked_at` / `reason` /
  the target cannot be edited after signing.
- `revoker_key_id` names the revoker key; the verifier pins it via
  `opts.revokerKeys` and rejects a proof under any other key (§5.3).

The signing-side helper is `buildRevocation({ target, revoker, revokedAt,
reason, signer })`; it refuses to mint a statement that does not bind a complete
target (honesty gate — a signed claim asserts a fact that was structurally
well-formed at signing time).

---

## 4. API

```
buildRevocation({ target, revoker_id, revoked_at, reason, signer }) -> statement
verifyRevocation(target, statement, opts) -> { valid, checks, errors }
isRevoked(target, statements, opts)       -> boolean
```

- **`target`** handed to the verifier is `{ target_type, target_id, action_hash }`
  — the thing the relying party is reasoning about, derived from the receipt /
  commit it holds, never from the statement.
- **`isRevoked(target, statements, opts)`** returns `true` **iff** at least one
  statement in `statements` returns `valid:true` from `verifyRevocation(target,
  statement, opts)`. It does **not** require the matching statement to be first
  or alone (vector `z2`). It is the aggregate convenience over a bag of
  statements a relying party may have collected.

---

## 5. Verifier rule (`verifyRevocation`) — FAIL CLOSED

```
verifyRevocation(target, statement, opts) -> { valid, checks, errors }
```

Given the **target the relying party holds** and a candidate statement, the
verifier evaluates the following gating checks. **Any one false ⇒ `valid:false`.**
`valid = AND(all gating checks)`.

### 5.1 `version`
`statement["@version"]` MUST equal `EP-REVOCATION-v1`. A statement under any
other tag is rejected (vector `f`) — a forked/future tag may carry different
semantics and is never honored as this version.

### 5.2 `target_bound`
The statement MUST bind the **exact** target the verifier was handed: both
`statement.target_type === target.target_type`,
`statement.target_id === target.target_id`, **and**
`hexOf(statement.action_hash) === hexOf(target.action_hash)`. A statement for a
different `target_id` (vector `d`) or a different `action_hash`
(vector `e`, "revoke-A-presented-for-B") is rejected. **Revoking A must never
revoke B.**

### 5.3 `revoker_key_pinned` (identified-but-not-trusted)
`revoker_id` MUST resolve to a key the verifier has **pinned** via
`opts.revokerKeys[revoker_id].public_key`, and the proof's `public_key` MUST
equal that pinned key.

- No pin (or no registry supplied) ⇒ **reject** (vector `b`). An unpinned,
  self-asserted key confers **nothing** — anyone can mint a keypair and sign "X
  is revoked." The verifier **never** falls back to the proof's own
  `public_key`. This mirrors `executor_key_pinned`
  (`lib/execution/integrity.js`) and `signer_key_unpinned`
  (`lib/wysiwys/render.js`).
- A pinned `revoker_id` whose proof carries a **different** key ⇒ **reject**
  (vector `c`, key substitution): the signature may verify under the substituted
  key, but the key binding fails.

### 5.4 `revoked_at_present`
`revoked_at` MUST be present and a well-formed RFC 3339 instant (vector `h`). It
is the freshness/replay anchor; without it there is no record of *when* the
revocation took effect and no basis for §5.6.

### 5.5 `revoker_signature_valid` + `signature_binds_statement`
The verifier **recomputes** the SIGNED_FIELDS canonical bytes from the
**presented** statement fields, then requires the proof to:

- (a) verify under the **pinned** key over **exactly** those recomputed bytes
  (`revoker_signature_valid`) — a forged or broken signature is rejected
  (vector `a`); and
- (b) be a signature over the **recomputed** bytes, not a producer-supplied
  `signed_payload` blob (`signature_binds_statement`) — if `revoked_at` or
  `reason` (or any signed field) was edited after signing, the recomputed bytes
  differ from what was signed and the statement is rejected (vector `g`).

The verifier never trusts `proof.signed_payload_b64u`; it is recomputed.

### 5.6 `freshness` (optional)
**Only** when `opts.maxAgeSeconds` is set: the statement is rejected if
`revoked_at` is older than `opts.maxAgeSeconds` relative to `opts.now`
(default: wall clock) (vector `i`). This bounds how stale a **presented**
statement may be. **It does nothing about a revocation that was never handed to
the verifier** — see [§7](#7-residual-risk--what-offline-revocation-does-not-prove).
When `opts.maxAgeSeconds` is unset, `freshness` is vacuously true.

### 5.7 Fail-closed obligations (any one ⇒ `valid:false`)

- `@version` is not `EP-REVOCATION-v1`.
- The statement does not bind the **exact** `(target_type, target_id,
  action_hash)` the verifier holds.
- `revoker_id` is unpinned, or the proof key is not the pinned key.
- `revoked_at` is absent or malformed.
- The proof is absent, forged, or signs bytes other than the recomputed
  SIGNED_FIELDS.
- (When required) `revoked_at` is older than the freshness window.

---

## 6. Conformance vectors

`conformance/vectors/revocation.v1.json` is the authoritative, attack-catalogue-first
catalogue; every id is asserted by name in `tests/revocation.test.js`. The
negatives are minted with **real** Ed25519 keys and **real** detached proofs
over canonical bytes, so each is a genuine forgery attempt, not hand-edited JSON
that fails for an unrelated reason.

| Vector id | Scenario | Verdict | Gating check |
| --- | --- | --- | --- |
| `a_forged_signature` | Proof does not verify under the pinned revoker key | reject | `revoker_signature_valid` |
| `b_unpinned_revoker_key` | `revoker_id` not pinned (self-asserted key) | reject | `revoker_key_pinned` |
| `c_wrong_pinned_key_substitution` | Proof key != the key pinned for `revoker_id` | reject | `revoker_key_pinned` |
| `d_bound_to_different_target_id` | Statement binds a different `target_id` | reject | `target_bound` |
| `e_bound_to_different_action_hash` | Statement binds a different `action_hash` (revoke-A-for-B) | reject | `target_bound` |
| `f_wrong_version` | `@version` is not `EP-REVOCATION-v1` | reject | `version` |
| `g_tampered_fields_after_signing` | `revoked_at`/`reason` edited after signing | reject | `signature_binds_statement` |
| `h_missing_revoked_at` | No `revoked_at` anchor | reject | `revoked_at_present` |
| `i_stale_beyond_freshness_window` | `revoked_at` older than `opts.maxAgeSeconds` | reject | `freshness` |
| `z_well_formed_binding_revocation` | Pinned revoker, exact target binding, real proof | accept | — |
| `z2_is_revoked_true_among_unrelated` | One valid binding statement among unrelated ones | accept | — |

Run: `npx vitest run tests/revocation.test.js`.

---

## 7. Residual Risk — what offline revocation does NOT prove

**This profile proves a revocation statement is AUTHENTIC and BINDS the target.
It does NOT prove you hold the LATEST revocation state.** That distinction is the
whole risk, and it is stated here plainly.

What this profile **does** prove (offline, no network):

- The statement was **signed by a named, pinned revoker** — an unpinned or
  self-asserted key confers nothing.
- The statement **binds the exact `(target_id, action_hash)`** the relying party
  is reasoning about — a revocation for action A cannot revoke action B.
- The signed fields (target, `revoker_id`, `revoked_at`, `reason`) were **not
  edited after signing**.
- (When required) the statement is **no older than** the relying party's
  freshness window.

What this profile **does NOT** prove, and what is **out of scope**:

- **That no revocation exists that you were not handed.** "Has this authorization
  been revoked by a statement I do not hold?" is a **freshness / liveness /
  transparency** question — exactly the gap **OCSP** and **CRLs** exist to fill.
  The offline check answers *"is THIS revocation real and for THIS target,"* not
  *"is the absence of a revocation trustworthy."* **Treating
  absence-of-statement as proof-of-not-revoked is a relying-party error this
  profile cannot prevent.**
- **Liveness in general.** The `opts.maxAgeSeconds` window bounds how stale a
  **presented** statement may be; it does **nothing** about a revocation that was
  never delivered to the verifier. A relying party that needs liveness **MUST**
  consult a revocation **feed / transparency log**, or rely on a **short receipt
  TTL** — a layer **above** this artifact, not a property of it.
- **That the revoker was entitled to revoke.** This profile verifies *who* signed
  and *what* it binds; whether `revoker_id` had the authority to revoke this
  target is an authorization-policy question for the relying party's pinning
  policy (who you pin as a revoker for a given target), not a property of the
  signature.

> **Framing (reuse this language).** "An EP-REVOCATION-v1 statement is a portable,
> offline-verifiable proof that a named, pinned revoker revoked *this specific
> target*. It is the CRL/OCSP *response* — proof a specific revocation is real —
> not the CRL/OCSP *service*: it does not tell you about revocations you were
> never handed. A relying party that needs to know the *absence* of a revocation
> is trustworthy must consult a revocation feed or rely on short receipt TTLs.
> This artifact raises the cost of denying a revocation that *did* happen; it
> does not make the absence of a revocation trustworthy."

---

## 8. Security considerations

- **Canonicalization is load-bearing.** The signed bytes reuse the frozen
  `canonicalize()`; signer and verifier MUST produce identical bytes. The
  reference re-imports the frozen function rather than re-implementing it.
- **Pin by `revoker_id`, never by self-assertion.** The verifier resolves the
  key from `opts.revokerKeys` and rejects any proof not under the pinned key.
  Who you pin as a revoker for a given target is the relying party's policy and
  is the real authorization boundary.
- **Bind both target_id and action_hash.** Binding only an id would let a
  revocation for one action be replayed against a re-issued authorization with
  the same id but a different action; the `action_hash` closes that.
- **Recompute the signed payload.** The verifier never trusts a producer-supplied
  `signed_payload_b64u`; tampered `revoked_at`/`reason` fail because the
  recomputed bytes differ from what was signed.
- **Freshness ≠ completeness.** A freshness window bounds staleness of a
  *presented* statement; it is not a substitute for a revocation feed. Do not
  read `valid:true` as "not revoked elsewhere."
- **One new primitive, no new trust.** The only added primitive is detached
  Ed25519 verification of the revoker's claim; it grants no authority by itself.

---

## 9. Governance

This profile is **experimental** and MUST be ratified by an Extension PIP before
it is part of the protocol. It changes no frozen Core object and is governed
exactly as `EP-PROVENANCE-CHAIN-v1` (PIP-009), `EP-EXECUTION-INTEGRITY-v1`
(PIP-010), and the WYSIWYS display-attestation profile: composition, not
ownership; an additive signed claim + a fail-closed verifier check; honest
residual stated plainly.
