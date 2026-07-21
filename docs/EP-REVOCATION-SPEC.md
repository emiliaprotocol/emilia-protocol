<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright EMILIA Protocol, Inc. -->

# EP-REVOCATION — Portable, Offline-Verifiable Revocation Statement (SPECIFICATION PROPOSAL)

**Status:** Draft / Experimental specification proposal
**Type:** Extension (additive over EP Core v1.0)
**Requires:** PIP-001 (EP Core v1.0 Freeze), EP-RECEIPT-v1 as specified by the
current published authorization-receipts draft
**Wire tag:** `EP-REVOCATION-v1`
**Reference implementation:** `lib/revocation/revocation.js`
**Conformance vectors:** attack catalogue `conformance/vectors/revocation.v1.json`;
executable cross-language suite `conformance/vectors/revocation.exec.v2.json`
**Conformance tests:** `tests/revocation.test.js`

> This is a **specification proposal** plus a reference implementation. It is
> **experimental**. It is **not** a production claim, asserts **no** customers,
> and reports **no** metrics. It MUST be ratified by a PIP before it can be
> called part of the protocol. It reuses Ed25519 but adds an explicit trust
> input: the relying party must pin which revoker key is authoritative for the
> target. Signature validity alone grants no revocation authority.
>
> **Offline verification answers "is THIS revocation real and for THIS
> target." It does NOT answer "is the absence of a revocation trustworthy."**
> Read [§7 Residual Risk](#7-residual-risk--what-offline-revocation-does-not-prove)
> before relying on anything here. Treating absence-of-statement as
> proof-of-not-revoked is a relying-party error this profile **cannot** prevent.

---

## 1. Abstract

Before this profile, revocation in the EP implementation was **server-state
only**. `revokeCommit()`
(`lib/commit.js`) flips a commit to `status:'revoked'`; `revokeAttestation()` /
`revokeChallenge()` (`lib/signoff/revoke.js`) do the same for signoff records.
All of these are *queries against a live datastore*. They did not produce a
portable EP artifact a relying party could be handed to prove, offline, that a
previously valid authorization was revoked. Other ecosystems provide CRLs,
OCSP responses, status lists, and signed status assertions; this profile is the
exact-target binding for EP authorization artifacts.

This profile defines that artifact: **`EP-REVOCATION-v1`**, a signed revocation
statement that **binds a target** and is **offline-verifiable**. A relying party
who is handed the statement plus the target it concerns can verify, with no
network and no trust in the bearer, that:

1. a **named, pinned** revoker signed it (identified-but-not-trusted), and
2. it binds the same **logical target identifier and action commitment** the
   relying party is reasoning about.

It composes the **frozen** `canonicalize()` from `@emilia-protocol/issue` for the
signed bytes and touches no Core object. It does **not** replace server-state
revocation; it is the **portable, hand-it-to-someone** form of the same fact.

What this profile does **not** do is tell you whether a revocation you do **not
hold** exists. Current non-revocation is a separate, time-bounded claim supplied
by an authenticated status mechanism. A terminal revocation record never ages
out; only a status view saying "not revoked as of T" can become stale.

---

## 2. Relationship to the Frozen Core (additive, no modification)

The EP Core is frozen under **PIP-001**. This profile:

- **Does not** modify the `EP-RECEIPT-v1` wire format, canonicalization, or
  signature path.
- **Does not** modify `packages/issue` or the existing server-state revocation
  (`lib/commit.js`, `lib/signoff/revoke.js`). The portable verifier is included
  in `packages/verify` so the artifact can be checked offline.
- **Imports** the frozen `canonicalize()` as the single source of
  canonicalization truth (`lib/revocation/revocation.js` →
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
    "revoker_key_id": "ep:revoker-key:sha256:<64-hex>",
    "signature_b64u": "<b64u Ed25519 signature over canonical SIGNED_FIELDS>",
    "public_key": "<b64u SPKI DER>"
  }
}
```

### 3.1 Target

| Field         | Meaning |
| ------------- | ------- |
| `target_type` | One of `receipt` \| `commit` \| `delegation`. |
| `target_id`   | The identifier of the thing being revoked (receipt id, commit id, delegation id). |
| `action_hash` | The action commitment the receipt carries (the **frozen** `actionHash`, I-D §3), or the commit hash for a `commit` target. It is not a digest of arbitrary wrapper serialization. It binds the logical authorization instance so a statement for action A cannot be replayed against action B. |

Both `target_id` **and** `action_hash` are part of the binding (§5). A statement
revokes the **(target_id, action_hash)** pair, never just an id.

### 3.2 Revoker + provenance

| Field        | Meaning |
| ------------ | ------- |
| `revoker_id` | The party asserting the revocation; the verifier **pins** the key for this id (§5.3). Identified, **not** trusted on assertion. |
| `revoked_at` | Strict RFC 3339 instant the revocation took effect. **REQUIRED.** It is the effective-time anchor; a statement without it is rejected (§5.4). |
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
- New emitters MUST set `revoker_key_id` to
  `ep:revoker-key:sha256:<64-hex>`, where the digest is computed over the
  base64url-decoded SPKI DER bytes. The verifier re-derives the identifier,
  requires it to match the proof and any key id in the relying-party pin, and
  still selects trust only through `opts.revokerKeys[revoker_id]`.
- Closed-profile EP-REVOCATION-v1 statements carrying a historical bounded local
  key label
  (for example `rk1`) remain verifiable only when the proof key is a non-empty,
  parseable Ed25519 SPKI that exactly equals the relying-party pin and any pin
  `key_id` exactly repeats the same local label. A value beginning with
  `ep:revoker-key:sha256:` never enters this compatibility path unless it is
  the complete derived identifier. This exception applies only to key-identifier
  syntax; it does not grandfather old open layouts or extra unsigned members.
- The statement and proof are closed objects. Unknown members are refused.
  There is no producer-supplied `signed_payload_b64u` and no unsigned
  `scope_note`; the verifier has one canonical signed representation.

The signing-side helper is `buildRevocation({ target, revoker_id, revoked_at,
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

### 5.2 `structure`
The statement and proof MUST contain exactly the members shown in §3. Unknown
top-level or proof members are refused even when the Ed25519 signature still
verifies over SIGNED_FIELDS. This prevents unsigned fields from acquiring
accidental semantics in downstream implementations.

### 5.3 `target_bound`
The statement MUST bind the same logical target the verifier was handed: both
`statement.target_type === target.target_type`,
`statement.target_id === target.target_id`, **and**
`hexOf(statement.action_hash) === hexOf(target.action_hash)`. A statement for a
different `target_id` (vector `d`) or a different `action_hash`
(vector `e`, "revoke-A-presented-for-B") is rejected. **Revoking A must never
revoke B.** Both sides MUST first contain a recognized target type, a non-empty
target id, and a valid 64-hex SHA-256 digest; two malformed values never match
merely because they normalize to the same empty value (vector `j`).

### 5.4 `revoker_key_pinned` and `revoker_key_bound`
`revoker_id` MUST resolve to a key the verifier has **pinned** via
`opts.revokerKeys[revoker_id].public_key`. The proof's carried `public_key` is
REQUIRED and MUST equal that pinned key. Verification always uses the pinned
key. New artifacts use the full digest-derived identifier. A verifier MUST
derive it from the SPKI and require exact agreement with
`proof.revoker_key_id` and any `key_id` supplied by the pin, except for the
narrow historical-v1 compatibility rule in §3. Under that rule the exact
pinned SPKI remains the cryptographic identity; the local label adds no trust.

- No pin (or no registry supplied) ⇒ **reject** (vector `b`). An unpinned,
  self-asserted key confers **nothing** — anyone can mint a keypair and sign "X
  is revoked." The verifier **never** falls back to the proof's own
  `public_key`. This mirrors `executor_key_pinned`
  (`lib/execution/integrity.js`) and `signer_key_unpinned`
  (`lib/wysiwys/render.js`).
- A pinned `revoker_id` whose proof carries a **different** key ⇒ **reject**
  (vector `c`, key substitution): the signature may verify under the substituted
  key, but the key binding fails.

### 5.5 `revoked_at_present` and `effective_at_or_before_T`
`revoked_at` MUST be present and a strict RFC 3339 instant (vector `h`). Invalid
calendar dates such as 30 February are rejected rather than normalized by a
permissive runtime parser. The instant MUST be at or before the verifier's
decision time `opts.now` (default: wall clock); a signed future revocation does
not establish that the target is revoked yet (vector `i`).

### 5.6 `revoker_signature_valid` + `signature_binds_statement`
The verifier **recomputes** the SIGNED_FIELDS canonical bytes from the
**presented** statement fields, then requires the proof to:

- (a) declare `Ed25519` and verify under the **pinned** key over **exactly** those recomputed bytes
  (`revoker_signature_valid`) — a forged or broken signature is rejected
  (vector `a`), and a mismatched algorithm label is rejected (vector `k`); and
- (b) be a signature over the **recomputed** bytes
  (`signature_binds_statement`) — if `revoked_at` or
  `reason` (or any signed field) was edited after signing, the recomputed bytes
  differ from what was signed and the statement is rejected (vector `g`).

### 5.7 Terminality and current status
A valid revocation is a terminal negative fact. Once `revoked_at` has been
reached, passage of time MUST NOT make the statement invalid. The legacy
`opts.maxAgeSeconds` parameter is ignored for compatibility; implementations
MUST NOT use it to age out a revocation.

A relying party that needs to establish current **non-revocation** MUST obtain
separate authenticated status evidence with its own observation instant,
freshness policy, rollback protection, and completeness boundary. The IETF
[Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
specification is one such status substrate for JOSE/COSE-secured tokens; an EP
binding may profile it for action artifacts. Missing, stale,
rolled-back, or incomplete status evidence MUST NOT be interpreted as
"not revoked."

### 5.8 Fail-closed obligations (any one ⇒ `valid:false`)

- `@version` is not `EP-REVOCATION-v1`.
- The statement or proof carries a missing or unknown member.
- The statement does not bind the same `(target_type, target_id,
  action_hash)` the verifier holds.
- Either target has an unknown type, empty id, or malformed SHA-256 digest.
- `revoker_id` is unpinned, or a proof-carried key is not the pinned key.
- `revoker_key_id` or a pinned key id matches neither the full SPKI digest nor
  the exact-pinned historical-v1 compatibility rule.
- `revoker_id` is not a non-empty string, the proof key is empty or not an
  Ed25519 SPKI, or `revoked_at` exceeds nine fractional digits.
- `revoked_at` is absent or malformed.
- The proof is absent, forged, or signs bytes other than the recomputed
  SIGNED_FIELDS.
- `revoked_at` is later than the verifier's decision time, or the decision time
  cannot be established.

---

## 6. Conformance vectors

`conformance/vectors/revocation.v1.json` is the authoritative,
attack-catalogue-first catalogue; every id is asserted by name in
`tests/revocation.test.js`. The live real-crypto cross-language vectors are in
`conformance/vectors/revocation.exec.v2.json`; v1 remains byte-frozen as part of
the historical external clean-room bundle. The
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
| `i_future_effective_instant` | `revoked_at` is later than the decision time | reject | `effective_at_or_before_T` |
| `j_malformed_target_shape` | Both sides carry an empty id or malformed digest | reject | `target_bound` |
| `k_algorithm_label_mismatch` | Genuine Ed25519 bytes labeled as another algorithm | reject | `revoker_signature_valid` |
| `l_revoker_key_id_substitution` | Full proof key id does not match the SPKI | reject | `revoker_key_bound` |
| `m_unsigned_top_level_injection` | Unsigned top-level member injected | reject | `structure` |
| `n_unsigned_proof_payload_injection` | Second unsigned payload representation injected | reject | `structure` |
| `o_empty_presented_key_with_valid_pinned_signature` | Empty proof key tries to borrow a signature verified under the pin | reject | `revoker_key_pinned` |
| `p_non_string_revoker_id` | Structured `revoker_id` attempts map-key confusion or a crash | reject | `revoker_key_pinned` |
| `q_timestamp_over_precision` | `revoked_at` has more than nine fractional digits | reject | `revoked_at_present` |
| `z_well_formed_binding_revocation` | Pinned revoker, logical target binding, real proof | accept | — |
| `z2_is_revoked_true_among_unrelated` | One valid binding statement among unrelated ones | accept | — |
| `z3_old_terminal_revocation_remains_valid` | Old revocation presented with a legacy max-age option | accept | — |
| `z4_historical_v1_key_label_exact_pin` | Historical local key label with the exact pinned SPKI | accept | — |

Run: `npx vitest run tests/revocation.test.js`.

---

## 7. Residual Risk — what offline revocation does NOT prove

**This profile proves a revocation statement is AUTHENTIC and BINDS the target.
It does NOT prove you hold the LATEST revocation state.** That distinction is the
whole risk, and it is stated here plainly.

What this profile **does** prove (offline, no network):

- The statement was **signed by a named, pinned revoker** — an unpinned or
  self-asserted key confers nothing.
- The statement **binds the same logical `(target_id, action_hash)`** the relying party
  is reasoning about — a revocation for action A cannot revoke action B.
- The signed fields (target, `revoker_id`, `revoked_at`, `reason`) were **not
  edited after signing**.
- The effective instant is at or before the verifier's decision time.

What this profile **does NOT** prove, and what is **out of scope**:

- **That no revocation exists that you were not handed.** "Has this authorization
  been revoked by a statement I do not hold?" is a **freshness / liveness /
  transparency** question — exactly the gap **OCSP** and **CRLs** exist to fill.
  The offline check answers *"is THIS revocation real and for THIS target,"* not
  *"is the absence of a revocation trustworthy."* **Treating
  absence-of-statement as proof-of-not-revoked is a relying-party error this
  profile cannot prevent.**
- **Liveness in general.** A relying party that needs to rely on current
  non-revocation **MUST** consult an authenticated status mechanism or use a
  separately signed status assertion with a policy-bounded age. That status
  evidence may become stale; the terminal revocation record may not.
- **That the revoker was entitled to revoke.** This profile verifies *who* signed
  and *what* it binds; whether `revoker_id` had the authority to revoke this
  target is an authorization-policy question for the relying party's pinning
  policy (who you pin as a revoker for a given target), not a property of the
  signature.
- **Artifact-byte identity beyond the action commitment.** `action_hash`
  commits to the action (or commit hash under that target profile); it does not
  hash arbitrary unsigned wrapper bytes. If byte-for-byte artifact identity is
  required, the target profile must supply and bind a separate artifact digest.

> **Framing (reuse this language).** "An EP-REVOCATION-v1 statement is a portable,
> offline-verifiable proof that a named, pinned revoker revoked *this specific
> target*. It is the CRL/OCSP *response* — proof a specific revocation is real —
> not the CRL/OCSP *service*: it does not tell you about revocations you were
> never handed. A relying party that needs to know the *absence* of a revocation
> is trustworthy must consult authenticated, fresh status evidence.
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
- **One closed representation.** The verifier refuses unknown statement and
  proof members and recomputes the signed payload. Tampered
  `revoked_at`/`reason` fail because the recomputed bytes differ from what was
  signed.
- **Terminality is monotonic.** Never apply a freshness window to a revocation
  fact. Freshness belongs to a separate non-revocation/status assertion. Do not
  read absence of a valid revocation statement as "not revoked elsewhere."
- **No novel cryptography; one explicit trust input.** The profile reuses
  detached Ed25519 verification and requires a relying-party-pinned revoker
  key. The carried key and signature grant no authority by themselves.

---

## 9. Governance

This profile is **experimental** and MUST be ratified by an Extension PIP before
it is part of the protocol. It changes no frozen Core object and is governed
exactly as `EP-PROVENANCE-CHAIN-v1` (PIP-009), `EP-EXECUTION-INTEGRITY-v1`
(PIP-010), and the WYSIWYS display-attestation profile: composition, not
ownership; an additive signed claim + a fail-closed verifier check; honest
residual stated plainly.
