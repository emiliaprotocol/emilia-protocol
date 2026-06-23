<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright EMILIA Protocol, Inc. -->

# EP-WYSIWYS — Deterministic Rendering + Display Attestation (SPECIFICATION PROPOSAL)

**Status:** Draft / Experimental specification proposal
**Type:** Extension (additive over EP Core v1.0)
**Requires:** PIP-001 (EP Core v1.0 Freeze), EP-RECEIPT-v1
(`standards/draft-schrock-ep-authorization-receipts-03.md` §3, §6.2–6.3, §11.3)
**Wire tag:** `EP-DISPLAY-ATTESTATION-v1`
**Render profile:** `EP-WYSIWYS-RENDER-v1`
**Reference implementation:** `lib/wysiwys/render.js`
**Conformance vectors:** `conformance/vectors/wysiwys.v1.json`
**Conformance tests:** `tests/wysiwys.test.js`

> This is a **specification proposal** plus a **reference implementation**. It
> is **experimental**. It is **not** a production claim, asserts **no**
> customers, and reports **no** metrics. It MUST be ratified by a PIP before it
> can be called part of the protocol. It adds **no new trust assumptions**
> beyond those already required to verify an EP-RECEIPT-v1 receipt, plus a
> single detached Ed25519 verification of the signing client's claim — which
> grants no authority on its own.
>
> **WYSIWYS — "What You See Is What You Signed" — is NOT solved by this profile.**
> Read [§7 Residual Risk](#7-residual-risk-wysiwys-is-not-solved) before relying
> on anything here. This profile *reduces* the presentation-attack surface; it
> does not *eliminate* it.

---

## 1. Abstract

A verified EP authorization receipt proves a named human produced a
user-verified signature over a context hash that commits to an exact action
(I-D §6.3). It does **not** prove the signing surface *displayed* that action
honestly. That gap — the **presentation attack** (I-D §11.3: "the approver signs
context hash H believing it represents action X when it represents action Y") —
is the gravest risk in the protocol, and cryptography alone cannot close it.

This profile narrows the gap with two additive pieces, neither of which touches
the frozen Core:

1. A **deterministic renderer** — `renderAction()`, a **pure function** from the
   canonical Action Object (the exact bytes `action_hash` commits to) to a
   byte-identical human-readable rendering. Because the rendering is a pure
   function of the *signed* action, an **offline verifier can re-derive it** and
   reject any rendering that is not the deterministic function of the action
   (the rendering says "$1" while the signed action is "$82,000").

2. A **display attestation** — `EP-DISPLAY-ATTESTATION-v1`, a signed claim by the
   signing client that binds the **rendering hash** to the **action hash**: "I
   rendered *this* representation of *this* action." A verifier requires a valid
   display attestation for **high-stakes** actions and fails closed when it is
   missing or forged.

The renderer is `EP-WYSIWYS-RENDER-v1`; the attestation is
`EP-DISPLAY-ATTESTATION-v1`. Both compose the **frozen** `canonicalize()` and
`actionHash()` from `@emilia-protocol/issue`, so the rendering binds to the very
bytes the receipt signed, by construction.

---

## 2. Relationship to the Frozen Core (additive, no modification)

The EP Core is frozen under **PIP-001**. This profile:

- **Does not** modify the `EP-RECEIPT-v1` wire format, canonicalization, or
  signature path.
- **Does not** modify `packages/verify` or `packages/issue`.
- **Imports** the frozen `canonicalize()` and `actionHash()` as the single
  source of canonicalization truth (`lib/wysiwys/render.js` →
  `../../packages/issue/index.js`), exactly as `lib/provenance/chain.js` does.
- Stores the display attestation **alongside** the receipt (e.g. in an audit
  event's `after_state`, or a provenance bundle's optional block), **never**
  inside the signed receipt body. Verifiers that predate this profile continue
  to verify receipts unchanged; new verifiers add the display check.

This realizes I-D §11.3 **Control 1** ("render from the exact hashed bytes,
never a re-described copy" — Enforcement-Point conformance rule **C-18**) as a
*verifiable* property: the rendering is no longer merely asserted to come from
the hashed bytes; an offline verifier **re-derives it from those bytes** and
rejects any deviation.

---

## 3. The deterministic renderer (`renderAction`)

### 3.1 Definition

```
renderAction(action) -> {
  render_profile: "EP-WYSIWYS-RENDER-v1",
  action_hash:    "sha256:<hex>",   // actionHash(action), the FROZEN hasher
  lines:          [ { label, value }, ... ],
  text:           "<label>: <value>\n...",   // human-readable rendering
  display_hash:   "sha256:<hex>"    // sha256(canonicalize({render_profile, action_hash, lines}))
}
```

`renderAction()` **MUST** be a **pure function**: for any two canonical Action
Objects that are deeply equal, it MUST return byte-identical `text` and
`display_hash`, on every conformant runtime, in every locale, at any time. It
MUST NOT read the clock, a locale, the environment, a random source, or any I/O.

### 3.2 Rendered fields

The renderer reads a **fixed, closed set** of action fields, in fixed order:

| Field               | Label          |
| ------------------- | -------------- |
| `action_type`       | Action         |
| `target_resource_id`| Target         |
| `organization_id`   | Organization   |
| `actor_id`          | Initiator      |
| `policy_id`         | Policy         |
| `amount`            | Amount         |
| `currency`          | Currency       |
| `requested_at`      | Requested      |
| `risk_flags`        | Risk signals   |

- The set is **closed**: the renderer never reads a field outside it. The
  *rendering* is therefore total over, and a pure function of, the action's
  rendered fields.
- A `null`/absent value renders the literal absence marker `∅`; it is still part
  of the deterministic output.
- Scalars render via their **canonical JSON scalar form** — `amount: 82000`
  renders `Amount: 82000`. The renderer deliberately does **not** use
  `toLocaleString`/`Intl`: locale-formatted currency is not reproducible across
  runtimes and would break determinism. **Presentation locale is a display
  concern layered ABOVE the attested bytes, never inside them.** A UI may show
  "$82,000.00" to the human; the *attested* and *re-derived* bytes are the
  canonical form.

### 3.3 Binding the rendering to the action

`display_hash` is `sha256(canonicalize({ render_profile, action_hash, lines }))`.
The `action_hash` (the **frozen** `actionHash(action)`) is hashed **into** the
rendering object. This is what binds "*this* rendering" to "*this* signed
action": a verifier re-derives both `action_hash` and `display_hash` from the
action it was handed and rejects on any mismatch (§5). Any change to any rendered
field changes `display_hash`; any change to the signed action changes both
`action_hash` and `display_hash`.

---

## 4. The display attestation (`EP-DISPLAY-ATTESTATION-v1`)

A display attestation is the signing client's signed claim of what it rendered.

```json
{
  "@version": "EP-DISPLAY-ATTESTATION-v1",
  "render_profile": "EP-WYSIWYS-RENDER-v1",
  "action_hash": "sha256:<hex>",
  "display_hash": "sha256:<hex>",
  "proof": {
    "algorithm": "Ed25519",
    "signer_key_id": "ep:key:client#1",
    "signed_payload_b64u": "<b64u canonicalize({@version, render_profile, action_hash, display_hash})>",
    "signature_b64u": "<b64u Ed25519 signature over signed_payload>",
    "public_key": "<b64u SPKI DER>"
  }
}
```

- `action_hash` / `display_hash` MUST be the outputs of `renderAction()` over the
  action the client rendered.
- `proof` is **optional at the object level** but **REQUIRED** by the verifier
  when `opts.requireSignedAttestation` is set (and, by policy, for high-stakes
  actions). An unsigned attestation is a bare claim a verifier reports but never
  treats as signed.
- The signature covers the **canonical bytes** of
  `{@version, render_profile, action_hash, display_hash}`. The verifier
  **independently recomputes** those bytes from the re-derived rendering and
  rejects a signature over any other bytes (§5).
- `signer_key_id` names the signing-client key; the verifier pins it via
  `opts.displaySignerKeys` and rejects a proof under any other key.

The signing-side helper is `buildDisplayAttestation({ action, signer })`.

---

## 5. Verifier rule (`verifyDisplayAttestation`) — FAIL CLOSED

```
verifyDisplayAttestation(action, attestation, opts) -> { valid, checks, errors, display_hash }
```

Given the **signed** canonical action (`receipt.action`) and an optional
attestation, the verifier:

1. **Re-renders the signed action** with `renderAction()`. The verifier NEVER
   trusts a producer-supplied rendering; it recomputes one. (`render_deterministic`)
2. **Presence.** If `opts.requireDisplayAttestation` (the verifier-side
   high-stakes policy) is set and no attestation is present, **REJECT**
   (`attestation_present` = false). A required attestation that is absent is a
   rejection, not a pass.
3. **Rendering is the deterministic function of the signed action.** The
   attestation's `action_hash` MUST equal the frozen `actionHash(action)`, and
   its `display_hash` MUST equal the re-derived `display_hash`. Otherwise the
   rendering said one thing and the signed action another — **REJECT**
   (`display_hash_match` = false). *This is the "$1 vs $82k" rejection.*
4. **Signature.** When a `proof` is present (or `opts.requireSignedAttestation`
   is set), the verifier recomputes the expected canonical payload from the
   re-derived rendering and requires the proof to (a) sign **exactly** those
   bytes (defeats signing-over-unrelated-bytes) and (b) verify under the key
   **pinned for `signer_key_id`** via `opts.displaySignerKeys` (defeats key
   substitution). An **unpinned or absent** signer key is itself a rejection —
   without a pin the signature is checkable only under the producer's own
   self-asserted key, which confers no attribution. Otherwise **REJECT**
   (`proof_signed` = false).

The verdict is `valid = AND(all gating checks)`. A high-stakes action is
accepted only when a present, correctly-bound, validly-signed attestation
matches the deterministic rendering of the signed action.

**High-stakes determination.** Whether an attestation is *required* is a
**verifier-side policy**, computed from the signed action (e.g. amount at/above a
threshold, or a policy-flagged action type), and supplied to the verifier via
`opts.requireDisplayAttestation`. A producer can never *lower* this bar: the
requirement is decided by the verifier, not read from any producer-supplied
flag.

### 5.1 Fail-closed obligations (any one ⇒ `valid:false`)

- Presented rendering is not the deterministic rendering of the signed action
  (`display_hash` or `action_hash` mismatch).
- A required display attestation is missing for a high-stakes action.
- A present attestation's proof signs unrelated bytes, or its `signer_key_id` is
  not pinned by the verifier, or it verifies only under a key that is not the
  pinned `signer_key_id` key.
- The signed action and its `action_hash` disagree (a malformed input is itself
  a fail-closed rejection upstream, in `verifyTrustReceipt()` step 1).

---

## 6. Conformance vectors

`conformance/vectors/wysiwys.v1.json` is the authoritative catalogue; every id
is asserted by name in `tests/wysiwys.test.js`. The negatives are minted with
**real** Ed25519 keys and **real** detached proofs over canonical bytes, so each
is a genuine forgery attempt, not hand-edited JSON.

| Vector id | Scenario | Verdict | Gating check |
| --- | --- | --- | --- |
| `a_rendering_inconsistent_with_action_hash` | Rendering shows $1, signed action is $82k | reject | `display_hash_match` |
| `b_missing_display_attestation_high_stakes` | High-stakes action, attestation required, none supplied | reject | `attestation_present` |
| `c_forged_display_attestation_unrelated_bytes` | Proof signs unrelated bytes | reject | `proof_signed` |
| `c2_forged_display_attestation_wrong_key` | Proof verifies under a non-pinned key | reject | `proof_signed` |
| `d_attestation_binds_wrong_action_hash` | Attestation `action_hash` swapped to another action | reject | `display_hash_match` |
| `z_well_formed_high_stakes_signed` | Re-rendered, bound, signed under the pinned key | accept | — |
| `z2_well_formed_low_stakes_no_attestation` | Low-stakes, attestation not required, none supplied | accept | — |

Run: `npx vitest run tests/wysiwys.test.js`.

---

## 7. Residual Risk — WYSIWYS is NOT solved

**This profile does not solve WYSIWYS, and no software profile can.** A
signature proves user presence and approval toward *whatever was rendered*.
Cryptography cannot prove the signing surface displayed the action honestly
(I-D §11.3; `docs/RECEIPT-CLAIMS.md`).

What this profile **does** prove:

- The rendering an offline verifier checks is the **deterministic function of the
  exact signed action**. A rendering inconsistent with the signed action
  (says "$1" while the action is "$82,000") is **rejected**.
- A high-stakes action carries a **signed, attributable claim** by a named
  signing-client key of what that client rendered — and that claim is rejected
  if it is missing, mis-bound, or forged.

What this profile **does NOT** prove, and what is **out of scope**:

- **A compromised signing client/device.** A fully compromised client can render
  one thing to the human, hash and attest *another*, and sign whatever it wants.
  The display attestation proves only what the client **CLAIMED** it rendered —
  **never** what a trustworthy surface actually showed a human. `valid:true`
  here does **not** mean "the human saw the truth."
- **That the human read or understood the rendering.** Time-to-sign telemetry and
  planted-mismatch drills (`docs/WEBAUTHN-SIGNOFF.md`, `docs/SIGNOFF-UX-METRICS.md`)
  address attention; this profile does not.
- **That the human was not coerced.** Separation of duties and attribution apply
  (see `docs/RECEIPT-CLAIMS.md`); a signed display attestation makes a hostile
  rendering *attributable*, raising the cost of an undetectable presentation
  attack — it does not make it impossible.

The compromised-device residual is addressed **only** by a layer **above** this
profile: **device / TEE attestation** — e.g. Apple App Attest, Android Play
Integrity, or WebAuthn device-bound key attestation — which can attest that the
rendering ran on a genuine, unmodified client. That layer is **not** a property
of this profile and is **not** claimed here.

Two further controls from I-D §11.3 remain complementary and unshipped here:
**Control 2** (render templates committed by `policy_hash`) and **Control 3** (an
independent second rendering surface for high-value policies). This profile is
the verifiable form of **Control 1**.

> **Framing (reuse this language).** "The display attestation proves the signing
> client rendered *this specific representation* of the action and bound it to
> the signed action hash; an offline verifier rejects any rendering that is not
> the deterministic function of the signed action. It does **not** prove the
> device was trustworthy or the approver paid attention. It raises the cost of
> an *undetectable* presentation attack by adding a signed, re-derivable claim
> about what was shown — it does not eliminate the attack."

---

## 8. Security considerations

- **Canonicalization is load-bearing.** The renderer reuses the frozen
  `canonicalize()`; the signer and verifier MUST produce identical bytes. The
  reference re-imports the frozen function rather than re-implementing it.
- **No locale in the attested bytes.** Currency/locale formatting is a display
  concern above the attested bytes; placing it inside would break determinism
  and let two honest clients disagree on the hash.
- **Verifier-side high-stakes policy.** The requirement to present an attestation
  is decided by the verifier from the signed action, never by a producer flag,
  so a producer cannot suppress the requirement.
- **One new primitive, no new trust.** The only added primitive is detached
  Ed25519 verification of the client's claim; it grants no authority by itself.
- **Honesty gate.** As with `signEvidenceReceipt()`, a display attestation
  asserts a fact (what the client rendered) that must be the deterministic
  function of the signed action; the verifier never accepts a claim it cannot
  re-derive.

---

## 9. Governance

This profile is **experimental** and MUST be ratified by an Extension PIP before
it is part of the protocol. It changes no frozen Core object and is governed
exactly as `EP-PROVENANCE-CHAIN-v1` (PIP-009): composition, not ownership;
additive signed claim + verifier check; honest residual stated plainly.
