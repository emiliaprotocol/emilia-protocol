<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright EMILIA Protocol, Inc. -->

# EP-EYE-SET — Eye Continuous-Eval as a Security Event Token (SPECIFICATION PROPOSAL)

**Status:** Draft / Experimental specification proposal
**Type:** Extension (additive over EP Core v1.0; composition target named in EMILIA-EYE-ADVISORY-SPEC §9.1)
**Requires:** PIP-001 (EP Core v1.0 Freeze), EP-RECEIPT-v1; `docs/EMILIA-EYE-ADVISORY-SPEC.md`
**Wire tag:** `EP-EYE-SET-v1`
**Token type:** `secevent+jwt` (RFC 8417 Security Event Token, JWS-COMPACT)
**Reference implementation:** `lib/eye/set.js` (`buildEyeSet`, `verifyEyeSet`)
**Conformance vectors:** `conformance/vectors/eye-set.v1.json`
**Conformance tests:** `tests/eye-set.test.js`

> This is a **specification proposal** plus a **reference implementation**. It is
> **experimental**. It is **not** a production claim, asserts **no** customers, and
> reports **no** metrics. It MUST be ratified by a PIP before it can be called part
> of the protocol. It adds **no new trust assumptions** beyond a single detached
> EdDSA verification of the Eye emitter's claim under a **pinned** key — which
> grants no authority on its own.
>
> **An Eye SET INFORMS; it is NEVER the sole gate and NEVER authorizes.**
> `verifyEyeSet()` returns an advisory **posture** for a relying party to *act on*
> (tighten / revoke / hold). It **never** returns allow/deny. Read
> [§7 Residual Risk](#7-residual-risk--out-of-scope) before relying on anything here.

---

## 1. Abstract

The Eye advisory spec (`docs/EMILIA-EYE-ADVISORY-SPEC.md`) defines a computed,
per-scope **advisory** — `status` (`clear` | `caution` | `elevated` |
`review_required`), `reason_codes`, `recommended_policy_action`,
`scope_binding_hash`, `advisory_hash`, `issued_at`, `expires_at` — and is explicit
(§9) that the v1 advisory is **unsigned**: its authenticity rests on the
authenticated channel, and its durable verifiable record is the EP receipt. §9.1
names a **forward-compatible path**: carry the advisory as a **Security Event Token
(RFC 8417)** JWS, and transport it CAEP-style, *supplying the verifiable
scope-binding and the "never the sole gate" invariant that SSF/CAEP deliberately
leave undefined.*

This profile **builds that SET emission**, additively, without touching the frozen
Core:

1. `buildEyeSet(advisory, { signer, audience })` — emits the advisory as a
   `secevent+jwt` in **JWS-COMPACT** serialization (`header.payload.signature`),
   signed **EdDSA** via `node:crypto`. No new dependency.

2. `verifyEyeSet(setCompact, opts)` — a **fail-closed** verifier that validates the
   JWS under a key **pinned for the kid/iss**, rejects `alg:'none'` / algorithm
   confusion, checks `typ`, the required SET claims, audience (when pinned),
   freshness (when required), and the **in-band `never_sole_gate:true` marker** —
   then returns the advisory **posture**, never allow/deny.

The redaction posture of `lib/eye/webhook-notify.js` is reused: the SET's subject
identifier (`sub_id`) is the re-derivable **`scope_binding_hash`**, **never** a raw
`subject_ref` / `actor_ref` / `target_ref` / `issuer_ref`.

### 1.1 Honest boundary — what is prior art vs. what is contributed

**Prior art (NOT claimed novel here):** SET (RFC 8417), JWS (RFC 7515), and OpenID
SSF/CAEP — including continuous evaluation *and* the posture that a signal "is never
the sole authorization gate." The never-sole-gate invariant itself is documented
prior art (Eye spec §8, §9.1, §11). **Contribution:** the *verifiable, scope-bound*
SET that carries the never-sole-gate invariant **in-band** (an event member
`never_sole_gate:true`, re-checked by the verifier) together with the **redaction
posture** (`sub_id` = `scope_binding_hash`, never a raw identifier). Nothing in the
RFC 8417 / JWS path is reinvented.

---

## 2. Relationship to the Frozen Core (additive, no modification)

The EP Core is frozen under **PIP-001**. This profile:

- **Does not** modify the `EP-RECEIPT-v1` wire format, canonicalization, or
  signature path; does not touch `packages/verify` or `packages/issue`.
- **Imports** the frozen `canonicalize()` from `@emilia-protocol/issue`
  (`lib/eye/set.js` → `../../packages/issue/index.js`, exactly as
  `lib/provenance/chain.js` and `lib/execution/integrity.js` do) wherever canonical
  bytes are needed; it re-implements **nothing** cryptographic of the receipt path.
- Carries the SET **alongside** Eye's transport — it is an emission *of the
  advisory*, not a mutation of the receipt. The advisory recorded inside an
  `EP-RECEIPT-v1` claim context remains the durable record; the SET is an
  independently verifiable, attributable copy of the same non-attributable facts.
- Does **not** make Eye a gate. The Eye spec's monotonicity / tighten-only
  contract (§6, §7.4, §8) is unchanged: a non-`clear` posture can only ever
  **tighten** a relying party's base decision, never relax it.

---

## 3. The SET emission (`buildEyeSet`)

### 3.1 Signature

```
buildEyeSet(advisory, { signer, audience }) -> "<b64u(header)>.<b64u(payload)>.<b64u(signature)>"
```

- `advisory` — an `eye-advisory-v1`-shaped object. Its `status` MUST be an
  **actionable posture-change** status (`caution` | `elevated` | `review_required`).
  A `clear` status is the default-path, no-change posture and **MUST NOT** be
  emitted as a posture-change event (§3.4).
- `signer` — `{ kid, privateKey }` (an Ed25519 private key, `node:crypto`
  `KeyObject` or equivalent). The `kid` names the emitter key a relying party will
  pin.
- `audience` — the intended relying party identifier, placed in `aud`.

### 3.2 JOSE header

```json
{ "alg": "EdDSA", "typ": "secevent+jwt", "kid": "<emitter kid>" }
```

`alg` is fixed to `EdDSA`. `typ` is fixed to `secevent+jwt` (RFC 8417 §2.3). `kid`
identifies the pinned emitter key.

### 3.3 SET payload (claims)

```json
{
  "iss": "<emitter issuer id>",
  "iat": 1711393200,
  "jti": "<unique token id>",
  "aud": "<relying-party id>",
  "sub_id": "sha256:<scope_binding_hash>",
  "events": {
    "https://schemas.emiliaprotocol.ai/secevent/eye-advisory": {
      "status": "elevated",
      "reason_codes": ["device_fingerprint_changed", "high_severity_signal_active"],
      "recommended_policy_action": "step_up_auth",
      "advisory_hash": "sha256:<hex>",
      "expires_at": "2026-03-25T20:00:00Z",
      "never_sole_gate": true
    }
  }
}
```

- `iss`, `iat`, `jti`, `aud` are standard SET/JWT claims. `iat` is seconds since
  epoch; `jti` is a unique identifier for replay/dedup.
- **`sub_id` is the scope-bound `scope_binding_hash`** — a re-derivable SHA-256 over
  the scope fields, **never** a raw `subject_ref` / `actor_ref` / `target_ref` /
  `issuer_ref`. This is the same "fact, not opinion" posture as
  `lib/eye/webhook-notify.js#redactAdvisory`: a relying party that knows the scope
  can re-derive `sub_id`; it leaks nothing attributable on its own.
- **`events`** is keyed by a single CAEP-style **event URI**
  (`https://schemas.emiliaprotocol.ai/secevent/eye-advisory`). The event member
  carries **only non-attributable advisory facts**: `status`, `reason_codes`,
  `recommended_policy_action`, `advisory_hash`, `expires_at`, and the explicit
  **`never_sole_gate: true`** marker.
- The event member carries **no** raw identifiers, no transaction volumes, no
  evidence contents, and no allow/deny verdict — mirroring the webhook redaction
  contract.

### 3.4 `clear` is not an event

`buildEyeSet` **MUST refuse** to emit a SET for `status:'clear'`. `clear` maps to
`allow_normal_flow` / no requirement change (Eye spec §6); emitting it as a signed
posture-change event would let a replayed or forged `clear` be read as an
affirmative "authorized" signal — exactly the sole-gate misuse the profile refuses.
A `clear` (or unknown) status is a build-time rejection.

### 3.5 Signing

The signature is **EdDSA over the JWS signing input** — the ASCII string
`b64u(header) + "." + b64u(payload)` (RFC 7515 §5.1) — produced with `node:crypto`.
b64u is base64url **without** padding. No new dependency is introduced.

---

## 4. The verifier (`verifyEyeSet`) — FAIL CLOSED

```
verifyEyeSet(setCompact, opts) -> {
  valid,            // boolean
  checks,           // { alg_is_eddsa, emitter_key_pinned, jws_signature_valid,
                    //   typ_ok, claims_present, audience_match, fresh,
                    //   never_sole_gate_present, status_is_actionable }
  errors,           // string[]
  posture           // present only when valid:true — see §4.2; NEVER allow/deny
}
```

`opts`:

| Option | Meaning |
| --- | --- |
| `pinnedKeys` | **Required.** Map from `(kid` and/or `iss)` → the pinned Ed25519 public key. An emitter not present here is **unpinned** and rejected. |
| `audience` | When set, `payload.aud` MUST equal it; when unset, audience is not gated. |
| `requireFresh` | When set (or by relying-party policy), `iat`/`exp` freshness is enforced. |
| `maxAgeSec` | Maximum `iat` age when freshness is required. |
| `now` | Injectable clock (seconds) for deterministic tests. |

Given the compact SET, the verifier (each step fail-closed):

1. **Parse & `alg` gate.** Split on `.`; decode the header. **REJECT** any `alg`
   other than `EdDSA` — including `alg:'none'` and any non-EdDSA value — **before**
   any verification. An unsecured token is never treated as signed.
   (`alg_is_eddsa`)
2. **`typ` gate.** `typ` MUST be `secevent+jwt`. (`typ_ok`)
3. **Pin the emitter key.** Resolve the public key from `opts.pinnedKeys` for the
   header `kid` / payload `iss`. If there is no pinned key, **REJECT** — a
   self-asserted `kid` confers nothing (mirrors execution-integrity
   `f_unpinned_executor_key`, wysiwys `c3_unpinned_display_signer_key`).
   (`emitter_key_pinned`)
4. **Verify the JWS signature.** Recompute the signing input
   `b64u(header) + "." + b64u(payload)` from the **presented** header/payload and
   verify the signature under the **pinned** key only — never under a
   producer-supplied public key. A forged signature, a wrong/substituted key, or a
   payload **tampered after signing** (e.g. a status downgrade) all fail here.
   (`jws_signature_valid`)
5. **Required claims.** `iss`, `iat`, `jti`, `aud`, `sub_id`, and exactly one
   `events` member carrying `status`, `reason_codes`, `recommended_policy_action`,
   `advisory_hash`, `expires_at` MUST be present and well-typed. (`claims_present`)
6. **Audience.** When `opts.audience` is set, `payload.aud` MUST equal it; otherwise
   **REJECT**. (`audience_match`)
7. **Freshness.** When required, `expires_at`/`exp` MUST not be in the past and
   `iat` MUST not be older than `maxAgeSec`. A stale SET is rejected, never used to
   tighten **or** relax. (`fresh`)
8. **Actionable status.** The event `status` MUST be `caution` | `elevated` |
   `review_required`. A signed `clear` event is **REJECTED**.
   (`status_is_actionable`)
9. **Never-sole-gate marker.** The event member MUST carry `never_sole_gate: true`.
   Its absence (or a non-`true` value) is a **rejection**. (`never_sole_gate_present`)

`valid = AND(all gating checks)`.

### 4.1 What the verifier NEVER does

`verifyEyeSet` **never** returns `allow` / `deny` and **never** authorizes. There is
no decision vocabulary in its output. It returns a **posture** the relying party
combines, **tighten-only**, with its own base decision (Eye spec §7.4). The
never-sole-gate invariant is therefore carried **in-band** (the marker) *and*
enforced **structurally** (the verifier exposes no allow/deny path).

### 4.2 The returned posture (on `valid:true`)

```json
{
  "status": "elevated",
  "reason_codes": ["device_fingerprint_changed", "high_severity_signal_active"],
  "recommended_policy_action": "step_up_auth",
  "scope_binding_hash": "sha256:<hex>",
  "advisory_hash": "sha256:<hex>",
  "expires_at": "2026-03-25T20:00:00Z",
  "never_sole_gate": true
}
```

This is **advice**, not a command (Eye spec §6). The relying party MUST recompute
`scope_binding_hash` against the action it is gating (Eye spec §7.3) and apply the
posture tighten-only. It MUST NOT read this as authorization.

---

## 5. Conformance vectors

`conformance/vectors/eye-set.v1.json` is the authoritative catalogue; every id is
asserted by name in `tests/eye-set.test.js`. The negatives are minted with **real**
Ed25519 keys and **real** EdDSA signatures over the **real** JWS signing input, so
each is a genuine forgery / tamper / confusion attempt, not hand-edited JSON.

| Vector id | Scenario | Verdict | Gating check |
| --- | --- | --- | --- |
| `a_forged_jws_signature` | Signature over unrelated bytes | reject | `jws_signature_valid` |
| `b_unpinned_emitter_kid` | Self-asserted, unpinned kid | reject | `emitter_key_pinned` |
| `c_wrong_pinned_key_substitution` | Signed by a different key than pinned | reject | `jws_signature_valid` |
| `d_alg_none_confusion` | `alg:'none'` / algorithm confusion | reject | `alg_is_eddsa` |
| `e_tampered_payload_status_downgrade` | Status downgraded after signing | reject | `jws_signature_valid` |
| `f_audience_mismatch` | `aud` ≠ `opts.audience` | reject | `audience_match` |
| `g_expired_set_exp_past` | `expires_at` in the past | reject | `fresh` |
| `h_iat_too_old` | `iat` older than `maxAgeSec` | reject | `fresh` |
| `i_missing_never_sole_gate_marker` | Marker absent / not `true` | reject | `never_sole_gate_present` |
| `j_clear_status_emitted_as_event` | `clear` emitted as posture event | reject | `status_is_actionable` |
| `z_well_formed_elevated_set_pinned_fresh` | Pinned, fresh, audience-matched, marked | accept | — |
| `z2_well_formed_review_required_no_audience_pin` | Pinned, fresh, no audience pin, marked | accept | — |

Run: `npx vitest run tests/eye-set.test.js`.

---

## 6. Security considerations

- **Pin the emitter; never trust a self-asserted `kid`.** The only added trust is a
  detached EdDSA verification under a **pinned** key. An unpinned or substituted key
  is a rejection — self-asserted keys confer nothing.
- **`alg` is fixed, checked first.** `alg:'none'` and algorithm confusion are
  rejected before any verification; an unsecured token is never treated as signed.
- **Tamper = signature failure.** Because the signature covers the signing input
  over the original payload, any post-signing edit (notably a status downgrade) is
  caught as a signature failure, not silently honored.
- **Redaction posture.** `sub_id` is the re-derivable `scope_binding_hash`, never a
  raw identifier; the event member carries only non-attributable facts (mirrors
  `lib/eye/webhook-notify.js`). The SET is safe to transport to a relying party
  without leaking who the scope is.
- **Staleness never relaxes; absence never relaxes.** A stale or missing SET is
  treated as *no posture change* (fail-open **as an input**), never as a relax of
  the relying party's base gate (Eye spec §7.2).
- **No new primitive, no new trust.** EdDSA-over-JWS via `node:crypto`; no new
  dependency; the frozen `canonicalize()` is reused where canonical bytes are
  needed. The SET grants no authority by itself.

---

## 7. Residual Risk — out of scope

**An Eye SET INFORMS; it is never the sole gate and never authorizes.** This profile
makes the advisory *attributable, scope-bound, tamper-evident, and fresh-checked*
under a pinned emitter key, and carries the never-sole-gate invariant in-band. It
does not, and cannot, do the following — these are **out of scope**:

- **A fully compromised emitter.** An Eye operator holding the pinned signing key
  can emit a truthful-looking SET for a posture it did not actually compute
  (over-tightening, or — bounded by the never-sole-gate property — under-tightening).
  Pinning bounds this to a **named** key whose claims are attributable; it does not
  make a compromised emitter's claims **true**. The residual is addressed only by
  emitter host/TEE attestation and key-management hygiene, a layer **above** this
  envelope — **not** by this envelope's mathematics. (Mirrors the
  identified-but-not-trusted framing of execution-integrity's executor and PIP-007's
  initiator.)
- **Sole-gate misuse by the relying party.** The `never_sole_gate:true` marker is
  carried and re-checked in-band, and `verifyEyeSet` exposes no allow/deny path. But
  a relying party that ignores its own base policy and *reads the posture as
  authorization* defeats the invariant. That is an integration error this envelope
  cannot prevent by cryptography; conformance is an integrator obligation (Eye spec
  §8, §10), evidenced by tests, not asserted in prose.
- **Under-tightening from a withheld or stale SET.** A relying party that never
  receives the SET proceeds on its base decision (Eye is fail-open as an *input*).
  Staleness never relaxes; absence never relaxes. The envelope cannot compel an
  emitter to speak.

`valid:true` means *a pinned, named emitter made this fresh, scope-bound, in-band
never-sole-gate posture claim, untampered since signing* — **not** "allow," and
**not** "the posture is objectively correct."

> **Framing (reuse this language).** "The Eye SET carries Eye's advisory posture as
> an RFC 8417 Security Event Token, signed under a pinned emitter key, scope-bound by
> `scope_binding_hash`, and marked never-sole-gate in-band. A relying party verifies
> it offline and combines the posture **tighten-only** with its own base decision. It
> is **never** the sole gate and **never** authorizes; `verifyEyeSet` returns a
> posture, never allow/deny. SET/JWS/SSF/CAEP and the never-sole-gate posture are
> prior art; the contribution is the verifiable, scope-bound SET that carries the
> invariant in-band plus the redaction posture. A fully compromised emitter is out of
> scope — pin the emitter key."

---

## 8. Governance

This profile is **experimental** and MUST be ratified by an Extension PIP before it
is part of the protocol. It changes no frozen Core object and is governed exactly as
`EP-WYSIWYS` / `EP-EXECUTION-INTEGRITY-v1` (PIP-010) and `EP-PROVENANCE-CHAIN-v1`
(PIP-009): composition, not ownership; additive signed claim + fail-closed verifier
check; honest residual stated plainly. It realizes the forward-compatible path the
Eye advisory spec named in §9.1 without modifying the v1 advisory or the receipt
flow.
