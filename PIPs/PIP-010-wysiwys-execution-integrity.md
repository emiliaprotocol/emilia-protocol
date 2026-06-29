# PIP-010: WYSIWYS / Execution-Integrity Profile — Display Attestation + Execution Binding

**Status:** Draft
**Type:** Extension (additive)
**Created:** 2026-06-14
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP defines an **additive profile** of two signed claims and their
fail-closed verifier checks that tighten the two seams an authorization
receipt cannot close by itself: **what the approver saw when they signed**
(WYSIWYS — "what you see is what you signed") and **whether what executed
is what was approved** (execution integrity). The two wire tags are:

- **`EP-DISPLAY-ATTESTATION-v1`** — a signed claim by the signing client
  asserting *"I rendered THIS representation of THIS action"*, where the
  rendering is a **pure, deterministic function** of the exact action
  bytes the receipt's `action_hash` commits to; and
- **`EP-EXECUTION-INTEGRITY-v1`** — a signed claim binding the canonical
  hash of the action that **actually executed** to the **approved**
  `action_hash`, so an approve-A-run-B substitution is detectable by
  re-derivation.

The profile is **purely additive and by-composition only**. It does
**not** modify `EP-RECEIPT-v1` (`EP-AUTHORIZATION-RECEIPT-v1`), its JCS
canonicalization (RFC 8785-style), its Ed25519 signature, or the frozen
§6.3 offline-verification algorithm; it touches neither `packages/verify`
nor `packages/issue`. Both claims live **outside** the frozen receipt: a
verifier that does not understand them verifies the embedded receipt
exactly as today. Verifying the profile introduces **no new trust root**:
it imports the frozen `canonicalize()` and `actionHash()` as the single
source of truth and re-derives the rendering and the executed-action hash
from the same bytes the receipt already signed, adding exactly one local
primitive — detached Ed25519 verification of an attestation `proof` —
which grants no trust by itself. The profile **fails closed**.

> **WYSIWYS IS NOT SOLVED HERE — and this PIP does not claim it is.** A
> signature proves user presence and approval toward *whatever was
> rendered*; cryptography cannot prove the signing surface displayed the
> action honestly. This profile **reduces** the presentation-attack
> surface (deterministic rendering as a pure function of the signed
> action, plus a signed claim of what was shown) and lets an offline
> verifier reject any rendering that is *not* that deterministic function.
> It does **not** eliminate the residual: a fully compromised signing
> device/client can render one thing, attest another, or lie about both.
> That residual is **out of scope** and is addressed only by device / TEE
> attestation (see Section 6 and Security Considerations (e)).

This PIP is a spec proposal accompanied by an **experimental** reference
implementation; it makes no production or customer claims and reports no
metrics.

## Motivation

A verified authorization receipt proves a named human's device-bound,
user-verified signature committed to an exact action hash, under a stated
policy, before execution, consumed at most once, with separation of
duties — all offline-verifiable (RECEIPT-CLAIMS, I-D §6.3). Two facts it
provably does **not** establish are called out in the I-D itself:

1. **That the rendering was faithful (I-D §11.3).** The signature is over
   `action_hash`. If the signing surface showed "pay $100" while the
   hashed action was "pay $1,000,000", the math still verifies. The I-D
   lists three controls for this presentation-attack risk: (1) render
   from the exact hashed bytes, never a re-described copy; (2) bind render
   templates to policy; (3) a second rendering surface for high value.
   Control 1 is shipped at the page level (`app/signoff/[signoffId]/page.js`
   already renders from the persisted canonical action), but there is **no
   signed, offline-verifiable proof that control 1 was exercised** — no
   artifact a relying party can check after the fact.

2. **That what executed is what was approved.** The receipt freezes the
   approved `action_hash`, but nothing in the frozen path re-derives the
   hash of the action that *actually ran* and compares it back. Approve A,
   run B, and record A's hash: the audit trail is dishonest and the
   substitution is silent.

The cleanest way to address both without touching frozen Core is two
**additive signed claims** that bind to the same bytes the receipt
already committed to, plus verifier checks that **re-derive** rather than
trust. This is composition, not ownership: neither claim owns or re-signs
any field of a receipt. It is the same discipline PIP-009 applied at the
bundle level and PIP-007 at the context level — additive, non-breaking,
claim-bearing, verified by inherited primitives.

What honesty requires us to state up front: **neither claim can make
WYSIWYS true.** They make a *narrower* thing true and verifiable — that
the rendering is the deterministic function of the signed action, and
that the recorded execution hashes to the approval — and they make the
residual (a lying device) explicit and out of scope. That is the whole
point of the profile.

## Specification

The normative object structures and full verification algorithms are
implemented in **`lib/wysiwys/render.js`** and
**`lib/execution/integrity.js`**; the attack catalogues are
**`conformance/vectors/wysiwys.v1.json`** and
**`conformance/vectors/execution-integrity.v1.json`**. This section
summarizes the objects and the verification obligations the PIP ratifies.

### 1. Deterministic rendering (the WYSIWYS anchor)

`renderAction(action)` is a **pure function** from the canonical Action
Object (I-D §3 — the exact bytes `action_hash` commits to) to a
human-readable rendering. Determinism is the security property: same
action ⇒ byte-identical rendering on any runtime, in any locale.

- The human-visible **lines** are derived from a **fixed, closed set** of
  action fields in fixed order; the renderer reads nothing outside that
  set, so it cannot be steered by added fields.
- Scalar values render via their **canonical JSON scalar form** — never
  `toLocaleString` or any locale/runtime-dependent formatting, which
  would break determinism. Presentation locale is a display concern
  layered **above** the attested bytes, never inside them.
- The rendering's `action_hash` is the **frozen `actionHash(action)`** of
  the *same* object. The attested `display_hash` is
  `sha256(canonicalize({ render_profile, action_hash, lines }))`. Hashing
  the frozen `action_hash` **into** the rendering is what binds *this
  rendering* to *this signed action*: a verifier re-derives both from the
  action and rejects on any mismatch. The bound `action_hash` is over the
  **whole** action object, so a rendering of any altered action (even one
  that changes only a non-displayed field) yields a different binding —
  the rendering can never silently stand in for a different signed action.

### 2. `EP-DISPLAY-ATTESTATION-v1`

A signed claim emitted by the signing client (the surface that showed the
action to the human):

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `@version` | REQUIRED | string | MUST be `"EP-DISPLAY-ATTESTATION-v1"`. |
| `render_profile` | REQUIRED | string | The render profile id (`"EP-WYSIWYS-RENDER-v1"`). |
| `action_hash` | REQUIRED | string | `"sha256:<hex>"`. MUST equal the frozen `actionHash()` of the signed action. |
| `display_hash` | REQUIRED | string | `"sha256:<hex>"` of the canonical rendering object (Section 1). |
| `proof` | OPTIONAL | object | Detached Ed25519 over `canonicalize({ @version, render_profile, action_hash, display_hash })`: `{ algorithm: "Ed25519", signer_key_id, signed_payload_b64u, signature_b64u, public_key }`. Absent ⇒ unsigned claim, reported, never trusted as signed; rejected when a signed attestation is required. |

The attestation is **not** part of the receipt and adds no field to it.
It carries no truth-bearing field a verifier trusts unre-derived: the
verifier recomputes the rendering from the signed action and checks the
attested hashes against its own.

### 3. `EP-EXECUTION-INTEGRITY-v1`

A signed claim, emitted by the **executor** (a party EP identifies but never
trusts — mirroring PIP-007's framing of the initiator), binding what
executed to what was approved:

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `@version` | REQUIRED | string | MUST be `"EP-EXECUTION-INTEGRITY-v1"`. |
| `executor_id` | REQUIRED | string | The named executor; resolved to a pinned key verifier-side. |
| `executor_public_key` | REQUIRED | string | base64url SPKI-DER; MUST equal the pinned key for `executor_id`. |
| `approved_action_hash` | REQUIRED | string | `"sha256:<hex>"` carried from the approval receipt. |
| `executed_action` | REQUIRED | object | The canonical Action Object that actually ran. The verifier **re-hashes this**; it never trusts a self-declared hash. |
| `executed_action_hash` | REQUIRED | string | `"sha256:<hex>"` = `actionHash(executed_action)`. Cross-checked against the re-hash. |
| `binding_status` | OPTIONAL | string | `"match"` \| `"drift"`. Advisory only; the verifier trusts the **re-derived hash**, not this field. |
| `irreversible` | OPTIONAL | boolean | Evidence label only; cannot relax any verifier obligation. |
| `execution_id` | OPTIONAL | string | |
| `executed_at` | OPTIONAL | string | RFC 3339. |
| `signature_b64u` | REQUIRED-if-signed | string | Detached Ed25519 over `canonicalize()` of the claim's fixed field set (`@version`, `approved_action_hash`, `binding_status`, `executed_action`, `executed_action_hash`, `executed_at`, `executor_id`), recomputed independently by the verifier from the presented fields. |

The honest assembler (`bindExecution`) applies an **honesty gate**: it
refuses to mint a signed attestation claiming `binding_status: "match"`
when the executed action drifts from the approved hash — a signature
asserts a fact that was actually true. (Adversarial tests therefore forge
drift attestations by signing tampered bytes directly, to exercise the
verifier's independent fail-closed checks.)

#### 3.1 High-risk executor-observed field binding

For high-risk actions, hash equality is necessary but not sufficient for a
system-of-record enforcement point. The executor MUST also verify that the
fields it observed at mutation time match the fields authorized by the receipt.
This is not only an amount control. It covers the action's high-risk material:
money (`amount`, `currency`, destination/counterparty fields), code/deploy
targets (`repo`, `ref`, `commit_sha`, `artifact_digest`, `environment`),
permissions (`principal_id`, `role`, `scope`, `permission`), records and
regulated decisions (`record_id`, `case_id`, `decision_id`, `subject_id`,
`before_state_hash`, `after_state_hash`), plus common identity and policy
fields (`organization_id`, `actor_id`, `action_type`, `target_resource_id`,
`policy_id`, `policy_hash`).

The implementation emits an additive `EP-EXECUTION-BINDING-v1` contract with
new high-risk receipts. At execution attestation time, the system-of-record
adapter presents `observed_action` (or equivalent observed fields). The
enforcement endpoint rejects if any required observed field is missing or
differs from the contract, even when the old canonical hash path would otherwise
look clean. In short: EP does not prove a user told the truth about a high-risk
action; it proves a conforming executor refused to proceed unless the
system-observed mutation matched what was authorized.

### 4. Display-attestation verification (additive, fail-closed)

`verifyDisplayAttestation(action, attestation, opts)` re-derives the
rendering from the **signed** action and establishes:

1. **Render determinism.** `renderAction(action)` succeeds (it is total
   over a well-formed action). The verifier never trusts a
   producer-supplied rendering; it recomputes one.
2. **Required presence.** When `opts.requireDisplayAttestation` (a
   high-stakes policy gate) and no attestation is present ⇒ **reject**.
3. **Render binding.** The attested `action_hash` MUST equal the frozen
   hash of `action`, and the attested `display_hash` MUST equal the
   re-derived rendering hash. Either mismatch — *the rendering says one
   thing and the signed action another* — ⇒ **reject**.
4. **Signature.** If a `proof` is present it MUST verify over exactly the
   recomputed canonical bytes, AND under the key **pinned** for the named
   `signer_key_id` via `opts.displaySignerKeys`. An **unpinned or absent**
   signer key, or a key that does not match the pin (key substitution), ⇒
   **reject** — without a pin the signature is checkable only under the
   producer's self-asserted key, which confers no attribution (mirrors the
   execution side's `executor_key_pinned`). If `opts.requireSignedAttestation`
   and no proof ⇒ **reject**.

`valid` is the conjunction of the gating checks only.

### 5. Execution-integrity verification (additive, fail-closed)

`verifyExecutionIntegrity(attestation, receipt, opts)` reads only
`receipt.action_hash` (the frozen approved hash) and establishes:

1. **Presence (fail-closed by default).** A missing attestation is fatal.
   A producer's `irreversible:false` flag **cannot** drop this; only a
   verifier-supplied `opts.reversibilityAsserted(attestation) === true`
   predicate — an independent assertion — can make a missing attestation
   vacuously acceptable.
2. **Executed-hash self-consistency.** The verifier re-hashes
   `attestation.executed_action` with the frozen `actionHash()` and rejects
   unless it equals the self-declared `executed_action_hash` (a lying hash
   field is caught).
3. **Execution binding (drift check).** Using the **re-derived** hash, the
   verifier rejects unless it equals `receipt.action_hash` (execution drift
   / approve-A-run-B). A `binding_status: "match"` that contradicts the
   re-derived hash is ignored — the status is never trusted, the hash is.
4. **Executor key pinning (identified-but-not-trusted).** The
   `executor_id` MUST resolve to a key in `opts.executorKeys`, and the
   presented `executor_public_key` MUST equal that pinned key; an unpinned
   or substituted key is rejected.
5. **Signature.** The detached Ed25519 `signature_b64u` MUST verify under
   the **pinned** key over bytes the verifier **independently recomputes**
   from the presented fields, so a producer cannot present one set of
   fields while claiming a signature over another.

### 6. What the profile does and does not prove

- **`EP-DISPLAY-ATTESTATION-v1` proves:** the signing client asserted
  (and, if signed, signed) that it rendered the deterministic rendering of
  the **exact action the receipt committed to** — i.e. the rendering was a
  function of the signed bytes, not a re-described copy — and an offline
  verifier can re-derive that rendering and confirm the claim. It makes
  control 1 of I-D §11.3 **signed and verifiable** rather than merely
  implemented.
- **`EP-DISPLAY-ATTESTATION-v1` does NOT prove:** that the human actually
  *read* the rendering; that the device was honest; or, decisively, **that
  WYSIWYS holds**. A fully compromised signing client can render the true
  action to the screen-scraper while showing the human a false one, or
  attest a hash it never displayed. This residual is **out of scope** and
  is addressed only by **device / TEE attestation** (App Attest, Play
  Integrity, WebAuthn device binding) and operational controls (I-D §11.3
  controls 2–3: policy-committed templates, an independent second
  rendering surface for high value) — a layer **below/beside** this
  profile, never a property of it.
- **`EP-EXECUTION-INTEGRITY-v1` proves:** the canonical action recorded as
  executed hashes to the approved `action_hash` — no approve-A-run-B
  substitution in the *record*.
- **`EP-EXECUTION-INTEGRITY-v1` does NOT prove:** that the executing
  system actually performed that action against the real world. A
  compromised executor can record a faithful canonical action and do
  something else. That residual is out of scope and is addressed by
  executor/TEE attestation and independent confirmation of effects.
- Neither claim proves currency (I-D §6.3): offline verification
  establishes validity at attestation time, not that the signer/executor
  keys remain unrevoked now.

## Rationale

- **Why two additive claims, not a Core change.** Both properties are
  expressible by *referencing* the bytes the receipt already signed —
  re-deriving the rendering and the executed-action hash with the frozen
  `canonicalize()`/`actionHash()`. Touching `EP-RECEIPT-v1` to carry a
  display hash or an executed hash would break the frozen object and every
  deployed verifier for zero gain; the receipt would also become a place
  to record a *self-asserted* rendering, which is exactly what must not be
  trusted.
- **Why determinism is the whole mechanism.** WYSIWYS cannot be proven,
  but a rendering that is a **pure function of the signed action** can be
  *re-derived* by anyone offline. That converts "trust the client's
  description" into "recompute and compare", which is the strongest thing
  software can do here. Locale formatting is deliberately excluded from the
  attested bytes for the same reason — it is not reproducible.
- **Why hashes over status.** `binding_status` and any client-supplied
  "I rendered faithfully" string are advisory; trusting them would
  reintroduce the very presentation/substitution attack. The verifier
  trusts only re-derived hashes.
- **Why irreversible-by-default.** A producer flag that can downgrade its
  own obligations is a bypass surface. Reversibility must be asserted by
  the verifier, mirroring PIP-009's `execution.irreversible` rule.
- **Why fail closed, and why we still say WYSIWYS is unsolved.** A
  permissive check that surfaced a non-deterministic rendering or a
  drifting execution as "valid" would be an overclaim and a bypass. But
  even a perfectly fail-closed verifier here only rejects renderings that
  are *demonstrably* not the function of the signed action; it cannot see
  a lie that a compromised device tells consistently to both the human and
  the attestation. Saying so plainly is a conformance requirement of this
  profile, not a caveat.

## Backwards Compatibility

Purely additive; no migration required, and nothing frozen is touched.

- **PIP-001 Core freeze intact.** The frozen Core objects (Authorization
  Receipt / Trust Receipt, Trust Profile, Trust Decision;
  `PIPs/PIP-001-core-freeze.md`) are unmodified. Both new claims live
  outside the receipt; the receipt's wire format, JCS canonicalization,
  Ed25519 signature, and the frozen §6.3 verifier are unchanged.
- **Old verifiers, new claims.** A verifier that does not understand
  `EP-DISPLAY-ATTESTATION-v1` / `EP-EXECUTION-INTEGRITY-v1` ignores them
  and verifies the receipt exactly as today; no receipt is invalidated.
- **New verifiers, old receipts.** A profile-aware verifier presented with
  a lone receipt verifies it as today and reports the display/execution
  checks as absent (not failing) unless they are required by policy.
- **No new trust roots.** The profile imports the frozen
  `canonicalize()`/`actionHash()` and adds one local primitive (detached
  Ed25519 verification). A relying party that already verifies
  `EP-RECEIPT-v1` trusts nothing additional except the signer/executor keys
  it chooses to pin.

## Reference Implementation

The reference implementation is **experimental** and accompanies this
Draft; it is not production- or customer-deployed, and no metric or
adoption claim is made. It is new code that edits no shared middleware and
no frozen package.

- **WYSIWYS render + display-attestation (implemented).**
  **`lib/wysiwys/render.js`** exports:
  - `renderAction(action)` — the pure, deterministic rendering (Section 1).
  - `buildDisplayAttestation({ action, signer })` — emits an
    `EP-DISPLAY-ATTESTATION-v1` object (optionally signed).
  - `verifyDisplayAttestation(action, attestation, opts)` — the
    fail-closed check of Section 4, returning `{ valid, checks, errors,
    display_hash }`.
  - `DISPLAY_ATTESTATION_VERSION`, `RENDER_PROFILE`.

- **Execution-integrity binding (implemented).**
  **`lib/execution/integrity.js`** exports:
  - `executedActionHash(executedAction)` — frozen hash of the action that
    ran.
  - `bindExecution({ approvedActionHash, executedAction, irreversible,
    signer, … })` — the preferred assembler; signs via a delegated executor
    callback (EP never holds executor keys) and applies the honesty gate.
  - `buildExecutionIntegrity({ approvedActionHash, executedAction,
    executor, … })` — a compatibility assembler that signs with a raw
    `KeyObject`, implemented in terms of `bindExecution()` so the signed
    bytes and binding semantics are identical.
  - `verifyExecutionIntegrity(attestation, receipt, opts)` — the
    fail-closed check of Section 5, returning `{ valid, checks, errors,
    binding_status }`.
  - `EXECUTION_INTEGRITY_VERSION`.

  Both modules import the **frozen** `canonicalize()` and `actionHash()`
  from `packages/issue/index.js` as the single source of truth and add
  exactly one local primitive — detached Ed25519 verification of an
  attestation `proof` — which grants no trust on its own. **They import
  nothing from, and modify nothing in, `packages/verify` or
  `packages/issue`,** and re-implement nothing in the receipt's
  cryptographic path.

- **Conformance vectors + adversarial suites (implemented).** Two
  authoritative catalogues, one per surface, each with a paired live suite
  that mints the cryptographic material **live** (real Ed25519 keys +
  genuine signatures over canonical bytes — the negatives are real
  forgeries, not hand-edited JSON) and asserts each catalogue id by name:
  - **`conformance/vectors/wysiwys.v1.json`**
    (`EP-WYSIWYS-DISPLAY-ATTESTATION-VECTORS-v1`) +
    **`tests/wysiwys.test.js`**.
  - **`conformance/vectors/execution-integrity.v1.json`**
    (`EP-EXECUTION-INTEGRITY-VECTORS-v1`) +
    **`tests/execution-integrity.test.js`**.

  As run with `vitest`, every `must_reject` vector returns `valid: false`
  on its named failing check and every `must_accept` vector returns
  `valid: true` (**20/20 passing across both suites**):

  | Vector id | Surface | Expect | Failing check | Result |
  |-----------|---------|--------|---------------|--------|
  | `a_rendering_inconsistent_with_action_hash` | display | reject | `display_hash_match` | PASS |
  | `b_missing_display_attestation_high_stakes` | display | reject | `attestation_present` | PASS |
  | `c_forged_display_attestation_unrelated_bytes` | display | reject | `proof_signed` | PASS |
  | `c2_forged_display_attestation_wrong_key` | display | reject | `proof_signed` | PASS |
  | `d_attestation_binds_wrong_action_hash` | display | reject | `display_hash_match` | PASS |
  | `z_well_formed_high_stakes_signed` | display | accept | — | PASS |
  | `z2_well_formed_low_stakes_no_attestation` | display | accept | — | PASS |
  | `a_execution_drift` | execution | reject | `executed_hash_matches_approved` | PASS |
  | `b_claimed_hash_not_recomputed` | execution | reject | `executed_hash_self_consistent` | PASS |
  | `c_missing_attestation_irreversible` | execution | reject | `attestation_present` | PASS |
  | `d_forged_executor_signature` | execution | reject | `executor_signature_valid` | PASS |
  | `e_signature_over_other_bytes` | execution | reject | `signature_binds_attestation` | PASS |
  | `f_unpinned_executor_key` | execution | reject | `executor_key_pinned` | PASS |
  | `g_well_formed_match` | execution | accept | — | PASS |

No change to `packages/verify`, `packages/issue`, the MCP server, the
`require-receipt` demand hook, or any nav/middleware is required or
permitted by this PIP.

### Wiring for shared surfaces (advisory, not part of this PIP's scope)

These are *additive* call sites a deployment MAY wire; this PIP neither
requires nor modifies them:

- **Signing client** (`app/signoff/[signoffId]/signer.js`): after
  rendering the canonical action, call `buildDisplayAttestation()` and
  submit it alongside the WebAuthn assertion. The page already renders
  from the persisted canonical action (control 1).
- **Approval endpoint** (`app/api/v1/signoffs/[signoffId]/approve-webauthn/route.js`):
  call `verifyDisplayAttestation()` against the persisted canonical action
  and store the result/claim in `audit_events.after_state` (a new
  **optional** field — never inside the receipt).
- **MCP guard** (`packages/mcp-guard/index.js`): after the handler runs,
  call `bindExecution()` over the executed canonical action and
  `verifyExecutionIntegrity(att, receipt, opts)` against the approved hash;
  on drift, refuse (fail closed) and record the attestation in the existing
  `EP-PROVENANCE-ENTRY-v1` ledger entry. This is the in-process anchor
  from which an `EP-EXECUTION-INTEGRITY-v1` claim is assembled; it modifies
  no frozen object.

## Security Considerations

**(a) Fail closed on display.** A verifier MUST reject when the presented
rendering is not the deterministic function of the signed action (attested
`display_hash` or `action_hash` not equal to the re-derived values), when
a display attestation is required (high-stakes) but missing, and when a
signed attestation's proof does not verify under the pinned signer key or
is unsigned where a signature is required. There is no partial-credit
"valid" for a rendering that disagrees with the signed action.

**(b) Fail closed on execution.** A verifier MUST reject when the
re-derived canonical hash of the executed action does not equal the
approved `action_hash` (drift), when a missing attestation is not covered
by an independent verifier-side reversibility assertion, when the
`executed_action` does not re-hash to its self-declared
`executed_action_hash`, when the `executor_id` is not pinned or the
presented `executor_public_key` differs from the pinned key, and when the
executor `signature_b64u` does not verify under the pinned key over the
bytes the verifier independently recomputes from the presented fields. A
producer's `irreversible:false` flag MUST NOT relax these.

**(c) No new trust assumptions, restated.** A conforming verifier MUST NOT
trust any rendering, hash, or status presented in either claim without
re-deriving it from the signed action via the frozen
`canonicalize()`/`actionHash()`. The one local primitive
(detached-signature verification) grants no standalone trust; its result
is evidence gated by (a)/(b). Advisory fields (`binding_status`, any
free-text rendering note) MUST NOT influence the verdict.

**(d) Untrusted-content discipline carries over.** Where a rendering
includes any relying-party- or initiator-supplied string (e.g. a PIP-007
`initiator_attestation`), the signing surface MUST render it as untrusted
content (plain text, no markup/links/control chars, length-capped,
visually distinct, separated from the operator-rendered Action Object).
The display attestation attests to *what was shown*; it does not launder
hostile content into trusted content.

**(e) Honest residual — WYSIWYS is not solved, and a compromised device
can lie.** This is the central, prominent caveat of the profile. The
display attestation proves the signing client *claimed* (and, if signed,
signed) that it rendered the deterministic function of the signed action;
it does **not** prove the human saw that rendering or that the device was
honest. A fully compromised signing client/device can:
  - show the human a false rendering while attesting the true hash (or
    vice versa);
  - sign a `display_hash` for a rendering it never displayed;
  - record a faithful executed canonical action while acting differently
    against the real world.
None of these are detectable by re-derivation, because the compromised
endpoint controls both what it shows and what it signs. **This residual
is explicitly OUT OF SCOPE for this profile.** It is mitigable only by a
*different* layer — **device / TEE attestation** (Apple App Attest,
Android Play Integrity, hardware-backed WebAuthn device binding) that
raises assurance about the integrity of the signing/executing endpoint
itself — together with the I-D §11.3 operational controls (policy-bound
render templates; an independent second rendering surface for high-value
actions). EP makes such attestation *composable* at the enrollment and
execution boundaries; it is a layer above the protocol, not a property of
a receipt or of these claims. Treating a passing display or execution
attestation as proof that the device was trustworthy is a conformance
violation and an overclaim.

**(f) Privacy.** A display attestation's rendering and an
execution-integrity claim concentrate the action's parameters (amounts,
counterparties, targets) into portable artifacts. Producers SHOULD attest
only what a relying party needs, SHOULD prefer the hashes alone where the
verifier can re-derive the rendering from a separately held canonical
action, and MUST apply the same retention/disclosure controls as to the
most sensitive embedded action.

## References

- `standards/draft-schrock-ep-authorization-receipts-01.md` — Sections 3
  (Action Object), 6.2 (Trust Receipt), 6.3 (Offline Verification
  Algorithm), 11.3 (Presentation attacks; controls 1–3 — faithful
  rendering, policy-committed templates, independent second surface)
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- `lib/wysiwys/render.js` — `renderAction()`, `buildDisplayAttestation()`,
  `verifyDisplayAttestation()`, `DISPLAY_ATTESTATION_VERSION`,
  `RENDER_PROFILE`
- `lib/execution/integrity.js` — `executedActionHash()`,
  `buildExecutionIntegrity()`, `verifyExecutionIntegrity()`,
  `EXECUTION_INTEGRITY_VERSION`
- `packages/issue/index.js` — `canonicalize()`, `actionHash()` (frozen;
  imported as the single source of truth, not modified)
- `packages/verify/index.js` — `verifyTrustReceipt()` (frozen §6.3
  verifier; unchanged and untouched by this PIP)
- `conformance/vectors/wysiwys.v1.json` — display-attestation attack
  catalogue (`EP-WYSIWYS-DISPLAY-ATTESTATION-VECTORS-v1`)
- `conformance/vectors/execution-integrity.v1.json` — execution-integrity
  attack catalogue (`EP-EXECUTION-INTEGRITY-VECTORS-v1`)
- `tests/wysiwys.test.js`, `tests/execution-integrity.test.js` — live
  adversarial suites asserting each vector id by name (20/20 passing)
- `docs/RECEIPT-CLAIMS.md` — what a receipt proves and does not prove
  ("a signature proves user presence and approval toward *whatever was
  rendered*")
- `PIPs/PIP-001-core-freeze.md` — frozen Core objects and the extension
  mechanism
- `PIPs/PIP-007-initiator-attestation.md` — prior additive extension;
  advisory-report and untrusted-content discipline
- `PIPs/PIP-009-provenance-chain.md` — prior additive composite;
  fail-closed, no-new-trust pattern and the `execution.irreversible` rule;
  `EP-PROVENANCE-ENTRY-v1` ledger as the in-process anchor for execution
  integrity
