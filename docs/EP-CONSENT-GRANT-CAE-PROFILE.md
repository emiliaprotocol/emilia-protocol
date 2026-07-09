<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP profile of the Command Authority Envelope consent-grant and binding-moment slots

**Status:** individual profile, offered for reference from
`draft-morrison-ot-command-authority` (the Command Authority Envelope, CAE).
This document is the EP profile of the CAE's standing-consent (binding 3) and
binding-moment (binding 4) slots. It is referenced from the CAE, not copied into
it: EP stays the carrier, the CAE stays the slot definition.

**Grounded in running code.** Every claim below is the behavior of
`packages/verify/consent-grant.js` and the receipt verifier it composes with.
Schema: `public/schemas/ep-consent-grant.schema.json`. Spec:
`docs/EP-CONSENT-GRANT-SPEC.md`.

## The two objects, kept apart

The CAE separates a scoped, revocable **standing consent grant** (binding 3,
naming the asset and the exact control verb) from the **per-action human
authorization at the binding moment** (binding 4). EP fills these with two
distinct objects, and the receipt never rounds up into the grant:

| CAE slot | EP object | What it asserts |
|---|---|---|
| Binding 3, standing consent | `EP-CONSENT-GRANT-v1` | A named principal consents to `{asset, control_verb}` until `expires_at`, revocable by `grant_hash`. |
| Binding 4, binding moment | EP receipt, carried per `draft-schrock-human-authorization-binding` | A named human's device-bound signature over the exact action, before execution; signed denial is the other veto outcome; the initiator is barred from approving their own request. |

The receipt **acts under** the grant by carrying `grant_hash`. It does not
contain the grant and does not restate the standing scope. `verifyReceiptUnderGrant`
refuses `grant_binding_mismatch` when that reference is absent or does not
match, so binding 3 and binding 4 cannot collapse into one object.

## Binding 3: EP-CONSENT-GRANT-v1

**Object.** A signed grant with the required fields
`{profile, grant_id, principal, asset, control_verb, issued_at, expires_at,
grant_hash, signature}` and an optional `constraints`. It is content-addressed:
`grant_hash` is over the canonical grant body, and the principal signs that body
with the same Ed25519 convention EP uses everywhere.

**Verification** (`verifyConsentGrant(grant, pinnedPrincipalKey, opts)`), all
fail-closed with a distinct reason:

- `hash` — `grant_hash` recomputes over the canonical body.
- `signature` — verifies against the **relying-party-pinned** principal key. A
  self-asserted key confers nothing.
- `within_window` — `issued_at <= now < expires_at`; a not-yet-valid or expired
  grant refuses.

**Revocation is not folded into the grant.** A grant is revoked by an EP
revocation statement against its `grant_hash`, verified under the revoker's own
pinned key. `verifyConsentGrant` returns `grant_revoked` only when such a
statement is presented and verifies.

## Binding 4: the receipt at the binding moment

The receipt is the second object. It is the device-bound human signature over
the exact action, evaluated by the base EP verifier, and it references the grant
by `grant_hash`. Composition is `verifyReceiptUnderGrant(receipt, grant, opts)`.

**The seven distinct fail-closed refusals** (the conformance points for the CAE
rows):

1. `grant_signature_invalid` — the grant does not verify under the pinned key.
2. `grant_not_yet_valid` — the grant's window has not opened.
3. `grant_expired` — the grant's window has closed.
4. `grant_revoked` — a verified revocation binds this `grant_hash`.
5. `asset_mismatch` — the receipt's asset is not covered by the grant.
6. `verb_mismatch` — the receipt's control verb is not covered by the grant.
7. `grant_binding_mismatch` — the receipt does not reference this grant.

**Binding strength is surfaced, not hidden.** The result carries
`binding_strength`: `signed_action` (the grant reference is inside the signed
action object, the strong binding), `top_level`, `caller_override` (advisory,
caller-supplied), or `none`. A relying party can distinguish a strong binding
from an advisory one and price it. This is a top-level result field, not a pass
or fail check.

## The offline case is two-valued (locked wording)

This is the one place a reader could hear "offline" as "not revoked," and it
must not. The two values:

1. **Authenticity as of commit.** Offline verification of the grant proves the
   principal signed `{asset, control_verb, expires_at}` and that the receipt is
   bound to it. It does **not** prove the grant is still live, and the **absence
   of a revocation statement is never treated as not-revoked.**
2. **Currency at time T.** The executor verifies a pushed, signed revocation
   snapshot offline against a pinned revoker key. An unseen grant is treated as
   **not-known-current** under a freshness bound. A snapshot carrying a
   revocation against this `grant_hash` refuses `grant_revoked`.

The CAE slot and the EP verifier describe the same two-valued check with these
words, so a State-change can be blocked at an air-gapped executor by a revoked
grant.

## Fail-closed on authority, never on safety

EP refuses when there is no valid grant-and-receipt bundle, with one of the
seven reasons above, and nothing else. The **safety interlock lives in the CAE
layer above EP and is never gated by an authority check.** EP is the authority
gate. It must never be wired as the safety gate, and no conforming
implementation drives an executor into an unsafe state because an authority
artifact was missing.

## Grant, policy_hash, and the admissibility profile stay one object each

- The **grant** says what was consented: `{asset, control_verb, expires_at}`,
  addressed by `grant_hash`.
- The **admissibility profile** (and its `policy_hash`) is the relying party's
  own acceptance policy, pinned by that party. It says what evidence the party
  requires before it will rely.

They meet only at the receipt, which references exactly one `grant_hash` and is
evaluated under the relying party's pinned profile. Neither is embedded in the
other, so a grant and an acceptance profile cannot drift apart.

## Placement in the agentproto verifier matrix

The standing grant is its own claim class in the agentproto verifier matrix,
distinct from the per-action class (Songbo's C-002) and the delegated-scope
class (C-003). A conforming row records the grant object, its `grant_hash`, the
seven refusals as the pass/fail behavior, and the `binding_strength` reported
for the receipt that acts under it.

## References

- `draft-schrock-human-authorization-binding` — the binding-moment carrier.
- `packages/verify/consent-grant.js`, `docs/EP-CONSENT-GRANT-SPEC.md`,
  `public/schemas/ep-consent-grant.schema.json` — the running implementation.
- `draft-morrison-ot-command-authority` — the Command Authority Envelope this
  profile fills bindings 3 and 4 of.
