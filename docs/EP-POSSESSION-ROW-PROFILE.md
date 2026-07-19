<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP profile of the possession row: joining condition-bounded credentials to authorization receipts

**Status:** individual profile, offered as the EP side of the two-row model
discussed on the WIMSE list (condition-bounded credentials / live-key
possession, the "LIT" framing) in composition with EP authorization receipts.
The possession row keeps its own verifier and trust boundary; EP keeps its own.
This document is the seam between them.

**Grounded in running code.** Every claim below is the behavior of
`packages/verify/surface-binding.js`, exercised by
`conformance/vectors/surface-binding.v1.json` (11 vectors, 3 accept, 8 refuse)
and `packages/verify/surface-binding.test.js`.

## The two rows, kept apart

| Row | Object | What it proves | Whose verifier |
|---|---|---|---|
| Possession | Condition-bounded credential presentation, live-key handshake, platform attestation | The key is live, in one place, under its conditions: the platform (and any human verified into it) is present NOW | The possession row's own verifier, under keys and conditions EP knows nothing about |
| Authorization | EP receipt (`draft-schrock-ep-authorization-receipts`) | A named human's device-bound signature covered this exact action, before it ran | The EP verifier, against keys the relying party pinned out of band |

Presence is an input to the approval ceremony, never the ceremony. The rows
join; they never merge.

## The join: EP-SURFACE-BINDING-v1

The signed Action Object may carry one reserved member, `approval_surface`:

```json
{
  "@version": "EP-SURFACE-BINDING-v1",
  "surface_kind": "wimse-condition-bounded",
  "attestation_digest": "sha256:<hex of the possession-row evidence bytes>",
  "verifier_hint": "<optional: where the relying party verifies that row>"
}
```

`bindSurfaceInto(action, binding)` places the validated, normalized binding
into the action object BEFORE hashing and signing, so the human's signature
covers which surface evidence was claimed. The frozen action hash is unchanged:
the binding is an ordinary signed member. A binding is honored only when it is
an OWN member of the signed action object: one placed at the receipt top level,
or reachable only through the prototype chain, is not covered by the signature
and never upgrades to a signed claim (`reject_binding_outside_signed_action_object`
in the vectors, and the prototype-inherited case in `surface-binding.test.js`).

`verifySurfaceBinding(receipt, evidence, { require })` is the seam check, and
only the seam check:

- `present`: the receipt carries a valid binding as an own member of the signed
  action object.
- `digest_match`: the presented possession-row evidence BYTES hash byte-exactly
  to the bound digest. Evidence is always hashed; a precomputed digest is never
  accepted, because the bound digest is public (it sits in the receipt) and
  echoing it would prove nothing.

Distinct fail-closed refusals: `surface_binding_absent`,
`surface_binding_malformed`, `surface_digest_mismatch`. A relying party whose
pinned profile does not require the possession row passes `require: false` and
proceeds on the receipt alone; that choice is the relying party's, recorded in
its own admissibility profile, never a default EP asserts.

## What the join proves, and what it never proves

Once inside the signed action object, the binding proves the human's signature
covered WHICH surface evidence was claimed for the ceremony. A later party
cannot silently swap the claimed surface, and the relying party can join the
two rows by digest equality.

It does NOT prove:

- that the referenced possession-row evidence is valid, current, or honest.
  That is the possession row's verifier's job, in its own trust boundary.
- what reached the human's eyes. An attested surface is evidence about the
  display environment. The trusted-display composition narrows the rendering
  gap; no cryptography closes it, and this profile does not claim otherwise.

## The substitution guard

A live key, a present human, an attested endpoint: none of these are an
approval. The conformance suite pins the refusal from both directions:

- `possession_substituted_for_authorization`
  (`vectors/surface-binding.v1.json`): possession evidence presented with no
  authorization row to join to refuses at the seam.
- `attribution_substituted_for_authorization` (`vectors/boundary.v1.json`):
  attribution evidence presented as authorization refuses at the boundary
  layer.

An agent and a human on one platform under one live key is exactly the case
this guard exists for: the possession row proves both are present; only the
human's per-action signature makes an action approved.

## Row-scoped signalling (CAEP)

The two rows carry their own events. "Possession no longer proven" revokes
nothing on the authorization row; "authorization withdrawn" says nothing about
key liveness. A combined deployed token stays deployable as long as each event
names the row it revokes, which is the recommendation already on the WIMSE
thread: event semantics first, token structure second.

## References

- `packages/verify/surface-binding.js`: the join, running code.
- `conformance/vectors/surface-binding.v1.json`: 11 vectors, 3 accept, 8 refuse.
- `packages/verify/initiator-attestation.js`: the sibling knob this pattern
  mirrors (WHICH software asked).
- `docs/EP-CONSENT-GRANT-CAE-PROFILE.md`: the same carrier/slot discipline
  applied to the Command Authority Envelope.
- `draft-schrock-ep-authorization-receipts`: the authorization row.
