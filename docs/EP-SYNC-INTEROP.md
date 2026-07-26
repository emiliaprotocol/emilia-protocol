<!-- SPDX-License-Identifier: Apache-2.0 -->
# SYNC × EMILIA interoperability profile (working note)

This note records the boundary for the exported `SYNCAuthorizationReceipt` supplied
as `SYNC-6A27C41D696E`. It is a runnable interop fixture, not a claim that EMILIA
implements or endorses the SYNC wire profile.

## What the artifact is

The attachment is a SYNC **authorization-origin presentation**. It carries a
public receipt identifier, a receipt hash, a chain position, an ES256 public key
and signature, and policy-context labels. It does not carry a neighboring chain
record, a trusted chain checkpoint, or the canonical signing preimage/profile.
The production profile was supplied separately for this interop fixture. The
signed payload's `createdAt` is transient in the export; the verifier
reconstructs candidates in the documented window around the adjacent
authorization timestamp and requires exactly one digest match.

The distinction matters:

* SYNC presentation evidence is not an EMILIA authorization receipt.
* A SYNC chain field is not proof of continuity without the referenced record or
  a trusted checkpoint.
* A policy label is not a legal determination and is not an AEB admission.
* An authorization-origin receipt is not evidence that a physical effect
  completed.

## Current result

Run:

```sh
node examples/scitt/sync-emilia-fixture.mjs
```

The harness checks the exported identifiers, type, purpose, hash/encoding
shapes, and effect boundary. The production signing profile supplied by SYNC
is now reproduced from the byte-level payload: sorted-key Swift JSONEncoder
output, UTF-8, and DER ES256 over SHA-256. The transient `createdAt` is
resolved from the authorization timestamp window; zero or multiple matching
candidates fail closed. The positive vector and the content-mutation and
changed-key refusal vectors are in
`examples/scitt/fixtures/sync-emilia-vectors.v1.json` and are exercised by
`sync-emilia-fixture.test.mjs`.

Chain continuity remains `INDETERMINATE` because this export still does not
include the neighboring record or a trusted checkpoint. This is the
fail-closed result for a consequential action:
`REFUSE_CONSEQUENTIAL_EFFECT`.

The external OpenVerifier result is retained as an external verification claim;
it is not silently converted into an independently reproduced EMILIA result.

## Composition boundary

An adapter can compose the systems without absorbing either one:

1. Preserve the SYNC receipt as an opaque upstream presentation and verify it with
   the SYNC verifier/profile.
2. Project the exact permitted transition into an EMILIA CAID. The projection
   must name the object, lineage, transition, material parameters, expiry, and
   verifier/trust-root pin.
3. Let AEC link the upstream presentation and any downstream evidence, and let
   AEB make the relying-party admission decision.
4. Record the decision and outcome separately. A SCITT transparency statement
   may log either signed artifact, but inclusion is not authorization and is not
   proof of physical completion.

The adapter has four conformance vectors: a structurally valid presentation,
content mutation, changed/forged key, and missing or ambiguous chain context.
The first three are evaluated by the native production profile without treating
OpenVerifier as a trusted component. The last vector is intentionally
`INDETERMINATE`.
