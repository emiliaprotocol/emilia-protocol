# AAE x PSEA x EMILIA Gate attempt pair

This directory carries EMILIA's side of the seven-field AAE/PSEA cross-run. It
closes the admission-custody case that cannot be represented as one row: the
same single-use authority can remain `AUTHORIZED` on a second presentation
while Gate withholds admission as `NONE / already_consumed`.

The committed vector pins the current AAE proof-exchange fixture at
`MoltyCel/aae-conformance-vectors` PR 6, commit
`e8c00e5014c52a4cb4ff51d24c360db5c82d599e`. That upstream fixture still marks
the WHO axis `PROPOSED`; this directory does not promote it to confirmed and
does not claim PSEA conformance. The vector also carries the exact upstream JWS
and action-payload SHA-256 commitments published by that fixture's manifest.

## Attempt pair

1. The first attempt is natively accepted, linked, evidence-satisfied and
   authorized. Gate consumes admission. Its provider effect remains
   `INDETERMINATE / provider_outcome_unresolved`.
2. The second attempt presents the same authority, action, evidence and
   decision. Gate records a separate attempt with admission
   `NONE / already_consumed` and outcome `NONE`.

The verifier enforces four cross-run constraints:

- every non-`NONE` outcome must have a same-or-prior admission in
  `CONSUMED`, `DISPATCH_PENDING` or `INVOKED`;
- every `INDETERMINATE` outcome must carry a reason;
- an already-consumed replay preserves the authorization decision but receives
  no second admission; and
- the two records preserve their native result, linkage, evidence, decision,
  reservation and top-level authority/action/evidence commitments.

## Verify

```sh
node --test interop/aae-psea-gate/verify.test.mjs
node interop/aae-psea-gate/reperform.mjs
```

`reperform.mjs` is the independent return package. It fetches every source
artifact from the immutable upstream commit, verifies the exact byte pins,
authenticates the Ed25519 AAE JWS under the fixture's pinned trust decision,
re-performs the applicable AAE Section 5 checks through step 7, checks that the
action payload is exact RFC 8785 output, compares the recomputed 32 octets to
the authenticated `action_binding`, and only then joins the result to the Gate
attempt pair. Its JSON output is checked in as
`independent-return.v1.json`.

The vector deliberately does **not** establish named-human WHO confirmation,
PSEA conformance, execution order or a provider effect. Those remain external
facts requiring their own evidence.
