# AAE x PSEA x EMILIA Gate attempt pair

This directory carries EMILIA's side of the seven-field AAE/PSEA cross-run. It
closes the admission-custody case that cannot be represented as one row: the
same single-use authority can remain `AUTHORIZED` on a second presentation
while Gate withholds admission as `NONE / already_consumed`.

The committed vector pins the current AAE proof-exchange fixture at
`MoltyCel/aae-conformance-vectors` PR 6, commit
`e8c00e5014c52a4cb4ff51d24c360db5c82d599e`. That upstream fixture still marks
the WHO axis `PROPOSED`, so `independent-return.v1.json` remains the historical
return for those exact bytes. `confirmed-live-state.v1.json` separately pins the
confirmed vector at `27227b5c4944f57a033fb45851f9aae0659b9590` without
rewriting that provenance. It verifies that the six frozen fixture files are
byte-identical and that the live vector differs only in its two WHO status
fields. Confirmation establishes WHO linkage under the supplied mapping. It
does not establish PSEA conformance or derive the kid-to-principal mapping.

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
node interop/aae-psea-gate/reperform.mjs --confirmed-live-state
```

`reperform.mjs` is the independent return package. It fetches every source
artifact from the immutable upstream commit, verifies the exact byte pins,
authenticates the Ed25519 AAE JWS under the fixture's pinned trust decision,
re-performs the applicable AAE Section 5 checks through step 7, checks that the
action payload is exact RFC 8785 output, compares the recomputed 32 octets to
the authenticated `action_binding`, and only then joins the result to the Gate
attempt pair. Its JSON output is checked in as
`independent-return.v1.json`.

The `--confirmed-live-state` run fetches both immutable heads, re-performs the
historical return, verifies the six fixture files at the new head against their
original byte pins, and refuses any live-vector change beyond `status` and
`input.join_who.status`. Its JSON output is checked in as
`confirmed-live-state.v1.json`.

The historical return deliberately does **not** establish named-human WHO
confirmation. The separate live-state artifact records the later supplied WHO
mapping confirmation, while continuing to make no claim of PSEA conformance,
execution order or a provider effect.
