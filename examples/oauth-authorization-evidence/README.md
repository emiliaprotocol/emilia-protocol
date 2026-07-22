# OAuth Authorization Evidence + EP Receipt

This runnable lab composes
[`draft-liu-oauth-authorization-evidence-01`](https://datatracker.ietf.org/doc/draft-liu-oauth-authorization-evidence/)
with an EP authorization receipt without changing either artifact's trust
boundary.

```bash
node examples/oauth-authorization-evidence/demo.mjs
```

## What joins

The OAuth Authorization Server emits the draft's enriched
`authorization_evidence` authorization detail. Its detached JWS covers exactly
`id` and `user_confirmation`, as required by Section 3.6. The outer signed JWT
access token protects the complete authorization detail, including
`audit_trail.evidence_ref`.

`evidence_ref` is not an EMILIA-added JSON member. Section 4.2 of the OAuth
draft already defines it as an OPTIONAL reference to a related evidence record.
This lab supplies one concrete application profile for that existing field: a
content-addressed EP authorization receipt. No change to the OAuth evidence
schema or its AS-signature input is required.

This example uses `evidence_ref` as a content address for an EP receipt. The
Resource Server performs three independent checks:

1. Verify the access token and the detached AS evidence signature with the
   pinned AS key.
2. Resolve `evidence_ref`, recompute its digest, and refuse any substitution.
3. Verify the EP receipt with the organization's approver directory and receipt
   log trust roots, then compare its signed Action Object with the action about
   to execute.

The draft's evidence proves what the AS recorded during its consent ceremony.
The optional EP leg supplies the user-side signature or independent-consent
artifact contemplated by Section 8.2 for deployments that require stronger
non-repudiation. Neither is presented as replacing the other.

## How the approver key reaches the verifier

The receipt does not get to name a key and thereby make that key trusted. The
demo models the Approver Directory from Section 5.2 of the EP receipt draft:

- the approver's key is enrolled under an `approver_id`, key class, validity
  window, and roles;
- an organization-controlled directory root signs the snapshot;
- the Resource Server pins that directory root separately from both the OAuth
  AS key and the EP receipt-log key;
- only after verifying the directory snapshot does the Resource Server pass its
  entries to `verifyTrustReceipt()` as `approverKeys`.

The snapshot format in this lab is illustrative deployment glue, not a new
protocol wire format. A deployment can carry equivalent authenticated directory
material through its federation agreement, a directory inclusion proof, or a
locally pinned extract. The invariant is the same: the relying party chooses the
directory authority out of band; a presenter-controlled key cannot establish
its own authority.

## Attacks exercised

The lab executes one valid flow and refuses:

- exact-action substitution;
- mutation of `evidence_ref` inside the access token;
- an invalid detached AS evidence signature;
- stale user-confirmation evidence, even inside a fresh token;
- EP receipt bytes that do not match the content address;
- a validly signed EP receipt under an approver key absent from the pinned
  directory; and
- substitution of an approver key inside a previously signed directory
  snapshot.

## Honest limits

- The AS evidence proves an AS assertion about its interaction; it does not by
  itself prove that the user consented.
- An EP receipt proves that a pinned approver key signed the exact Action Object;
  identity assurance depends on directory enrollment and key custody.
- This Class-B example does not claim WebAuthn user verification or proof of
  human perception. A production profile can replace the signer with a Class-A
  device-bound ceremony without changing the OAuth join.
- Currency, revocation status, and one-time execution require the relying
  party's deployment policy; offline authenticity alone cannot prove current
  status. This lab enforces a five-minute confirmation-age bound, but that is
  an illustrative local policy, not a requirement imposed on the OAuth draft.
