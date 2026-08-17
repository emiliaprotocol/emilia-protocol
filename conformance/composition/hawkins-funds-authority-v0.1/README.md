# Hawkins Check 8 funds-authority profile (v0.1)

A runnable composition vector that instantiates the funds-authority clause of
Check 8 in draft-hawkins-scitt-attested-agent-payment-01 with an EMILIA
authorization receipt.

## What Check 8 leaves open

Section 4, Check 8 of the pinned draft requires a Payment Executor to
establish, "by a rail- or deployment-defined procedure, that the scope's
Issuer may authorize spending from the account the payment draws on". The
draft deliberately does not define that procedure, and states that its
absence is failure of the check, not a permission.

## What this profile proposes

The rail-defined procedure is an offline EMILIA receipt check:

1. The human principal of the account signs an EP-RECEIPT-v1 whose exact
   action material names the scope issuance: the Issuer identity, the
   account, and the scope digest of the Authorization Scope.
2. The executor holds, pinned out of band per account: the principal's
   Ed25519 key, the expected scope Issuer identity, and the principal's
   revoker keys.
3. Before treating the funds-authority clause of Check 8 as established, the
   executor verifies the receipt offline (`packages/verify` `verifyReceipt`),
   recomputes the action CAID, checks account, Issuer, and scope digest,
   checks expiry at its own decision time, and checks presented
   EP-REVOCATION-v1 statements under the pinned revoker keys.

The Authorization Scope is modeled faithfully to the Section 3 CDDL: a CBOR
map in the deterministic encoding of RFC 8949 Section 4.2.1 (produced by the
repo's real encoder, `encodeDeterministicCbor8949`), with the scope digest
computed over exactly those bytes, an RFC 9679 SHA-256 COSE Key Thumbprint as
`apk`, integer amounts with a declared scale, and `executor` present because
`limits` carries an aggregate bound.

Composition rule: the two legs stay in their own trust boundaries and join by
the scope digest. The EP verifier never parses the scope; the scope encoding
never embeds the receipt.

## Cases

| id | outcome |
| --- | --- |
| funds-authority-established | Check 8 funds-authority clause established |
| different-scope-digest-refused | `funds_authority_scope_mismatch` |
| no-receipt-fails-closed | `funds_authority_unavailable` (fail-closed, never a pass) |
| expired-receipt-refused | `funds_authority_receipt_expired` |
| revoked-receipt-refused | `funds_authority_receipt_revoked` |
| unpinned-signer-refused | `funds_authority_signer_not_pinned` |

## Run

```
node conformance/composition/hawkins-funds-authority-v0.1/run.mjs
node --test conformance/composition/hawkins-funds-authority-v0.1/run.test.mjs
```

Fixtures are deterministic (fixed Ed25519 seeds, fixed timestamps); every
conforming run reproduces the committed `report.reference.json` byte for byte
and the same `report_digest`.

## Claim boundary

- This is EMILIA's proposed instantiation of a slot the Hawkins draft leaves
  rail- or deployment-defined. The draft does not reference EMILIA. No
  endorsement, adoption, or agreement by its author is claimed or implied.
- Only the funds-authority clause of Check 8 is instantiated here. Receipt
  availability from the Transparency Service (the other clause of Check 8)
  and Checks 1 through 7 and 9 of Section 4 are out of scope.
- The fixture keys are public deterministic seeds and must never be trusted
  outside this vector.
- The draft text is pinned by SHA-256 in `source-lock.json`; the claims above
  are made against exactly those bytes.
