# EP-SD-v1 selective-disclosure conformance vectors

Deterministic vectors for the selective-disclosure presentation profile
implemented in `packages/verify/src/receipt-selective-disclosure.ts` and
described in `standards/staged/NEXT-PRESENTATION-BINDING-01/SELECTIVE-DISCLOSURE.md`
(staged working text, not filed).

## What the profile proves

A holder presents a disclosure-ready EP receipt to an auditor, insurer, or
regulator proving that an authorized approval bound one exact action: the
CAID is intact, the issuer signature verifies over the exact signed bytes,
and the evidence-grade fields are visible. The business content of
undisclosed fields is replaced, inside the signed payload, by salted
path-bound commitments (`ep-sd-commit:sha256:<hex>`); disclosed fields are
opened with their `{path, salt, value}` openings, which the verifier
recomputes against the signed commitments.

Real constraint, stated plainly: an EP-RECEIPT-v1 signature covers the full
canonical payload bytes, so selective disclosure requires DISCLOSURE-READY
ISSUANCE (commitments inside the signed body, openings delivered to the
holder out of band). Already-issued plaintext receipts verify and present in
full but cannot be retrofitted into redacted presentations; the verifier
refuses them with `missing_disclosure_block`.

## Determinism

Every byte in `vectors.json` regenerates identically:

- The issuer and holder Ed25519 keys are PUBLIC TEST FIXTURES: the PKCS8 key
  is the standard Ed25519 PKCS8 prefix plus the 32-byte seed
  `SHA-256(seed_string)`, with the exact `seed_string` recorded per key in
  the file. They are not secrets and must never be used outside conformance.
- Per-field salts are `base64url(SHA-256("EP-SD-v1 vector salt: <path>")[0..16))`.
- All timestamps are fixed constants recorded in the vectors.
- Canonical bytes are the EP strict canonicalization profile (RFC 8785 JCS
  over the EP I-JSON subset), the same single source of truth as every other
  signed artifact in `packages/verify`.

The vitest suite `packages/verify/receipt-selective-disclosure.test.ts`
re-derives the disclosure-ready receipt, all three presentations, and the
binding digests from those seeds and asserts byte-identity with this file.

## Contents

- `keys` - deterministic test keys (issuer signs the receipt, holder signs
  presentation bindings where a holder proof is exercised).
- `source_payload` - the plaintext payload before issuance preparation.
- `disclosable_paths`, `salts` - the designated fields and their pinned salts.
- `disclosure_ready_receipt` - the signed receipt with commitments in place
  of the designated business fields plus the signed `disclosure` block.
- `openings` - the full opening set the issuer hands the holder.
- `presentations` - three accepted presentations with their verifier
  expectations and pinned binding digests:
  - full disclosure to an auditor, with a holder proof;
  - amount and currency only, to an insurer;
  - zero disclosure to a regulator (the receipt still proves the exact
    action via the intact CAID and evidence fields).
- `hostile` - presentations that MUST refuse, with the exact named refusal:
  forged opening (right salt, wrong value), opening swapped across fields,
  a misissued receipt that committed the non-redactable CAID, audience
  replay, nonce replay, opening without a salt, salt below 128 bits, salt
  reuse across fields, tampered signed payload, and a verifier-required
  field left undisclosed.
- `prepare_refusals` - issuance-preparation refusals for designating
  non-redactable paths (`caid`, `evidence_grade`, `signoffs`).

## Running

```
cd packages/verify && npx vitest run receipt-selective-disclosure.test.ts
```

(The repo-root vitest config deliberately excludes `packages/**`, which run
their own node:test suites; run this suite from inside `packages/verify`.)

## Scope honesty

Everything these vectors check is cryptographic VERIFICATION. Whether the
issuer key is trusted, whether the receipt is current or revoked, and
whether a disclosure subset suffices for a reliance purpose are ACCEPTANCE
decisions outside this suite. The verifier learns the receipt's structure
(which fields exist and which were withheld); presentations of the same
receipt are linkable to each other. Those residuals are stated, not solved,
by this profile.
