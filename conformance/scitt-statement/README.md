<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-SCITT-STATEMENT-v1

A SCITT Signed Statement profile for EMILIA authorization receipts, plus a
deterministic vector suite for it.

Implementation: `packages/verify/src/scitt-statement.ts`
Vectors: `vectors.json` in this directory
Generator: `examples/scitt-registration/generate-vectors.mjs`
Suite: `packages/verify/scitt-statement.test.ts`

## Claim boundary, first

This is OUR profile of the Signed Statement shape defined in RFC 9943 Section 6.
It is not a standard, not adopted, and not endorsed by anyone.

**No Transparency Service has accepted any statement produced by this profile.**
Registration is a separate, staged, human-gated step
(`examples/scitt-registration/`). Nothing here has been submitted anywhere.

Three states are kept strictly apart, and this profile only ever reaches the
first:

| State | Meaning | Where it is established |
| --- | --- | --- |
| VERIFIED | The signatures check out under the relying party's pinned keys. | `verifyEpScittSignedStatement`, offline. |
| REGISTERED | A Transparency Service accepted the statement into its verifiable data structure and returned a Receipt (RFC 9943 Section 6.3). | Nowhere yet. |
| ACCEPTED | The statement is trusted under a pinned root and an admissibility policy. | Not in scope for this profile at all. |

`verifyEpScittSignedStatement` returns `registered: false` on every result,
success and failure alike, so a caller cannot read a verification result as a
registration result.

## What the profile is

A Signed Statement is a COSE_Sign1 (RFC 9052) whose payload is the receipt's
canonical JSON bytes, attached rather than detached, and whose protected header
carries the mandatory SCITT header parameters.

Protected header, in CBOR extended diagnostic notation:

```
{                                    / Protected                 /
  1: -8,                             / alg = EdDSA               /
  3: "application/emilia-receipt+json",  / content type of the payload /
  4: h'...',                         / kid                       /
  15: {                              / CWT Claims (RFC 9597)     /
    1: "ep:issuer:<name>",           / iss                       /
    2: "caid:1:<action_type>:jcs-sha256:<digest>"  / sub         /
  }
}
```

Unprotected header: the empty map. Payload: the receipt's canonical JSON.

## Requirement table

Every quotation below is from the RFC text at the pinned digest in
"Specifications pinned", read directly rather than from a summary.

| Requirement | Source | Where satisfied |
| --- | --- | --- |
| "Signed Statements produced by Issuers must be COSE_Sign1 messages, as defined by [STD96]." | RFC 9943 Section 6 | `buildEpScittSignedStatement` emits CBOR tag 18 over a 4-element array; `verifyEpScittSignedStatement` refuses anything else with `cose_structure_invalid`. |
| "The protected header of a Signed Statement and a Receipt MUST include the CWT Claims header parameter as specified in Section 2 of [RFC9597]." | RFC 9943 Section 6 | Protected label 15 is always emitted. Absent on input: refusal `cwt_claims_missing`. Vector `missing-cwt-claims`. |
| "The CWT Claims value MUST include the Issuer Claim (Claim label 1) and the Subject Claim (Claim label 2)." | RFC 9943 Section 6 | Both always emitted. Absent on input: refusals `iss_missing` / `sub_missing`. |
| "The kid header parameter MUST be present when neither x5t nor x5chain is present in the protected header." | RFC 9943 Section 6 | This profile carries neither x5t nor x5chain, so `kid` (label 4, bstr) is mandatory. Absent: refusal `kid_missing`. |
| "The iss Claim value's length MUST be between 1 and 8192 characters in length." | RFC 9943 Section 6 (scoped there to x5t/x5chain statements) | Applied unconditionally by `isAcceptableIss`, which also requires a URI scheme. Build refusal `invalid_iss`, verify refusal `iss_malformed`. |
| Normative CDDL: `Protected_Header` requires `&(CWT_Claims: 15)`, with `alg`, `content_type`, `kid` optional; `CWT_Claims` requires `iss` and `sub` as `tstr`. | RFC 9943 Section 6.1 Figure 3 | The emitted header is a superset of the mandatory set and a subset of the permitted set. `iss` and `sub` are text strings; non-text refuses. |
| CWT Claims header parameter: name "CWT Claims", label 15, value type map. | RFC 9597 Section 2, Table 1 | `COSE_HEADER_CWT_CLAIMS = 15`; the value is encoded as a CBOR map. A non-map refuses with `cwt_claims_malformed`. |
| "It is RECOMMENDED that the CWT Claims header parameter only be used in a protected header to avoid the contents being malleable." | RFC 9597 Section 2 | Label 15 is only ever in the protected header. The unprotected bucket must be empty; any content refuses with `unprotected_headers_present`. |
| "The header parameter MUST only occur once in either the protected or unprotected header of a COSE structure." | RFC 9597 Section 2 | Guaranteed by construction: the unprotected bucket is empty, and the deterministic CBOR decoder refuses duplicate map keys (`duplicate_map_key`). |
| "In cases where CWT claims are present both in the payload and the header of a CWT, an application receiving such a structure MUST verify that their values are identical, unless the application defines other specific processing rules for these claims." | RFC 9597 Section 2 | This profile takes the escape clause and defines the rule explicitly. See "CWT claims and the payload" below. |
| Sig_structure for COSE_Sign1 is `["Signature1", body_protected, external_aad, payload]`. | RFC 9052 Section 4.4 | Both build and verify construct exactly this, with an empty `external_aad`. |
| A label appearing in both the protected and unprotected buckets is an error. | RFC 9052 Section 3 | Foreclosed by construction: the unprotected bucket must be empty. |
| `crit`: every listed label must be understood by the recipient. | RFC 9052 Section 5.4 | This profile marks nothing critical, so any `crit` names a label it does not understand: refusal `crit_unsupported`. |
| "Relying Parties MUST apply the verification process as described in Section 4.4 of RFC 9052 [STD96] when checking the signature of Signed Statements". | RFC 9943 Section 7.1 | `verifyEpScittSignedStatement` verifies over the Sig_structure, after checking the signed `alg`. |
| "the unprotected header of a Signed Statement MUST be set to an empty map before the Signed Statement can be included in a Statement Sequence." | RFC 9943 Section 6.3 | Emitted empty; required empty on input. |
| Deterministic encoding: shortest-form arguments, no indefinite lengths, map keys in bytewise order of their encodings. | RFC 8949 Section 4.2.1 | Delegated to `encodeDeterministicCbor8949` / `decodeDeterministicCbor8949` in `packages/verify/src/receipt-cose-encoding.ts`. Non-deterministic input refuses with `non_deterministic_encoding`. |

Not implemented, and not claimed: Receipts (RFC 9943 Section 7, unprotected
label 394, RFC 9942 verifiable data structure algorithms), Transparent
Statements, hash-payload statements (Section 6.2), and x5t / x5chain
statements. A statement carrying a Receipt is a Transparent Statement, a
different artifact; this verifier refuses it rather than silently treating it as
a Signed Statement.

## Why `sub` is the action CAID

RFC 9943 Section 3 defines Subject as

> an identifier, defined by the Issuer, that represents the organization,
> device, user, entity, or Artifact about which Statements (and Receipts) are
> made and by which a logical collection of Statements can be grouped

and adds that Relying Parties "can leverage sub to ensure completeness and
Non-equivocation across Statements by identifying all Transparent Statements
associated with a specific Subject". Section 6.3 reinforces it: an Issuer whose
view of an Artifact changes "SHOULD Register a new Signed Statement using the
same 15 CWT iss and sub Claims".

For EMILIA the Artifact is the authorized ACTION, not the receipt document. The
CAID (`caid:1:<action_type>:jcs-sha256:<digest>`) is a content-addressed
identifier of exactly that action object. So `sub` is the CAID.

Two properties follow, and both are the reason for the choice:

1. **Grouping works.** Every statement about the same action, from any issuer,
   collects under one `sub`. That is precisely the completeness and
   non-equivocation use Section 3 describes. A relying party asking "what has
   anyone said about this action" has one key to ask with.
2. **The subject is verifiable, not merely asserted.** The CAID recomputes from
   the carried payload. `verifyEpScittSignedStatement` recomputes it and refuses
   `sub_not_bound_to_payload` on mismatch, so a statement cannot claim to be
   about an action it does not carry.

Alternatives considered and rejected:

- **`sub` = receipt id.** Every receipt becomes its own subject, which destroys
  the grouping property Section 3 exists for. Two receipts for the same action
  would be unrelatable.
- **`sub` = the target resource (an account, a document).** Not derivable from
  the payload, so a relying party cannot check it. An issuer could assert any
  subject it liked.
- **`sub` = the issuer's organization.** Far too coarse to identify an Artifact.

The profile does not let a caller override `sub`. It is always the CAID, and the
binding check is therefore unconditional.

## CWT claims and the payload

RFC 9597 Section 2 requires an application seeing CWT claims in both the payload
and the header to check they are identical, "unless the application defines
other specific processing rules for these claims". This profile defines such a
rule, stated here so it is on the record rather than implied:

The payload is an EP receipt document, not a CWT, and carries no CWT claims, so
there is nothing to compare field by field. Instead `sub` is bound to the
payload by recomputation (above), and `iss` is checked against the relying
party's pin when one is supplied. The header claims are therefore bound to the
payload by construction rather than by field comparison, which is strictly
stronger than the equality check the escape clause replaces.

## Two signatures, never conflated

A verified statement carries two independent signatures, reported as two
separate booleans that are never collapsed into one:

- `statement_signature` is the SCITT Issuer's COSE_Sign1 signature. It attests
  that this key holder emitted these payload bytes. It is a
  transport/registration attestation and confers no approval or authorization
  semantics whatsoever.
- `receipt_signature` is the EP receipt's own Ed25519 signature over its
  canonical JSON payload, verified offline under the relying party's pinned
  receipt-issuer key. This, and only this, is the approval evidence.

Because the COSE payload IS the receipt's canonical JSON bytes, wrapping and
unwrapping the statement changes nothing the receipt signature covers. Vector
`tampered-payload` pins the case where the first is green and the second is not.

## Relationship to EP-COSE-ENCODING-v0.1

`conformance/encoding-equivalence/` ships a COSE_Sign1 transport envelope for the
same receipts, and its README says plainly that it "is NOT a complete SCITT
Signed Statement per RFC 9943: that requires additional protected-header
semantics, including CWT Claims, which this transport envelope does not carry. A
SCITT profile is future work."

This is that profile. It imports that module's deterministic CBOR codec rather
than reimplementing one, and adds the CWT Claims header and the subject binding.
Vector `missing-cwt-claims` is deliberately shaped like the transport envelope's
header set, so the vector suite records exactly what the difference is.

## The vectors

`vectors.json` pins one EP receipt, fixed public test keys, and five statements
with their expected accept-or-refuse outcome. The four negative cases are forged
at the CBOR layer with genuinely valid signatures over the forged headers, so
only a profile rule can catch them; building them through the API would have
proven only that the API declines to emit them.

| id | What it is | Expected |
| --- | --- | --- |
| `valid-signed-statement` | Conforming statement. | `valid: true`, every check green |
| `missing-cwt-claims` | Protected header omits label 15. | refusal `cwt_claims_missing` |
| `wrong-sub` | `sub` is a well-formed CAID for a different action. | refusal `sub_not_bound_to_payload` |
| `tampered-payload` | Receipt edited, statement re-signed. | refusal `receipt_invalid`, with `statement_signature: true` and `receipt_signature: false` |
| `alg-confusion` | Signed `alg` says ES256 (-7), signature is real Ed25519. | refusal `unsupported_statement_alg` |

Fail-closed means each of those returns a named reason. None throws.

Regenerate and replay:

```sh
npx tsx examples/scitt-registration/generate-vectors.mjs --write
npx tsx --test packages/verify/scitt-statement.test.ts
```

The generator self-checks before writing, and the suite replays the checked-in
file, so a drift between code and vectors fails in two places.

## Specifications pinned

Read from the RFC Editor text at these digests:

| Document | sha256 of the .txt |
| --- | --- |
| RFC 9943, An Architecture for Trustworthy and Transparent Digital Supply Chains | `204aea020731e1306e8ffe0aaae5c9559a7a8edf24bd089ae79d6a6d6c7676f1` |
| RFC 9597, CBOR Web Token (CWT) Claims in COSE Headers | `b6baaec655bc86606602a6f6e93f0103db6e6f98460f1e43437e74a6a5e02bdd` |
| RFC 9052, CBOR Object Signing and Encryption (COSE): Structures and Process | `01eecd7f646537600e7aad665b1fa581ce6ec33dae4ef4add0997aaf38cd0a45` |
