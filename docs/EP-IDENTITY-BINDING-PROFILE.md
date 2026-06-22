<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-IDENTITY-BINDING-PROFILE — binding an EP approver key to a real-world credential

**Status:** Profile (spec-level). EXPERIMENTAL — governed by an Extension PIP.
Defines an OPTIONAL enrollment profile; implemented with the first deploying
customer. Not a production metric or customer claim.

## The gap this closes

An EP authorization receipt proves, offline, that **the holder of an enrolled
approver key** approved a specific action. It does **not**, by itself, prove
**who that holder is in the real world** — that is an identity-proofing problem
the base protocol deliberately leaves to enrollment ([draft-schrock-ep-
authorization-receipts] §5.2). Every auditor, regulator, and counterparty asks
the same question — *"who is `ep:approver:ao_chen`, really?"* — so this profile
specifies how an EP approver key is **bound at enrollment to an externally-
governed real-world credential**, and what that binding does and does not prove.

This is the human analogue of how agent identity is anchored elsewhere in the
ecosystem (e.g. DNS + certificate binding for agents). EP binds the *human
approver* key to a credential a relying party already trusts.

## The binding

At enrollment, the Approver Directory entry for an approver key MAY carry an
`identity_binding` object that attests the key was enrolled under a verified
real-world credential:

```json
{
  "approver_id": "ep:approver:ao_chen",
  "public_key": "<base64url SPKI>",
  "key_class": "A",
  "identity_binding": {
    "method": "piv | cac | eidas-qes | eudi-wallet | login.gov-ial2 | org-attested",
    "credential_subject": "<opaque subject id or certificate serial>",
    "assurance": "NIST-IAL2 | NIST-IAL3 | eIDAS-substantial | eIDAS-high",
    "bound_at": "<RFC 3339>",
    "attestor_id": "<the enrolling authority the verifier pins>",
    "proof": { "algorithm": "Ed25519", "attestor_key_id": "...", "signature_b64u": "..." }
  }
}
```

Recognized `method` values (extensible):

| Method | Context | Typical assurance |
|---|---|---|
| `piv` / `cac` | US federal / DoD smartcard | IAL3 |
| `login.gov-ial2` | US civilian, remote | IAL2 |
| `eidas-qes` | EU qualified electronic signature | eIDAS high |
| `eudi-wallet` | EU Digital Identity Wallet | eIDAS substantial/high |
| `org-attested` | a named enrolling authority vouches | organization-defined |

## Verification rules (fail-closed)

A relying party that requires identity binding MUST treat an `identity_binding`
the same way EP treats every other party it identifies but does not trust:

1. **Attestor pinned.** `attestor_id` MUST resolve to a key the verifier has
   pinned out of band. A self-asserted, unpinned attestor confers nothing.
2. **Proof binds the subject.** The attestor signature MUST verify, under the
   pinned attestor key, over the canonical `{ approver_id, public_key, method,
   credential_subject, assurance, bound_at }`. A binding that does not cover the
   approver `public_key` is rejected — it must bind *this* key to *this* subject.
3. **Assurance sufficiency.** The verifier MAY require a minimum `assurance`
   (e.g. an auditor of federal funds may require IAL2+ / eIDAS-substantial+).
4. **Absent binding ⇒ unproven, not invalid.** A receipt whose approver key has
   no `identity_binding` still verifies cryptographically; it simply does not
   carry a real-world-identity claim. Verifiers MUST NOT infer identity from its
   absence, and MUST NOT treat absence as a verification failure.

## Honest boundary — what this proves, and what it does not

A verified `identity_binding` proves that **a named enrolling authority attested,
at `bound_at`, that this approver key was issued to the holder of a specific
externally-governed credential at a stated assurance level.** It does **not**
prove the credential was un-revoked at signing time (a freshness/CRL problem,
see [EP-REVOCATION-SPEC]), that the attestor's own proofing was sound, or that
the holder was not coerced. It moves the "who is this, really?" question from
*unanswerable inside EP* to *answerable against a credential system the relying
party already governs* — which is the most an offline protocol can honestly do.

## Relationship to the base protocol

This profile adds **no new trust primitive** and does not modify the EP-RECEIPT
or EP-QUORUM wire formats: `identity_binding` lives in the Approver Directory
entry, alongside the existing key-class and second-party-attestation fields, and
is verified with the same asymmetric, identified-but-not-trusted, fail-closed
discipline as the rest of EP. It is the enrollment-side answer to the directory-
authority consideration in [draft-schrock-ep-authorization-receipts] §11.6.
