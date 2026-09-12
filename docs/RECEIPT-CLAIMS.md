# What an Authorization Receipt Proves — and What It Doesn't

**Updated:** 2026-09-11
**Audience:** Auditors, regulators, security reviewers, and anyone deciding how much weight to place on an EP receipt.
**Purpose:** State the evidentiary value of authorization-receipt verification. The basic `verifyReceipt` check verifies an issuer signature; it does not perform all the authorization checks described below. The selected receipt profile, verifier options, and independently pinned trust inputs determine which claims are checked.

The receipt proves a precise, narrow thing. It does not prove several things people sometimes assume it does. Both lists matter equally.

---

## What a receipt proves

A complete authorization-receipt verification can establish the following under
the selected profile and independently pinned trust inputs:

- **A specific key produced a user-verified signature over this exact action.** The signature is over the canonical Authorization Context, which commits to the action hash. Change one parameter of the action (amount, beneficiary, target) and the receipt no longer verifies. (I-D -12 Sections 3–4 and 5.3.)
- **The trusted directory binds the signing key to an approver identifier.** The verifier checks the applicable directory material, policy reference, and signed validity fields. This is evidence of the directory's assertion, not independent proof of a person's identity or of when the provider acted. (I-D -12 Sections 5.2, 6.2, and 7.3.)
- **For Class A, the assertion binds the context and reports user presence and verification.** The verifier checks the signed WebAuthn challenge and authenticator flags. Relying-party policy must separately select the permitted origin, RP ID, authenticator assurance, and key provenance; user-verification flags alone do not establish civil identity or a non-exportable key. (`packages/verify/src/index.ts`, `verifyWebAuthnSignoff` and `verifyTrustReceipt`.)
- **Separation of duties held within the modeled system.** The initiator is in no approver slot, approvers are pairwise distinct, and the approval count meets `required_approvals`. (I-D -12 Sections 6.2, 7.3, and 9.)
- **The receipt is included under the supplied signed log checkpoint.** Inclusion proves membership under that root. Append-only consistency requires a separately pinned earlier checkpoint and a consistency proof; detecting split views requires independent observation. (I-D -12 Sections 7.2–7.3.)
- **Historical authenticity can be checked offline.** The verifier needs the complete profile-required evidence and trusted keys. This does not establish current revocation status, current policy acceptance, or global non-consumption. Long-term verification also depends on preserving evidence and trust material and on the continued security of its algorithms.

This is what makes a receipt *evidence* rather than *testimony*: it is portable, signed, and third-party-verifiable, independent of the operator whose conduct may be under examination.

---

## What a receipt does NOT prove

A receipt is silent on everything outside the signature's reach. It does **not** prove:

- **That the decision was wise, correct, lawful, or successful.** The signed decision is bound to a key and action. It says nothing about whether approving the action was a good idea.
- **That the policy was adequate.** The receipt binds the signoff to a policy reference; it does not certify that the policy required the right approvers or set the right thresholds. A weak policy produces a perfectly valid receipt.
- **That the human was not coerced.** Separation of duties defeats *unilateral* self-approval; it does not defeat a coerced approver, collusion among distinct enrolled humans, or one human controlling multiple enrolled identities. Receipts make such events *attributable* — named, signed, evidenced — which raises the cost of insider fraud; they do not make it impossible, and we do not claim otherwise. (I-D -12 Section 13.8.)
- **That the rendering was faithful.** A signature binds signed bytes; it does not establish what the person saw or understood. Separately verified presentation evidence can bind display bytes to the same action within its own trust boundary, but cannot prove what a compromised physical display showed. ([I-D -12, Section 13.4](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-receipts-12#section-13.4).)
- **A specific natural-person identity beyond the key↔approver enrollment binding.** The receipt proves a *key* enrolled under a named approver signed. Proving that the named approver is a specific real-world human — biometric identity, KYC-grade identity proofing — is explicitly out of scope of this protocol; the current draft states this boundary directly in [Section 1.2](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-receipts-12#section-1.2), and enrollment binds key to approver in [Section 5.2](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-receipts-12#section-5.2). A key-discovery or identity layer can slot in at the enrollment boundary if a deployment needs stronger identity assurance. That is a layer above the receipt, not a property of it.
- **That the named approver personally authorized their own enrollment.** The receipt proves a key that the Approver Directory binds to a named approver produced the signature; it does not prove the approver — rather than an enrollment-authorized operator — placed that key in the directory. Enrolling a credential is a directory write, gated by an explicit `approver.enroll` capability distinct from ordinary read/write access, and it records the enrolling party as a second-party attestation (I-D §5.2). That is an *authority assertion* that the key belongs to the named approver, not a proof that the approver personally controls it. The strength of that assertion depends on whether the deployment has provisioned a directory. **For an org that has provisioned a directory (SCIM/IdP), EP enforces the anchor at enrollment**: the `approver_id` must resolve to an *active* provisioned directory user, and the credential records `enrollment_basis='directory'` with the matching directory identity pinned. An enrollment-authorized operator can no longer bind an `approver_id` the provisioned directory does not carry. Where no directory is provisioned, enrollment still rests on the operator's say-so and is recorded honestly as `enrollment_basis='operator_attested'`: a party holding `approver.enroll` can bind a device under an `approver_id` it names, including one it does not personally control. Either way, the boundary is unchanged in kind — a deployment that operates its own directory inherits the directory operator into its trust base, which is why a relying party pins the Approver Directory it trusts. What the directory anchor changes is that, once a directory exists, the binding is enforced against it rather than resting on an unconstrained operator assertion.
- **Current authority or global one-time consumption.** Admission and replay prevention require the configured enforcement boundary and durable state. An optional consumption proof describes a transition between supplied checkpoints; it is not an atomic admission decision or proof that no other operator admitted the action. (`verifyTrustReceipt().decision_scope`.)
- **That execution followed approval or produced an external effect.** Receipt timestamps and signed assertions do not independently prove provider ordering, complete mediation, settlement, or physical execution. Those need separately evaluated enforcement and provider evidence.
- **Anything outside the formal claim's stated scope.** Each modeled result has explicit assumptions and exclusions. See `security/claims.v1.json` and the generated `security/security-case.json`; a model result is not proof of an AI model's behavior or an uncompromised deployment. (I-D -12 Section 13.6.)

If a claim is not in the first list, do not make it.

---

## Algorithm agility and post-quantum

**What the format uses today.** Receipts and log checkpoints are signed with **Ed25519**. Class-A device signoffs use **ECDSA P-256 / SHA-256 (ES256)** over a WebAuthn assertion (Class A also permits Ed25519 where the authenticator supports it). Action, policy, and context hashes are **SHA-256**. (Verified against `packages/verify/index.js` and the I-D §5.1.)

**Why this matters for a long-lived artifact.** A receipt is not a session token; it is *durable evidence*. The survivorship claim — that a 2026 receipt still verifies in 2033 and beyond — is exactly what makes post-quantum relevant: evidence that may be verified decades from now must outlive classical signatures. The realistic threat is "harvest now, decrypt later" against the *authority signatures*, not the hashes (SHA-256 is only weakened, not broken, by Grover). See `docs/POST-QUANTUM-MIGRATION.md` for the full analysis.

**The path, framed as headroom — not a default receipt feature.** The wire format is versioned (`EP-RECEIPT-v1`) and signatures carry key ids and an explicit `algorithm` field. An opt-in repository-local Ed25519 + ML-DSA-65 envelope prototype now exercises the migration seam, but it is not wired into `EP-RECEIPT-v1`, default receipt issuance, transparency checkpoints, or deployed Gate receipts. Re-anchoring historical checkpoints under post-quantum keys is a forward-compatible mitigation for evidence that must survive a cryptographically-relevant quantum computer. The prototype is not a claim that EP is post-quantum secure or FIPS-validated today.

---

*References: [draft-schrock-ep-authorization-receipts-12](https://datatracker.ietf.org/doc/html/draft-schrock-ep-authorization-receipts-12) (current published I-D as checked 2026-09-11), `standards/posted/draft-schrock-ep-authorization-receipts-12.xml` (submitted source snapshot), `packages/verify/` (offline verifier), and `docs/POST-QUANTUM-MIGRATION.md` (PQ analysis). Check the [live Datatracker record](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/) before citing a revision as current.*
