# What an Authorization Receipt Proves — and What It Doesn't

**Date:** 2026-06-12
**Audience:** Auditors, regulators, security reviewers, and anyone deciding how much weight to place on an EP receipt.
**Purpose:** State the exact evidentiary value of an `EP-RECEIPT-v1` document. EP's credibility depends on never claiming more than the cryptography delivers.

The receipt proves a precise, narrow thing. It does not prove several things people sometimes assume it does. Both lists matter equally.

---

## What a receipt proves

A verified authorization receipt establishes — with mathematics, offline, by anyone — that:

- **A specific key produced a user-verified signature over this exact action.** The signature is over the canonical Authorization Context, which commits to the action hash. Change one parameter of the action (amount, beneficiary, target) and the receipt no longer verifies. (I-D §3–§4, §5.3.)
- **That key was enrolled to a named approver, under the stated policy, before execution.** The approver's public key is included via an inclusion proof against a signed Approver Directory, and the signoff is bound to the policy reference and a validity window that the receipt checks `signed_at`/`committed_at` against. The signature is produced *before* the action executes — it is pre-execution authorization, not a post-hoc log entry. (I-D §5.2, §6.3.)
- **For Class A, the signature came from a device-bound key with user verification.** The WebAuthn assertion's challenge equals the context hash, and the authenticator's user-verification bit (biometric or PIN) was set. The EP operator does not hold the key and cannot forge the signature. (I-D §5.1; `packages/verify/index.js → verifyWebAuthnSignoff`.)
- **The authorization was consumed at most once.** Replay across sessions, operators, or time is detectable and rejected (one-time consumption, nonce single-consumption). (I-D §1.1 G3, §6.1.)
- **Separation of duties held within the modeled system.** The initiator is in no approver slot, approvers are pairwise distinct, and the approval count meets `required_approvals`. (I-D §6.1, §7.)
- **The receipt is in an append-only log.** A Merkle inclusion proof places the receipt leaf under a checkpoint root, and the checkpoint signature verifies against the trusted log key. (I-D §5.2, §6.2–§6.3.)
- **All of the above is verifiable offline.** With only the receipt, the approver's public key material, and a published log checkpoint — no network access to any EP operator, log, or API, forever.

This is what makes a receipt *evidence* rather than *testimony*: it is portable, signed, and third-party-verifiable, independent of the operator whose conduct may be under examination.

---

## What a receipt does NOT prove

A receipt is silent on everything outside the signature's reach. It does **not** prove:

- **That the decision was wise, correct, or lawful.** A receipt proves a named human approved this exact action. It says nothing about whether approving it was a good idea.
- **That the policy was adequate.** The receipt binds the signoff to a policy reference; it does not certify that the policy required the right approvers or set the right thresholds. A weak policy produces a perfectly valid receipt.
- **That the human was not coerced.** Separation of duties defeats *unilateral* self-approval; it does not defeat a coerced approver, collusion among distinct enrolled humans, or one human controlling multiple enrolled identities. Receipts make such events *attributable* — named, signed, evidenced — which raises the cost of insider fraud; they do not make it impossible, and we do not claim otherwise. (I-D §11.7.)
- **That the rendering was faithful.** A signature proves user presence and approval toward *whatever was rendered*. Cryptography cannot prove the signing surface displayed the action honestly; that is the presentation-attack risk, mitigated by controls (action rendered from the exact hashed bytes, policy-committed render templates, an independent second rendering surface for high-value policies) — not by mathematics alone. (I-D §11.3.)
- **A specific natural-person identity beyond the key↔approver enrollment binding.** The receipt proves a *key* enrolled under a named approver signed. Proving that the named approver is a specific real-world human — biometric identity, KYC-grade identity proofing — is explicitly out of scope of this protocol; EP's terminology defines the approver as the holder of an enrolled signing key (I-D §2), and enrollment binds key to approver (I-D §5.2). A key-discovery / identity layer (for example, a DKA-style identity attestation) can slot in at the enrollment boundary if a deployment needs stronger identity assurance — that is a layer above the receipt, not a property of it.
- **That the named approver personally authorized their own enrollment.** The receipt proves a key that the Approver Directory binds to a named approver produced the signature; it does not prove the approver — rather than an enrollment-authorized operator — placed that key in the directory. Enrolling a credential is a directory write, gated by an explicit `approver.enroll` capability distinct from ordinary read/write access, and it records the enrolling party as a second-party attestation (I-D §5.2). That is an *authority assertion* that the key belongs to the named approver, not a proof that the approver controls it: a party holding `approver.enroll` can bind a device under an `approver_id` it names, including one it does not personally control. A deployment that operates its own directory therefore inherits the directory operator into its trust base — which is why a relying party pins the Approver Directory it trusts, and why a deployment that needs the binding to rest on the approver rather than on the operator anchors enrollment to an out-of-band per-approver ceremony or a provisioned identity source (SCIM/IdP), not on an operator's say-so.
- **Anything the formal models do not cover.** The TLA+/Alloy models prove safety of the authorization state machine. They prove nothing about an AI model's behavior, host compromise, or a weaker conformance class, and they do not yet cover the WebAuthn challenge binding, the Approver Directory, log checkpoints, or the m-of-n flow — those are specified, not proven. (I-D §11.5.)

If a claim is not in the first list, do not make it.

---

## Algorithm agility and post-quantum

**What the format uses today.** Receipts and log checkpoints are signed with **Ed25519**. Class-A device signoffs use **ECDSA P-256 / SHA-256 (ES256)** over a WebAuthn assertion (Class A also permits Ed25519 where the authenticator supports it). Action, policy, and context hashes are **SHA-256**. (Verified against `packages/verify/index.js` and the I-D §5.1.)

**Why this matters for a long-lived artifact.** A receipt is not a session token; it is *durable evidence*. The survivorship claim — that a 2026 receipt still verifies in 2033 and beyond — is exactly what makes post-quantum relevant: evidence that may be verified decades from now must outlive classical signatures. The realistic threat is "harvest now, decrypt later" against the *authority signatures*, not the hashes (SHA-256 is only weakened, not broken, by Grover). See `docs/POST-QUANTUM-MIGRATION.md` for the full analysis.

**The path, framed as headroom — not a default receipt feature.** The wire format is versioned (`EP-RECEIPT-v1`) and signatures carry key ids and an explicit `algorithm` field. An opt-in repository-local Ed25519 + ML-DSA-65 envelope prototype now exercises the migration seam, but it is not wired into `EP-RECEIPT-v1`, default receipt issuance, transparency checkpoints, or deployed Gate receipts. Re-anchoring historical checkpoints under post-quantum keys is a forward-compatible mitigation for evidence that must survive a cryptographically-relevant quantum computer. The prototype is not a claim that EP is post-quantum secure or FIPS-validated today.

---

*References: `standards/draft-schrock-ep-authorization-receipts-03.md` (the I-D), `packages/verify/` (the offline verifier), `docs/POST-QUANTUM-MIGRATION.md` (PQ analysis).*
