# Changelog

All notable changes to `@emilia-protocol/verify` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 3.0.0 — 2026-06-28

### Changed (BREAKING)
- **Canonicalization is now strict and cross-language byte-identical.** Signed
  material must be strings or safe integers; `verifyReceipt` fails closed on
  payloads outside the profile (non-integer/unsafe numbers, etc.). Fixes the
  JS/Python/Go consensus split — the same payload now hashes identically in all
  three. (`isCanonicalizable` is exported.)
- **Legacy EP-MERKLE-v1 anchors are refused by default.** Production verification
  requires EP-MERKLE-v2 (domain-separated, payload-bound). v1 anchors verify only
  with the explicit `{ allowLegacyMerkle: true }` opt-in — preserving the
  "receipts verify forever" promise for old artifacts without carrying live v1
  risk. New issuance is v2-only.

### Migration
- If you verify pre-v2 anchored receipts, pass `{ allowLegacyMerkle: true }`.
- Ensure signed payloads use strings or integers (no floats like `1.5`/`-0.0`).

## 2.1.0 — 2026-06-25

### Added
- `evaluateAgentBinding(context, { maxAgeSec, at })` (PIP-008 §2.1, L4→L7
  binding): surfaces the external agent-identity / delegation evidence a
  decision relied on (`agent_id`, `delegation {scheme, ref, hash}`,
  `observed_at`) and, when `maxAgeSec` is set, enforces freshness **fail-closed**
  — missing, future-dated, or over-age `observed_at` yields `fresh: false` with
  a reason. With no `maxAgeSec`, evidence is recorded (`fresh: null`) for audit.
  Lets a PDP record which upstream evidence backed a human authorization and
  detect a stale/unconstrained upstream claim after the fact. Additive; no
  change to existing verifier behavior.

## 2.0.0 — 2026-06-23

### Breaking

- **`verifyCommitmentProof()` now rejects unsigned proofs by default.** Previously a
  proof with no signature / no pinned public key was silently accepted. It now returns
  `{ valid: false, error: 'Signature and public key are required' }`. Callers that
  genuinely need to accept an unsigned commitment must opt in explicitly:
  `verifyCommitmentProof(proof, null, { allowUnsigned: true })`. This closes a
  silent-accept gap — the verifier no longer vouches for proofs nothing actually signed.

### Added

- **Strict verifier mode** — `verifyTrustReceipt(receipt, key, { strict: true, rpId, expectedPolicyHash })`.
  Opt-in and safe by default: without `strict: true` the verifier behaves exactly as in
  1.x (`strict: { enabled: false, valid: true, checks: {} }`), so existing callers and
  conformance suites are unaffected. When enabled, the receipt must additionally satisfy:
  - `pinned_keys` — every signoff names an `approver_key_id` resolving to a pinned public key; a trusted `logPublicKey` anchors the log
  - `rp_id` — Class-A WebAuthn `rpIdHash` matches the caller-supplied `rpId`
  - `user_presence` / `user_verification` — Class-A signoffs assert the UP and UV flags
  - `key_windows` — pinned keys carry `valid_from`/`valid_to`, and each signoff's context `issued_at` falls inside its key's validity window
  - `policy_hash` — every context carries a `policy_hash` matching the caller-supplied `expectedPolicyHash`
  - `no_unsigned` — no critical proof is accepted unsigned
- Public TypeScript types for strict mode: `VerifyStrictOptions`, `StrictReport`, `VerifyReceiptOptions`.

### Notes

This release makes third-party offline verification strict enough to stand on its own:
an outside auditor can pin keys, policy, and RP identity and get a hard pass/fail without
trusting the issuer's server. 108/108 package tests; cross-language conformance (JS/Py/Go) green.
