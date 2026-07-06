# Changelog

All notable changes to `@emilia-protocol/verify` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 3.4.0 (2026-07-05)

### Added
- **Opt-in append-only consistency check** in `verifyTrustReceipt`: pass
  `opts.priorCheckpoint = { tree_size, root_hash, consistency_proof }` (a
  checkpoint head you previously observed and pinned, plus the RFC 6962
  consistency proof from that head to the receipt's checkpoint) and the
  verifier adds a fail-closed `checks.consistency` gate. A malformed pin, a
  missing proof, an unusable receipt checkpoint, or an invalid proof each
  refuse with a distinct reason. Honesty note: this proves append-only
  consistency between two observed heads; it does NOT establish currency or
  split-view honesty by itself (that needs independent witnesses).
  `verifyCheckpointConsistency` and `CONSISTENCY_ALG` are now exported from
  the package entry, and `consistency.js` ships in the published package.

### Fixed
- **Empty inclusion path degenerate case (fail-closed).** An empty
  `log_proof.inclusion_path` used to collapse to `leafHash === root_hash` for
  ANY claimed `tree_size`, so a forged checkpoint whose root simply repeated
  the leaf hash would pass. An empty path is now accepted only when the
  checkpoint's `tree_size` is exactly the integer 1 (and `leaf_index`, when
  present, is 0). Any other tree size with an empty path is refused with a
  distinct reason. Applies to both EP-MERKLE-v2 and opt-in legacy folds.
  Behavior for non-empty paths is unchanged.

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
