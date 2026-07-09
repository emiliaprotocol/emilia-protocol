# Changelog

All notable changes to `@emilia-protocol/verify` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 3.7.1 (2026-07-09)

### Security
Delegation-chain head anchoring no longer trusts `parent_ref`. `parent_ref` is
not in `DELEGATION_PROOF_FIELDS`, so it is unsigned and attacker-controlled: a
validly-signed head link whose delegator is a stranger could set `parent_ref`
to a real root approver and falsely attribute the whole chain to a human who
never delegated (authority laundering / false attribution). The
`chain_anchored` check now anchors ONLY on the SIGNED `head.delegator`. Breaks
zero legitimate chains (a valid head's delegator is always the root approver).
Fixed uniformly in this package, `lib/provenance`, `emilia-verify` (Python
2.4.4), and `go-verify` (v2.1.4). Regression vector
`reject_forged_parent_ref_anchor` in `conformance/vectors/delegation-integrity.v1.json`
locks it in all three languages.

## 3.7.0 (2026-07-08)

### Added
The reliance layer: `EP-RELIANCE-KERNEL-v1` (the closed rely / do_not_rely_*
verdict set), `EP-RELIANCE-PROFILE-v1` and the signed, pinnable
`EP-RELIANCE-PROFILE-REGISTRY-v1` for regulated profiles, and the reliance-gap
acceptance preflight (library + CLI). Authority subject is bound to the
verified signer and a pinned profile is required.

### Security
Closed the type-coercion / assertion class across all three ports; closed 6
digest-divergence / mutation-after-sign holes and 6 malformed-input /
type-coercion holes from the surface audit; `verifyReceipt` pins the Ed25519
issuer key (Node/web parity).

## 3.6.1 (2026-07-06)

### Added
`receiptGrantBindingStrength(receipt, grantHash?)` (`./consent-grant`), returning
`signed_action | top_level | caller_override | none`, and a top-level
`binding_strength` field on `verifyReceiptUnderGrant` results. A receipt binds to
a consent grant most strongly when it carries `grant_hash` inside its SIGNED
Action Object (covered by the human signature); a caller-supplied hash is still
honored but labeled `caller_override` (advisory, only as trustworthy as the
caller). `receiptReferencedGrantHash` now prefers the signed reference over any
override. The `witness` and `consumption-proof` reference emitters are now
reachable as package subpaths (`@emilia-protocol/verify/witness.js`,
`@emilia-protocol/verify/consumption-proof.js`).

## 3.6.0 (2026-07-06)

### Added
**EP-CONSENT-GRANT-v1** (`./consent-grant`): the scoped, revocable STANDING
consent grant naming `{asset, control_verb, expiry}`. It fills binding 3 (Consent
Grant) of the Command Authority Envelope (draft-morrison-ot-command-authority) as
its own first-class object, DISTINCT from the per-action receipt at the binding
moment (CAE binding 4, which is what an EP receipt IS). The grant is standing
authority issued once over a window; the receipt is the per-action authorization.

- **The object.** `{ profile: "EP-CONSENT-GRANT-v1", grant_id, principal, asset,
  control_verb, constraints?, issued_at, expires_at, grant_hash, signature }`.
  `grant_hash` is `sha256:` over the JCS/RFC-8785 canonical bytes of the grant
  with grant_hash and signature excluded; `signature` is the principal's
  device-bound Ed25519 signature over those same bytes. Reuses the package's
  `canonicalize()` + SHA-256 and the `crypto.verify(null, ...)` Ed25519
  convention exactly, no new primitives.
- **`buildConsentGrant(spec, signer)`** reference issuer (stamps grant_hash,
  signs), plus `computeGrantHash(grant)` / `verifyGrantHash(grant)`.
- **`verifyConsentGrant(grant, pinnedPrincipalKey, { now, revocation, revokerKeys })`**
  returns `{ valid, checks: { hash, signature, within_window }, reason? }`.
  Fail-closed with a distinct reason: a bad grant_hash, an unpinned or bad
  principal signature, a `now` outside `[issued_at, expires_at]`, or a valid
  revocation statement binding the grant_hash (`grant_revoked`). Revocation is
  checked with the existing `verifyRevocation` against a `commit`-typed target
  keyed on grant_hash; an unpinned revoker cannot revoke.
- **`verifyReceiptUnderGrant(receipt, grant, opts)`** is the composition: the
  per-action receipt acts under the grant by carrying grant_hash. Returns
  `{ ok, checks: { grant, asset_covered, verb_covered, grant_binding }, reason? }`
  and refuses with a distinct reason on any mismatch: `grant_signature_invalid`,
  `grant_expired`, `grant_revoked`, `asset_mismatch`, `verb_mismatch`,
  `grant_binding_mismatch`. What it proves: the grant is authentic and in-window
  and the receipt is scoped-and-bound to it. What it does NOT prove: business
  correctness, or CURRENT validity. Offline verification of either artifact is
  authenticity as of commit; revocation currency needs a fresh revocation
  snapshot, the same as any EP status.

Schema: `public/schemas/ep-consent-grant.schema.json`. Spec:
`docs/EP-CONSENT-GRANT-SPEC.md`. This is a candidate profile to fold into the
authority / receipts drafts in a future revision, shipped in code today.

### Changed
**timestamp-proof (RFC 3161) is now cross-language.** The `timestamp-proof.js`
minimal DER/CMS reader was ported faithfully to Python (`packages/python-verify`,
`verify_timestamp_proof`) and Go (`packages/go-verify`, `VerifyTimestampProof`).
The Python port hand-rolls the same minimal DER reader in pure Python and uses
`cryptography` only for the RSA/ECDSA signature verify (no new dependency); the Go
port uses a pure-stdlib DER reader plus `crypto/rsa` / `crypto/ecdsa` /
`crypto/x509`. A new shared vector suite
(`conformance/vectors/timestamp-proof.v1.json`, 13 vectors minted from a local
test TSA with `openssl`) runs in `conformance/run.mjs`, where the JavaScript,
Python, and Go verifiers must agree, including the exact per-vector refusal path.
This supersedes the earlier "timestamp proof remains JavaScript-only" note in the
3.5.0 entry below.

## 3.5.0 (2026-07-05)

### Added
Five ADDITIVE, OPT-IN transparency/currency knobs in `verifyTrustReceipt`, each
following the existing `priorCheckpoint` pattern: a knob runs ONLY when its
option is supplied, adds exactly one member to `checks` when active, folds into
`valid` by conjunction, and fails closed with a distinct reason. With NO knob
option supplied the result is byte-for-byte unchanged (the frozen seven-member
`checks` set, no extra top-level members). Each knob's full module result is
surfaced under a dedicated, option-gated top-level member.

- **Witness cosignatures (EP-WITNESS-v1).** `opts.witnessQuorum = { cosignatures,
  pinnedWitnessKeys, k }` requires at least `k` DISTINCT pinned witnesses to have
  validly cosigned the receipt's checkpoint head. Adds `checks.witness_quorum`
  and surfaces `result.witness_quorum`. Fail-closed: a receipt with no checkpoint,
  a bad `k`, or fewer than `k` distinct valid cosignatures each refuse. What it
  proves: `k` trusted witnesses attested to ONE head (the local, single-view half
  of equivocation detection). What it does NOT prove: that no different head was
  shown to someone else (that cross-view gossip is the deployment's job).
- **Trusted-time proof (RFC 3161).** `opts.timestampProof = { token,
  expectedDigest, pinnedTsaKeys }` verifies a TSA timestamp token over a
  caller-chosen digest against a PINNED TSA key. Adds `checks.timestamp_proof`
  and surfaces `result.timestamp_proof`. Fail-closed: a missing token, a
  missing/malformed digest, an unpinned TSA, or a bad signature each refuse with
  a distinct reason. What it proves: a TSA asserted the digest existed at
  `gen_time` (the bytes predate `gen_time`). What it does NOT prove: that the
  action was correct or authorized, and it is authentic-as-of-token only (it says
  nothing about current TSA-certificate validity or revocation, which needs a
  fresh online check).
- **Currency evaluation (EP-CURRENCY-v1).** `opts.currency = { now,
  maxStalenessSeconds, freshHead, freshHeadRequired }` evaluates currency-at-T on
  a separate axis from offline authenticity. Adds `checks.currency`, which passes
  ONLY when a supplied recent non-revoking signed head proves status `fresh`.
  BOTH `stale` AND the honest offline default `unknown` FAIL this opted-in gate:
  offline verification can NEVER establish currency, so absence of proof of
  freshness does not pass (fail-closed). The full two-axis result
  (`authentic_as_of_commit` plus `currency_at_T` with status, evaluated_at, and a
  stable reason string) is surfaced as `result.currency` so a caller can tell
  `unknown` (offline only) apart from `stale` (a head that is too old, was
  required but absent, or shows revocation). `maxStalenessSeconds` is an
  action-policy field (tighter for higher-consequence, irreversible actions), not
  a global verifier constant.
- **Consumption proof (EP-SMT-CONSUME-v1).** `opts.consumptionProof` is a
  third-party bundle proving a one-time nonce transitioned absent to present
  exactly once across two append-only-linked heads. Adds `checks.consumption` and
  surfaces `result.consumption`. Fail-closed: any missing, malformed, or invalid
  sub-proof, a non-append-only h1 to h2 link, a present-at-h1, or an absent-at-h2
  each refuse with a distinct reason (`present` is never inferred). What it
  proves: the tree-shaped consumption facts only. What it does NOT prove: the
  checkpoint SIGNATURES (the caller authenticates those separately) or currency of
  the later head.
- **Initiator-software attestation (EP-INITIATOR-ATTESTATION-v1).**
  `opts.requireInitiatorAttestation === true` structurally validates the
  self-asserted initiating-software attestation at
  `receipt.action.initiator_software` (model_id, model_version,
  tool_chain_digest, optional neutralized statement). Adds
  `checks.initiator_attestation` and surfaces `result.initiator_attestation`.
  Fail-closed: an absent or malformed attestation is `false` (the validator never
  repairs a malformed one). What it proves: WHICH software asked. What it does NOT
  prove: that the software behaved (the labels are self-asserted, and the digest
  is authentic-as-supplied, not proof of correct execution).

The five modules (`witness.js`, `timestamp-proof.js`, `currency.js`,
`consumption-proof.js`, `initiator-attestation.js`) now ship in the published
package, and their standalone functions and constants are re-exported from the
package entry (`verifyWitnessCosignature`, `requireWitnessQuorum`,
`witnessSigningDigest`, `WITNESS_VERSION`, `WITNESS_DOMAIN_TAG`,
`verifyTimestampProof`, `TIMESTAMP_PROOF_ALG`, `evaluateCurrency`,
`CURRENCY_VERSION`, `CURRENCY_STATUS`, `CURRENCY_REASON`,
`verifyConsumptionProof`, `ReferenceConsumptionTree`, `CONSUMPTION_PROFILE`,
`CONSUMPTION_LEAF_DOMAIN`, `SMT_DEPTH`, `validateInitiatorAttestation`,
`neutralizeStatement`, `normalizeDigest`, `bindInitiatorAttestation`,
`INITIATOR_ATTESTATION_VERSION`, `INITIATOR_ATTESTATION_FIELD`,
`INITIATOR_STATEMENT_MAX`), with TypeScript types in `index.d.ts`. Note: the
in-repo JS reference verifiers are one team's cross-language ports, not
clean-room independent implementations. EP-CURRENCY-v1, EP-WITNESS-v1,
EP-SMT-CONSUME-v1, and EP-INITIATOR-ATTESTATION-v1 are now ported to Python
(`packages/python-verify`) and Go (`packages/go-verify`) and run cross-language
in `conformance/run.mjs` over shared vector suites (`currency.v1.json`,
`initiator-attestation.v1.json`, `consumption-proof.v1.json`, `witness.v1.json`),
where the JS, Python, and Go verifiers must agree. **Timestamp proof (RFC 3161)
remains JavaScript-only** — its Python/Go ports were deferred because neither the
Python `cryptography` dependency nor the zero-dependency Go module exposes a
CMS/PKCS#7 SignedData / TSTInfo parser, so it has no cross-language vector suite.

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
