# Changelog

## Unreleased

## 2.4.4 (2026-08-21)

### Added

- Add same-team Go verification for the opt-in Ed25519 and ML-DSA-65 hybrid
  signature profiles, including hybrid authorization receipts and refusal-code
  parity with the JavaScript and Python conformance runners.

### Security

- Bind the declared hybrid algorithm set into the signed bytes and refuse
  stripped, duplicated, unsupported, malformed, or incomplete signature legs.
- Update the verified build toolchain to Go 1.26.7 and Cloudflare CIRCL 1.6.5;
  the module retains Go 1.21 language compatibility.

## 2.4.3 (2026-08-15)

### Fixed

- Align the Go conformance reason code with the JavaScript and Python
  evaluators when `predicted_effects` is present but is not an array. The
  malformed value now reports `effect_commitment_missing` instead of
  `effect_incomparable`; the fail-closed verdict is unchanged.

### Security

- Pin repository and release verification to Go 1.26.7, which closes the
  invoked `encoding/asn1` recursion vulnerability reported as GO-2026-5972,
  while retaining Go 1.21 language compatibility for the module source.

## 2.4.2 (2026-08-01)

### Security

- Enforce the closed provenance action-scope grammar, reject the malformed
  empty-prefix wildcard `.*`, and require a universal child scope to be funded
  by a universal parent scope, matching the TypeScript verifier.

## 2.4.1 (2026-07-29)

- Trust Receipt verification treats pinned `compromised_at` as terminal and
  supports an optional relying-party `now` for refusing future-issued receipts,
  matching the JavaScript and Python conformance behavior.

All notable changes to the Go verifier are documented here.

## 2.4.0 (2026-07-21)

### Added

- Same-team Go implementations and shared-vector coverage for authority
  document/proof joining and outcome binding.
- Ordered-prefix quorum conformance and stricter revocation statement grammar,
  key identity binding, and closed-member validation.

### Security

- Relying-party authority, action, executor, and revoker pins remain distinct
  from cryptographic validity; malformed or presenter-expanded artifacts fail
  closed.

## 2.3.1 (2026-07-16)

### Security

- Authentic signed negative human decisions remain inspectable evidence but no
  longer satisfy authorization, approval quorum, or separation-of-duties
  predicates.
- Strict JSON and hostile-value handling now refuse duplicate members,
  ambiguous numeric coercions, unsafe timestamps, malformed provenance bounds,
  and invalid evidence-chain role substitutions instead of throwing or
  silently weakening a check.
- Shared conformance vectors exercise the security fixes across the JavaScript,
  Python, and Go one-team ports.
- The existing fixed-arity `VerifyWebAuthnSignoff` and `VerifyQuorum` entry
  points remain source-compatible; origin-pinning variants are exposed as new
  `WithOrigins` functions.

### Release

- The module now carries its Apache-2.0 license, this changelog, and a
  machine-readable release identity in `go-release.json`.
- `publish-go-verify.yml` is the sole supported release path. It requires owner
  dispatch and protected-environment approval, tests the exact dispatched
  `main` commit read-only, creates the module tag in an isolated API job, and
  validates the public proxy checksums, VCS origin, and complete source tree.
