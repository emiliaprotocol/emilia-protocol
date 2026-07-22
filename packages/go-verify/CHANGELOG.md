# Changelog

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
