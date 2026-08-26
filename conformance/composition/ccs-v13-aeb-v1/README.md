<!-- SPDX-License-Identifier: Apache-2.0 -->
# CCS-05 v1.3 receipt to AEB composition v1

This package independently implements the 22-field CCS v1.3 receipt profile
described by `draft-correctover-ccs-05`, verifies it under a
relying-party-pinned Ed25519 issuer, and maps the full signed action digest to
an exact action constructed by the executor under a pinned CAID profile.

The runner performs a real local `sum` operation and binds its structured
response into the positive receipt. It also emits a policy-deny receipt without
executing the out-of-range operation.

Run the package:

```bash
npm run conformance:composition:ccs-v13-aeb
```

The fourteen checks cover the official draft source pin, separation from the
published 1.1.20 package shape, live response binding, Ed25519 verification,
exact-action CAID mapping, signature mutation, untrusted key, audience,
freshness, parameter substitution, full-digest substitution preserving the
draft's 16-hex `params_hash`, consumed status, unavailable status, and a native
deny that remains non-authorizing.

## Source and interpretation boundaries

- Official source: `draft-correctover-ccs-05`, SHA-256
  `c91f0fa31b1b9e5e2dfe79b99f3b554075d3a44d5309406e748b728f86767cb9`.
- The latest public `ccs-verifier` package and Codeberg head still emit their
  distinct `receipt_version: 1.1` profile. This runner does not relabel those
  bytes as v1.3.
- CCS-05 defines a 16-hex `params_hash` and a full SHA-256 inside `action`.
  The AEB mapping recomputes the full digest from executor-owned parameter
  bytes and requires both the signed full digest and its 16-hex prefix.
- The draft says that `signature` covers all receipt fields. Because a
  signature cannot include itself, this profile applies the standard detached
  interpretation: RFC 8785 canonical JSON of the other 21 fields.
- The legacy HMAC `receipt` field is present and covered by the Ed25519
  signature. AEB treats it as signed issuer data, not as an independently
  verifiable cross-domain trust root.
- CCS `allow` fills only the `machine-policy-decision` evidence role. It does
  not become human authorization, AEB admission, provider entry, or effect
  proof.
- The deterministic signing keys are public test material. A passing report is
  a self-attested reproduction package until an external operator runs it.
