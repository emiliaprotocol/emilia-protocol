<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/gate` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 0.10.0 (2026-07-16)

### Added

- The EMILIA Gate consequence-control plane, including action coverage,
  settlement, metering, deployment-attestation, network-witness, SIEM, and
  control-plane modules.
- A BYOC GitHub repository-deletion service with complete mediation, strict
  receipt ingress, durable Postgres action/consumption/evidence state,
  authenticated evidence reads, bounded readiness, graceful shutdown, and
  fail-closed recovery of interrupted effects.
- Helm, Terraform, Docker Compose, and SQL deployment assets for the BYOC
  service. Production assets require explicit non-latest images, separate
  runtime and migration credentials, and operator-owned trust configuration.

### Security

- Pinned issuer, approver, policy, actuator, meter, attestation, and
  network-witness trust roots are kept outside presenter-controlled evidence.
- Signed negative human decisions remain durable evidence but cannot satisfy
  authorization, signer, assurance, authority, quorum, or action-material
  predicates.
- Mobile approval and denial evidence is bound to the exact action, profile,
  presentation, app, device enrollment, RP, origin, and single-use challenge.
- A same-sequence network-witness conflict permanently poisons that exact
  witness/capture-point stream. Higher sequence numbers cannot restore trust;
  recovery requires an explicitly provisioned replacement stream identity.
- Ambiguous external effects burn their receipt and become `indeterminate`;
  Gate never retries a consequential effect whose outcome is unknown.

### Distribution

- Gate now declares the exact `@emilia-protocol/require-receipt` and
  `@emilia-protocol/verify` release bytes it imports. The verifier floor is
  `3.10.1`, which includes the signed-denial authorization fix.
- The npm package now carries this changelog and the Apache-2.0 license text.

## 0.9.2 (2026-07-06)

### Added
`EP-EXTERNAL-VERIFICATION-STATEMENT-v1` (`./reports/external-verification`): the
artifact a non-EMILIA verifier signs after checking EP evidence. It records a
procedure, inputs, result, and limitations under the verifier's own Ed25519 key,
and is accepted only by a relying party pinning that key together with the
verifier identity out of band. It does not authorize an action or certify
correctness. A turnkey harness for issuing one over a conformance run lives in
`examples/external-verification/`.

### Fixed
`./reports/external-verification` imported `canonicalize` from outside the
package root, which made the published tarball unloadable
(`ERR_MODULE_NOT_FOUND`) for every consumer, including the package main entry.
It now imports the byte-identical in-package `canonicalize`. A new
`package-boundary` test fails closed if any shipped module ever again resolves a
relative import outside the package root.

### Security
Verification hardening (fail-closed): a pin must name the `verifier_id` it
vouches for, so a pinned key can never validate a different claimed identity
(`pin_missing_or_mismatched_verifier_id`); `key_id` is derived from the carried
public key and a mismatched envelope `key_id` is refused (`key_id_mismatch`),
since the envelope is outside the signed bytes. Default statement limitations now
disclose that a statement carries no expiry and no consumer binding, is
replayable verbatim, and that `generated_at` is signer-asserted, not verified.
