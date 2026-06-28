# Security Decision Record

## Decision

For government pilots, EMILIA should first deploy as customer-controlled software inside the buyer's existing boundary.

## Rationale

This avoids exporting sensitive mission data to an unauthorised hosted service while still proving the protocol value: no high-risk action proceeds without a verifiable, action-bound receipt.

## Controls Implemented In Code

- strict production receipt verifier wrapper
- inline/self-asserted issuer keys refused outside demo routes
- tenant-bound v1 writes
- public/sandbox entities born org-bound
- hash-chained `security_events`
- KMS/HSM signer abstraction
- static `npm run gov:check`
- key-compromise drill

## Known Boundaries

EMILIA proves authorization evidence. It does not prove the human made a wise decision, was not coerced, or understood every consequence. WYSIWYS display binding, Class-A device signatures, quorum, and audit trails reduce that risk but do not eliminate it.

## Accreditation Boundary

This repository is not FedRAMP authorized and does not by itself make a deployment FIPS validated. Those claims require a defined cloud service boundary, validated cryptographic modules, independent assessment, continuous monitoring, and formal authorization.
