# Mobile Approval Threat Model

## Protected property

A relying party accepts a mobile approval or denial only when a pinned enrolled
credential completed user-verified WebAuthn over the exact action context, the
approved application produced independently verified integrity evidence bound
to that context, and the exact registered challenge was consumed once and
recorded durably.

## Refused attacker moves

| Attack | Enforcement |
|---|---|
| Agent changes material action fields | Recomputed action hash and signed context |
| Network or presenter mutates the bound presentation bytes | Recomputed presentation hash inside the signed context |
| Presenter swaps origin or RP ID | Pinned WebAuthn origin and RP ID |
| Unenrolled key or app claims authority | Server-pinned enrollment and app allowlist |
| Bare P-256 signature replaces a passkey ceremony | Class-A WebAuthn verification with UP and UV |
| Client asserts its own integrity status | Independent App Attest or Play Integrity verifier |
| Platform token is replayed across actions | Exact attestation request hash |
| Android passkey is synced or replayed from a second device | Play-bound non-exportable Keystore public key plus a required per-ceremony key signature |
| Concurrent or later ceremony replay | Atomic body-bound challenge consumption |
| First authenticator assertion repeats or falls below its registration counter | Registration `sign_count` is atomically seeded as the durable counter baseline |
| Later authenticator or App Attest counter rolls back | Durable monotonic counter stores |
| Presenter hides unknown or nested display data | Closed versioned presentation schema and native pre-sign validation of every accepted field |
| Storage or evidence log is unavailable | Closed refusal, never fallback |
| Caller supplies a weaker profile | Profile selected by the server from the challenge hash |
| Caller self-asserts another approver's identity | Mandatory agency authorization at ceremony issuance, verification, and both enrollment phases |
| Client requests an overlong enrollment | Server-owned validity boundary is bound into enrollment evidence |

## Residual assumptions

- Enrollment correctly binds the approver, passkey, app, and attestation key.
- The agency identity provider authenticates principals correctly and the
  configured authorization policy maps them to the intended approver records.
- Platform attestation services and their verification roots behave within the
  relying party's stated trust model.
- The system-of-record adapter constructs the correct action and presentation.
- The reference clients render every accepted field in the closed presentation
  schema. A fully compromised
  client can display one thing while signing and attesting another. Presentation
  hashing detects byte substitution, not dishonest pixels or semantic mismatch
  between the action and its presentation. This profile does not implement or
  claim [PIP-010 deterministic rendering](../../PIPs/PIP-010-wysiwys-execution-integrity.md).
- Clocks and durable stores meet the deployment's fault assumptions.
- The protected executor has no alternate path around the gate.

## Explicit non-claims

Biometrics and passkeys establish a device ceremony, not civil identity or
mental comprehension. Platform integrity is not proof that the entire device is
benign, that the displayed pixels were faithful, or that the approver perceived
the bound presentation. A valid approval is not a finding that an action is
lawful, safe, or wise. The reference apps are implementation examples, not
evidence of a state deployment or endorsement.

## Operational requirements

Production deployments should isolate keys, attestation verification, challenge
consumption, and audit writes into separately monitored services. Alert on
counter rollback, profile drift, repeated refusals, platform-verifier latency,
authorization-backend failure, and any protected executor call lacking a
consumed ceremony identifier. Rate-limit enrollment and ceremony endpoints by
principal, device enrollment, and network source.
