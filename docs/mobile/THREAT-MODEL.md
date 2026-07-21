# Mobile Approval Threat Model

## Protected property

A relying party accepts a mobile approval or denial only when a pinned enrolled
credential completed user-verified WebAuthn over the exact action context, the
approved application produced independently verified integrity evidence bound
to that context, and the exact registered challenge was consumed once and
recorded durably. Challenge v2 includes the relying-party action reference,
server-computed CAID, and authoritative action digest in that signed context.
Authorization and execution remain separate: an authorized revision can affect
the protected system only after one atomic consequence-consumption transition.

## Refused attacker moves

| Attack | Enforcement |
|---|---|
| Agent changes material action fields | Recomputed action hash and signed context |
| Caller substitutes an action reference, CAID, or action digest | Server recomputes the exact-action identity and challenge v2 signs all three values |
| Network or presenter mutates the bound presentation bytes | Recomputed presentation hash inside the signed context |
| Presenter swaps origin or RP ID | Pinned WebAuthn origin and RP ID |
| Unenrolled key or app claims authority | Server-pinned enrollment and app allowlist |
| Bare P-256 signature replaces a passkey ceremony | Class-A WebAuthn verification with UP and UV |
| Client asserts its own integrity status | Independent App Attest or Play Integrity verifier |
| Platform token is replayed across actions | Exact attestation request hash |
| Android passkey is synced or replayed from a second device | Play-bound non-exportable Keystore public key plus a required per-ceremony key signature |
| Concurrent or later ceremony replay | Atomic body-bound challenge consumption |
| Operator consumes the same authority twice, reuses an operation ID, or squats another tenant's identifier | One operation per action revision, tenant-scoped operation IDs, a server-random consumption nonce, and unique constraints |
| Operator executes a superseded revision | Active-revision lock and refusal after supersession |
| Provider executes but the caller times out, then blindly retries | Durable `INDETERMINATE` state with `retry_safe=false`; no second consumption |
| Caller fabricates a terminal provider outcome or races executor-key rotation | Exact operation, CAID, digest, nonce, executor, and frozen-key binding; the commit transaction rechecks the exact active tenant pin and retains the signed evidence |
| Caller claims two systems mean the same action from labels alone | Positive equivalence requires native verification, a named hash-pinned mapping profile, and an evidence digest |
| Export leaks reusable passkey, platform, or provider evidence | Decision passport exports bounded metadata and evidence digests only |
| Approval is withdrawn after consequence authority is consumed | Withdrawal transaction locks the action group and refuses after consumption |
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
- The CAID wrapper identifies the exact authoritative action bytes supplied by
  that adapter. CAID does not prove those bytes are lawful, correct, equivalent
  to another system's object, authorized, or executed.
- The reference clients render every accepted field in the closed presentation
  schema. A fully compromised
  client can display one thing while signing and attesting another. Presentation
  hashing detects byte substitution, not dishonest pixels or semantic mismatch
  between the action and its presentation. This profile does not implement or
  claim [PIP-010 deterministic rendering](../../PIPs/PIP-010-wysiwys-execution-integrity.md).
- Clocks and durable stores meet the deployment's fault assumptions.
- The protected executor has no alternate path around the gate.
- Registered executor public keys are provisioned through a separately
  authenticated organization-admin ceremony and private signing keys remain
  under the provider's control.

## Explicit non-claims

Biometrics and passkeys establish a device ceremony, not civil identity or
mental comprehension. Platform integrity is not proof that the entire device is
benign, that the displayed pixels were faithful, or that the approver perceived
the bound presentation. A valid approval is not a finding that an action is
lawful, safe, or wise. The reference apps are implementation examples, not
evidence of a state deployment or endorsement.

`EXECUTED` means pinned provider evidence verified the exact consumed operation;
it is not an independent observation of the physical world. `REFUSED` is a
provider outcome, not permission to retry. `INDETERMINATE` deliberately makes
no terminal-outcome claim and forbids blind replay. A cross-system
`EQUIVALENT_UNDER_PROFILE` record is scoped to its named mapping profile and
evidence; it is not universal semantic equivalence.

## Operational requirements

Production deployments should isolate keys, attestation verification, challenge
consumption, and audit writes into separately monitored services. Alert on
counter rollback, profile drift, repeated refusals, platform-verifier latency,
authorization-backend failure, and any protected executor call lacking a
consumed ceremony identifier. Rate-limit enrollment and ceremony endpoints by
principal, device enrollment, and network source.

Also alert on action-identity mismatch, revision conflicts, duplicate
consumption, indeterminate operations that exceed the reconciliation objective,
executor-key rotation, failed provider signatures, and downgraded or
indeterminate cross-system alignments. Keep raw ceremony and provider evidence
in protected stores; expose only bounded event summaries and evidence digests
through mobile history and passports.
