<!-- SPDX-License-Identifier: Apache-2.0 -->
# FIDO/AP2 Consequence Bridge Profile v1

**Profile:** `EP-FIDO-AP2-CONSEQUENCE-BRIDGE-v1`

**Status:** experimental EMILIA implementation profile for one immediate
payment in one tenant deployment boundary. This is a closed subset, not an
extension to AP2 or WebAuthn.

## 1. Purpose and consequence boundary

The profile composes two separately verified evidence legs for one exact AP2
v0.2 payment action:

1. an authoritative native AP2 result for a closed `CheckoutMandate` and
   `PaymentMandate`; and
2. an RP-pinned WebAuthn assertion by a named human over a human-readable
   disclosure and exact source, action, operation, and provider commitments.

The two legs must independently map to the same CAID and normalized-action
digest. A signed AEB evaluation may then report `SATISFIED`. Gate still needs
matching qualification, AEC, and local-policy legs. Only a successful
AdmissionStore transaction reserves and later consumes authority.

```text
native AP2 VERIFIED ----+
                         +-- signed AEB SATISFIED -- local AUTHORIZED
human WebAuthn VERIFIED -+                              |
                                                AdmissionStore reserve
                                                         |
                                        beginInvocation recheck + consume
                                                         |
                                                  provider adapter entry
                                                         |
                            provider commitment ---- observed effect
                                      \                 /
                                       authenticated reconciliation
```

`VERIFIED`, `ACCEPTED`, `MATCH`, `SATISFIED`, `AUTHORIZED`, `RESERVED`,
`INVOKING`, provider `COMMITTED`, and an observed effect are different states.

## 2. Normative pins

This implementation profile travels with the versioned EMILIA Verify and Gate
package source that contains it; an older repository baseline is not evidence
that the bridge exists. Its external protocol semantics are pinned to:

- the official
  [`google-agentic-commerce/AP2` commit
  `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`](https://github.com/google-agentic-commerce/AP2/tree/e1ea56db72a6385bce3e5c1112b3a56ce60acb43),
  including its v0.2 generated `CheckoutMandate` and `PaymentMandate` models
  and `SdJwtMandate.serialized` representation; and
- [W3C Web Authentication Level 3, Candidate Recommendation Snapshot,
  26 May 2026](https://www.w3.org/TR/2026/CR-webauthn-3-20260526/).

The strict AEB JSON domain uses RFC 8785 canonicalization. A different AP2
revision, a moving `main` branch, a future WebAuthn revision, or a new member
is not accepted by implication.

## 3. Native AP2 authority and closed subset

The native AP2 verifier remains authoritative. The bridge neither replaces
nor approximates AP2 verification. Before issuing the native attestation, the
deployment's native AP2 verifier is responsible for all AP2 cryptographic and
protocol checks, including:

- verification of each mandate SD-JWT and any AP2-required issuer, holder,
  audience, nonce, delegation, disclosure, time, and key binding;
- verification of the merchant-signed `checkout_jwt` JWS and that it denotes
  the current checkout accepted for this transaction;
- recomputation and validation of `checkout_hash` under the AP2 rules; and
- validation that `PaymentMandate.transaction_id` links to that exact
  checkout and that the two mandates form one valid AP2 payment chain.

The native verifier emits a signed
`EP-AEB-NATIVE-VERIFICATION-ATTESTATION-v1`. Its protocol identifier is
`ap2:v0.2-closed-checkout-payment`. The attestation binds the native artifact
digest, native artifact reference, audience, verifier subject, verification
and expiry instants, evidence role, mapping profile, mapper, resolver, CAID,
normalized-action digest, signature key, and signature.

After native verification, this bridge accepts only this additional closed
projection:

- exactly one `CheckoutMandate` with the exact members `vct`, `checkout_jwt`,
  `checkout_hash`, `iat`, and `exp`;
- exactly one `PaymentMandate` with required members `vct`, `transaction_id`,
  `payee`, `payment_amount`, `payment_instrument`, `iat`, and `exp`, and only
  the AP2-defined optional members `pisp` and `risk_data` when they carry
  their schema-defined object values;
- `vct` values `mandate.checkout.1` and `mandate.payment.1`;
- a compact three-segment `checkout_jwt`, a base64url `checkout_hash`
  computed with the native verifier's authenticated `_sd_alg` (`sha-256`,
  `sha-384`, or `sha-512`, with absent `_sd_alg` normalized to `sha-256`),
  and exact equality of `transaction_id` and `checkout_hash`;
- a positive safe-integer amount in minor units and an uppercase three-letter
  currency;
- closed merchant, PISP, amount, and payment-instrument member sets;
- omitted `execution_date`, which AP2 v0.2 defines as immediate execution;
- positive `iat` and `exp` values with `iat < exp` for both mandates.

`CartMandate`, open mandates, recurrence, scheduled execution, mandate
chains, multiple payments, extra members, and future versions fail closed.
The projection's syntactic and linkage checks are defense in depth; they do
not turn the bridge into the authoritative AP2 verifier.

## 4. Exact canonical AP2 token commitments

The server supplies the exact canonical `SdJwtMandate.serialized` string and
the disclosure-resolved payload that the same native AP2 verification
accepted for each mandate. The bridge accepts one
printable-ASCII SD-JWT token per mandate. It rejects `~~` delegation chains,
empty or malformed disclosures, non-canonical base64url, whitespace, and
ambiguous concatenations. The token is never reconstructed from a parsed
object.

For label `L` and exact ASCII token bytes `T`, the commitment is:

```text
sha256:
  HEX(SHA-256(
    UTF8("EP-FIDO-AP2-CANONICAL-TOKEN-v1") || 0x00 ||
    UTF8(L) || 0x00 ||
    ASCII(decimal(byte_length(T))) || ASCII(":") || T
  ))
```

The labels are exactly `checkout-mandate-token` and
`payment-mandate-token`. The resulting fields are
`checkout_mandate_token_digest` and `payment_mandate_token_digest`.
The strict AEB digests of the two native-verifier-returned payload objects are
`checkout_mandate_payload_digest` and `payment_mandate_payload_digest`.
Projection fails closed unless each supplied projection object has exactly
the corresponding authenticated payload digest. This prevents valid token
bytes from being spliced onto a different amount, payee, instrument, or
checkout object.

The native artifact digest is the strict AEB digest of exactly:

```json
{
  "source_revision": "google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
  "checkout_mandate_token_digest": "sha256:<64 lowercase hex>",
  "payment_mandate_token_digest": "sha256:<64 lowercase hex>",
  "checkout_mandate_payload_digest": "sha256:<64 lowercase hex>",
  "payment_mandate_payload_digest": "sha256:<64 lowercase hex>",
  "checkout_hash_algorithm": "sha-256 | sha-384 | sha-512"
}
```

A representation change is a different source. Gate recomputes these
commitments from server-owned tokens and requires exact equality with the
human artifact, native attestation, normalized action, and AEB legs.

## 5. Normalized action and human disclosure

The CAID action type is `payment.purchase.1`. The closed normalized action has
exactly these fields:

```json
{
  "action_type": "payment.purchase.1",
  "checkout_mandate_digest": "sha256:<checkout token commitment>",
  "payment_mandate_digest": "sha256:<payment token commitment>",
  "checkout_payload_jwt_digest": "sha256:<domain-separated exact JWS bytes>",
  "transaction_id": "<checkout_hash>",
  "amount_minor": 12550,
  "currency": "USD",
  "payee_id": "merchant:acme",
  "payee_name": "Acme Industrial",
  "payee_website_digest": "sha256:<digest of value or null>",
  "pisp_digest": "sha256:<digest of value or null>",
  "payment_instrument_id": "instrument:card-7",
  "payment_instrument_type": "CARD",
  "payment_instrument_description_digest": "sha256:<digest of value or null>",
  "risk_data_digest": "sha256:<digest of value or null>",
  "execution": "immediate",
  "source_expires_at": "2026-07-31T18:04:00.000Z"
}
```

No material field is declared omitted under the mapping profile. Optional AP2
values are represented by deterministic digests of the value or `null`.
`source_expires_at` is the earlier of the CheckoutMandate and PaymentMandate
expiry instants.

The artifact also carries a bounded human-facing disclosure with exactly:

```text
checkout_commitment | payment_commitment | checkout_payload_jwt_commitment
| transaction_id | amount_minor
| currency | payee_id | payee_name | payment_instrument_id
| payment_instrument_type | execution | source_expires_at
```

Each disclosure field must equal the corresponding normalized-action field.
The disclosure is shown to the human before the ceremony, and its strict AEB
digest is included in the signed context. A valid signature proves only that
the pinned credential signed that exact context; it does not prove that the
human read, understood, or legally consented to it.

## 6. Closed WebAuthn human leg

`EP-FIDO-AP2-EVIDENCE-v1` contains commitments and the normalized action, not
raw AP2 mandates. Its signed context binds exactly:

```text
source revision | tenant | relying party | audience | operation
| provider-request digest | provider ID | provider account | environment
| both AP2 token commitments | native-attestation digest
| normalized-action digest | CAID | disclosure digest
| approver ID | RP nonce | authorization expiry
```

The WebAuthn challenge is the unpadded base64url SHA-256 of the UTF-8 RFC 8785
canonical signed context.

The closed human leg requires:

- one RP-pinned active P-256 public key and credential ID;
- ES256 verification over `authenticatorData || SHA-256(clientDataJSON)`;
- exact `clientDataJSON.type == "webauthn.get"`, challenge, allowed HTTPS
  origin, and no cross-origin assertion;
- exact RP-ID hash;
- exactly 37 authenticator-data bytes: 32-byte RP-ID hash, one flags byte,
  and four-byte big-endian `signCount`;
- UP and UV set, no unsupported flag bits, and no authenticator extensions or
  attested-credential data;
- relying-party-pinned backup-eligibility and backup-state policy; and
- one relying-party-pinned counter policy:
  - `above-enrollment-and-one-time` requires `signCount` strictly above both
    the enrolled count and the server-owned current counter head; or
  - `not-relied-upon` permits a zero counter for platform passkeys and makes no
    clone-detection or monotonicity claim from `signCount`.

The RP owns the source revision, tenant, relying party, audience, action type,
RP ID, origins, nonce, approver and credential identity, public key, key
status, enrolled counter, backup policy, maximum status age, mapper/profile,
and trust roots. Artifact-selected trust is ignored or refused.

The derived WebAuthn replay unit includes the exact operation, request,
provider, approver, credential, nonce, and context digest. AdmissionStore also
reserves a replay resource derived from the credential, accepted count,
artifact digest, and AEB replay unit. Under
`above-enrollment-and-one-time`, it additionally reserves one durable
`monotonic_counter` resource keyed only by relying party and credential. At
reservation, that
resource atomically compares the server-owned expected head and advances it to
the signed count. The head MUST already have been provisioned from an
authenticated enrollment or recovery ceremony; an absent head fails closed
and an admission artifact cannot create or replace its own baseline. Invocation
rechecks that the durable head is at least the reserved next value. The advance
commits atomically with a successful reservation; if reservation fails, neither
the admission nor the new head exists. Release, expiry, and reconciliation do
not lower a committed head. Skipped values are safe, while reuse or rollback is
refused. Counters remain clone signals, not proof of authenticator uniqueness.
Under `not-relied-upon`, no monotonic-counter resource is emitted and a zero
counter is not interpreted as evidence of either uniqueness or cloning. The
exact assertion, AP2 tokens, operation, and provider entry remain independently
replay-fenced and one-time admitted. A platform passkey may use Face ID for the
WebAuthn user-verification ceremony; this profile does not claim that the
credential private key is itself a Secure Enclave key.

## 7. Server-owned provider-request binding

The request does not supply the authoritative clock, configuration, status,
actors, provider adapter, AP2 source tokens, or provider bytes. Gate receives
all of these through `FidoAp2TrustedAdmissionControls`:

```text
clock | pinned AEB configuration | current-status resolver
| tenant | relying party | audience | operation | initiator | executor
| provider ID/account/environment | Gate trust digest
| executor-adapter digest | exact CheckoutMandate token
| exact PaymentMandate token | both verified mandate payloads
| current WebAuthn counter head
| exact provider-request bytes
| pinned provider-request verifier
```

The checkout hash algorithm is not a separate trusted control. The bridge
derives it from the exact CheckoutMandate issuer JWT's authenticated `_sd_alg`
claim, defaulting to `sha-256` when that claim is absent.

Gate independently projects the normalized action from the exact
native-verifier-returned mandate payloads and source binding supplied through
the trusted controls. The action digest in the Gate binding, human artifact,
and AEB record MUST equal that independently projected digest. A signed claimed
action therefore cannot substitute a different amount, payee, instrument, or
transaction even if a pinned native-attestation issuer repeats the bad claim.

For exact request bytes `R`, Gate computes:

```text
sha256:HEX(SHA-256(
  UTF8("EP-FIDO-AP2-PROVIDER-REQUEST-v1") || 0x00 ||
  ASCII(decimal(byte_length(R))) || ASCII(":") || R
))
```

That digest must equal the effect-request digest in the human artifact and
signed context, whose digest is carried by the human AEB leg, and must also
equal the Gate binding, qualification protected-request binding, and
AdmissionStore snapshot.

The pinned provider-request verifier's implementation digest must equal the
executor-adapter digest. On a cloned byte array it receives the exact request
bytes, exact canonical PaymentMandate token, its token commitment, and the
server-owned provider tuple. It must return exactly `true` and must not mutate
the bytes. This adapter-specific check establishes that the exact payment
token is embedded in or otherwise unambiguously bound to the exact provider
request. The generic bridge does not guess provider serialization.

## 8. Full AEB record and current-status binding

Gate accepts only a signed `AEB-EVALUATION-v1` record with verdict
`SATISFIED`, no reasons, and exactly two accepted, verified, matching legs:
`ap2-native-authorization` and `human_authorization`.

The complete record is re-verified in execution mode at the server-owned
admission time against the pinned configuration, exact native attestation,
exact human artifact, exact normalized action, and newly resolved statuses.
The signed evaluator identity/key/configuration, record signature, operation,
consumption nonce, initiator, executor, requirement and registry bindings,
CAID, evidence digest, composition, authority constraints, evaluation time,
and every leg's adapter, version, profile, artifact, evidence/status digest,
subject, mapper, resolver, replay unit, action digest, CAID, verdict, and
freshness are part of the verified record.

The composition must be exactly:

```text
ap2-native-authorization AND human_authorization
```

Initiator exclusion, executor exclusion, and one-time consumption must all be
true. The two legs must have distinct adapters and artifact references and
the same CAID and normalized-action digest. Historical verification is not
execution-authorizing.

Gate inserts one AEB AdmissionInput itself. Its `payload_digest` is the strict
digest of the complete signed AEB evaluation record, not a caller boolean or
detached summary. The input also binds the requirement digest, relying-party
verifier, pinned-configuration digest, subject, and earliest applicable
expiry. The complete AEB record digest and consumption nonce also enter the
replay, monotonic-counter, and provider-operation commitments. Authenticated
status leases retain their own narrower authority/artifact/sequence/head/expiry
commitments and remain independently rechecked at invocation.

The server resolver must return exactly two authenticated current-status
statements, one for each AEB artifact reference. Each statement is matched to
the signed evidence digest and replay unit and contains an authority ID,
nonnegative sequence, authenticated head digest, and current status. Gate turns
each head into a distinct `external_lease` reservation. Both lease expiries
must cover admission. AdmissionStore rechecks their currentness before entry;
one missing, duplicated, stale, revoked, consumed, unavailable, mismatched,
or changed head refuses admission or invocation.

## 9. AdmissionStore is the sole authority-custody boundary

The bridge functions are synchronous pure builders. They do not reserve
authority, hold credentials, invoke a provider, record an outcome, or
reconcile an effect. Presenter-selected replay IDs, reservation IDs, status,
clock, actors, provider identity, source bytes, or adapter identity never
become authoritative.

The builder derives exactly:

- one replay resource for the canonical CheckoutMandate token;
- one replay resource for the canonical PaymentMandate token;
- one replay resource for the WebAuthn assertion;
- one monotonic-counter resource for the RP/credential pair;
- one provider-operation resource for the exact operation; and
- two authenticated status-head external leases.

Gate Qualification v2 must bind qualification, AEB, AEC, and local policy to
the same admission snapshot. AdmissionStore is the sole authority-custody and
one-time boundary. `reserve()` transfers the exact rights into custody.
`reserve()` also atomically compares and advances the credential counter in
the same authoritative state domain as the other admission resources.
Immediately before provider entry, `beginInvocation()` atomically rechecks
expiry, currentness, and the persisted counter head, then consumes the
operation and every replay/lease/counter right. The protected adapter receives
only the frozen snapshot after that transaction succeeds.

## 10. Provider commitment, effect, and reconciliation

Provider commitment and observed effect remain independent axes. An
authenticated provider result may establish `COMMITTED` or
`PROVEN_NOT_COMMITTED`; separately authenticated observation may establish
`OBSERVED_AS_REQUESTED`, `DIVERGED`, or remain `INDETERMINATE`. For example,
`COMMITTED` plus `DIVERGED` is valid and must not be collapsed into success.

If `beginInvocation()` may have succeeded, or provider entry is followed by a
timeout, response loss, crash, or conflicting evidence, the operation becomes
`INDETERMINATE`. Authority and replay resources remain consumed. Only
authenticated reconciliation bound to the exact operation, request, provider,
adapter, and idempotency identity may refine the record. Reconciliation is an
evidence read; it must not retransmit the payment request.

There is no blind retry after ambiguity. Even authenticated proof that the
provider did not commit does not recreate consumed authority: another attempt
requires a new admission. Refund, cancellation, or remedy is a new exact
action with its own authority.

## 11. Honest limits

This v1 profile is limited to one tenant per deployment boundary and one
immediate payment in the pinned closed subset. It makes no claim of:

- a final FIDO Verifiable Intent standard, FIDO certification, authenticator
  certification, or general WebAuthn conformance;
- AP2 certification, complete AP2 implementation, or interoperability beyond
  the pinned official commit and closed subset;
- legal consent, capacity, identity proofing, authority under law, payment-
  network authorization, regulatory compliance, or liability allocation;
- provider receipt, provider commitment, observed business effect, delivery,
  settlement, charge finality, dispute outcome, or global exactly-once
  execution; or
- shared-database multi-tenant isolation, federated atomicity, complete
  mediation, production key custody, or production deployment correctness.

Deployments still need governed credential enrollment/recovery/revocation,
native AP2 key resolution, merchant and provider trust, protected provider
credentials, complete mediation, durable AdmissionStore configuration,
authenticated status/effect sources, monitoring, retention, privacy, and
operator reconciliation procedures.

## 12. Conformance evidence

[`conformance/vectors/fido-ap2-bridge.v1.json`](../../conformance/vectors/fido-ap2-bridge.v1.json)
is a deterministic semantic corpus, not an executable AP2, FIDO, WebAuthn,
merchant-JWS, payment-provider, or authenticator vector suite. Every vector
that claims executable coverage names the repository test file and exact test
title that exercises it. The corpus does not convert an unexecuted descriptor
into evidence.

The corpus is validated against the independently stored, closed
[`fido-ap2-bridge-semantic-corpus.v1.schema.json`](../../conformance/schemas/fido-ap2-bridge-semantic-corpus.v1.schema.json).
Schema validity does not change the semantic-only claim boundary above.

The AP2/WebAuthn bridge tests use generated P-256 assertions and synthetic
SD-JWT/JWS-shaped fixtures; they do not use official AP2 conformance vectors,
a real authenticator, merchant production keys, or a live payment provider.
Generic AdmissionStore tests cover the one-time and post-entry state machine,
not AP2 interoperability. Passing tests establish bounded same-repository
consistency only.
