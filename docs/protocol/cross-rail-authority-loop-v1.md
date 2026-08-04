<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cross-Rail Authority Loop v1

**Profile:** `EP-CROSS-RAIL-AUTHORITY-LOOP-v1`

**Status:** experimental EMILIA Gate implementation profile. It is not a
payment protocol, escrow service, bank, custodian, settlement network, or
merchant dispute rulebook.

## Purpose

This profile connects an exact-action authorization decision to one configured
payment connector without giving the agent a reusable provider credential.
Payment partners move money. EMILIA determines whether one exact transaction
may reach the configured partner.

```text
agent proposes provider request
            |
trusted connector projects exact action + provider request digest + CAID
            |
external policy/risk service selects standing policy or human interruption
            |
if required: separately verified exact human authorization
            |
current signed allowance + authorization receipt + atomic budget reservation
            |
Gate mints opaque short-lived rail-entry permit
            |
trusted connector consumes permit once, then calls the partner
            |
executed | refused | indeterminate -> minimized observation -> governed census
```

The policy or risk service does not authorize an action merely by deciding
whether to interrupt a human. The human artifact does not move money. The
permit does not prove available funds or provider acceptance. The provider's
result does not become effect truth merely because Gate recorded it.

## Artifacts

### Human-interruption decision

`EP-HUMAN-INTERRUPTION-DECISION-v1` is signed by a relying-party-pinned policy
or risk service. It binds:

- tenant, subject, connector, and CAID;
- the exact Gate action digest and provider-request digest;
- policy and evaluator-configuration digests;
- the closed decision `standing_policy` or `require_human`;
- bounded reason codes explaining why interruption was or was not selected;
- issue and expiry instants, with a maximum one-hour lifetime.

Its claim is only interruption selection. It does not establish identity,
authority, safety, payment, custody, settlement, refund eligibility, or effect.
It is a companion artifact; it does not add a field to `EP-RECEIPT-v1`.

### Rail-entry permit

`EP-RAIL-ENTRY-PERMIT-v1` is minted inside Gate only after the existing
allowance verifier has accepted the authorizing receipt, current allowance
status, exact action, target, amount, aggregate budget, and atomic reservation.
It binds:

- one connector instance, operation, CAID, action digest, and provider request;
- the authorization-receipt, allowance, and interruption-decision digests;
- the verified human-authorization digest when interruption was required;
- one short validity interval and `single_use: true`.

The caller receives neither the artifact nor a provider credential. It receives
only the final Gate result and permit digest. The opaque handle is consumed
inside the trusted connector immediately before provider invocation. A live
permit is never evicted to make room: capacity exhaustion refuses.

The reference broker is process-local by design. A process loss before provider
entry loses the permit while the durable allowance reservation remains fenced
for recovery. A loss after provider entry is `indeterminate` and cannot be
blindly retried. A distributed deployment may replace the broker only with an
equally fail-closed, atomic, bounded implementation.

## Human authorization

When the decision is `require_human`, Gate requires a deployment-pinned human
verifier to return all of the following from cryptographically checked source
evidence:

- `human_authorized: true`;
- artifact digest;
- interruption-decision digest;
- CAID;
- action digest; and
- provider-request digest.

A boolean approval is insufficient. The existing FIDO/AP2 bridge is one
eligible source for an AP2 payment because it independently verifies the
WebAuthn and native AP2 legs and requires both to map to the same action. Other
rails keep their native verifiers and semantics.

## Rail composition

The connector interface is deliberately narrower than any payment rail. A
trusted deployment supplies:

1. a closed provider-request projection;
2. a relying-party-pinned CAID resolver;
3. one typed provider invocation; and
4. the provider client and credential, retained inside the connector closure.

The current tests exercise Stripe-shaped and AP2-shaped connector instances.
That does not assert Visa, Mastercard, Google, Stripe, or any other provider has
adopted or endorsed this profile. Native rail authentication, mandates,
idempotency, KYC/AML, custody, settlement, refunds, chargebacks, and disputes
remain authoritative in the corresponding partner system.

## Minimized outcome observation

The optional observation callback receives only:

```json
{
  "@version": "EP-CROSS-RAIL-OBSERVATION-v1",
  "connector_class": "stripe",
  "action_class": "commerce.payment",
  "human_interruption": false,
  "outcome": "executed",
  "reason_class": "none",
  "occurred_at": "2026-08-03T18:00:00.000Z"
}
```

It omits amount, currency, counterparty, account, tenant, subject, operation,
CAID, credentials, signatures, and raw provider results. The callback cannot
rewrite the execution outcome. These minimized observations can feed the
existing governed Receipt Census, whose primary suppression and explicit claim
boundary still apply. They do not prove population completeness, causation,
loss, coverage, payment, or external effect.

## Visibility and optional transparency

Private operation and operator-independent publication are separate modes:

- Authenticated, tenant-scoped approval queues and receipt lists MAY enumerate
  records that the tenant is authorized to manage. They MUST remain tenant
  bound and cache-private. This profile does not prohibit the inboxes and audit
  views required to operate a Gate.
- The profile does not define a public, unauthenticated, cross-tenant feed,
  search index, or reputation registry. Private records remain unlisted by
  default.
- A tenant MAY explicitly publish a governed Receipt Census or another
  separately specified public artifact. Publication is opt-in and MUST NOT
  expose the opaque permit, provider credential, raw request, or private event
  fields defined by this profile.
- A published artifact SHOULD be anchored in an independent transparency
  service, such as a SCITT transparency service or an equivalent Rekor/DSSE
  deployment, instead of a log controlled solely by the EMILIA operator.

Raw per-action observations are not automatically published or anchored. The
governed aggregate or publication artifact owns its disclosure floor,
suppression rules, signature, and transparency receipt. External anchoring
proves registration and supports non-equivocation; it does not prove the
issuer's factual claim, authorization, payment, settlement, or effect.

## Refusal and uncertainty invariants

- No valid interruption decision: no reservation and no provider call.
- Human interruption selected but no exact human result: no reservation and no
  provider call.
- Stale allowance status, action splice, target splice, amount violation, CAID
  mismatch, request mismatch, or permit mismatch: no provider call.
- A permit is consumed once and cannot be replayed.
- A provider exception after entry records `indeterminate`; it is not treated as
  failure, success, or permission to retry.
- Provider credentials are never fields in the decision, permit, observation,
  allowance, capability receipt, or caller-facing result.

## Implementation

- `@emilia-protocol/gate/cross-rail-authority`
- `@emilia-protocol/gate/allowance`
- `@emilia-protocol/gate/fido-ap2-bridge`
- `@emilia-protocol/gate/receipt-census`
- `@emilia-protocol/gate/open-exposure-ledger`

This profile is a commercial integration surface over existing protocol
artifacts. It does not by itself require a new Internet-Draft or a change to the
base authorization-receipt schema.
