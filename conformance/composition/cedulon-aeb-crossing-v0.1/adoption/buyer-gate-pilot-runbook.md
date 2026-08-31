# Buyer-controlled Gate pilot runbook

This is a non-production acceptance plan. It does not authorize connection to
a live payment rail. The buyer owns the environment, keys, policies, provider
credentials, and durable database, and decides whether the pilot advances.

## 1. Freeze the pilot boundary

Record the exact repository commit, Cedulon source lock, adapter digest, Gate
build, buyer deployment ID, issuer key ID, status-service identity, provider
sandbox account, and policy revision. Permit only
`cedulon.payment.attempt.1` through one named executor. Keep provider
credentials outside agent and model processes.

The buyer must control:

- the configured Cedulon PDP trust root and its rotation/revocation policy;
- Gate authorization/signing keys and local admission policy;
- the database holding decisions, replay fences, provider-attempt state, and
  reconciliation evidence; and
- the provider credential and network route used by the mediated executor.

No token-carried key becomes a trust root. Status must come from an internal,
authenticated, buyer-controlled source. Record its observation time and
freshness limit. Revoked or consumed means reject; stale, unauthenticated,
unchecked, or unavailable means withhold provider entry.

## 2. Enforce the exact crossing

Before local authorization, verify and bind all six Cedulon request members:

| Native request | Exact action |
| --- | --- |
| `amount` | `amount` |
| `currency` | `currency` |
| `payee` | `payee` |
| `tool` | `tool` |
| `nonce` | `nonce` |
| `manifestHash` | `manifest_hash` |

Any missing, null, normalized, substituted, or extra material value is not the
reviewed action. Refuse it or return `INDETERMINATE`; never repair it silently.
`SATISFIED` alone is not provider-entry authority. Require a separate current
Gate authorization bound to the exact CAID/action digest, buyer deployment,
executor, provider account, policy version, and validity window.

## 3. Atomically create both fences and the attempt

In the buyer database, use the same database transaction to insert both unique
replay fences and the durable provider-attempt row in state `RESERVED`:

1. (`issuer_key_id`, `consumer_deployment_id`, `singleUseId`)
2. (`issuer_key_id`, `consumer_deployment_id`, `nonce`)

The attempt row must bind the issuer, deployment, both replay identities, exact
action digest/CAID, Gate authorization, executor, provider account, and a stable
provider operation ID. Commit the two fences and the `RESERVED` row together or
commit none of them. If either tuple already exists, deny entry. Concurrent
attempts must yield one winner at most.

Cedulon's allow is consumed on the first settlement attempt, including a
fail-closed abort. Once this transaction commits, both replay fences are
terminal and never released, including after `NOT_ENTERED`. Changing a wrapper,
request, process, response, or outcome cannot make either identity reusable.

## 4. Persist provider-attempt state before side effects

After the three-record transaction commits, durably transition the attempt from
`RESERVED` to `PROVIDER_ENTRY_STARTED` before any provider I/O, including DNS,
connection setup, SDK invocation, or request transmission. If that transition
cannot commit, perform no provider I/O. The Decision Token and both replay
identities remain consumed.

Terminal states are `EXECUTED`, `NOT_ENTERED`, and `INDETERMINATE`.
None releases either replay fence. A crash, timeout, lost response, or failed
post-effect commit after `PROVIDER_ENTRY_STARTED` becomes `INDETERMINATE`.
Reconciliation records what happened but never restores the consumed allow.
Every retry requires a newly issued Decision Token with fresh identities,
regardless of the prior terminal state.

## 5. Deny bypasses

Make the mediated executor the only process able to reach the provider sandbox
or read its credential. Deny direct SDK/API use by agents, models, web routes,
workers, and operators outside the named break-glass path. A request without a
current accepted profile result, current Gate authorization, both replay
reservations, and the durable attempt row must not cross the provider boundary.

Log bypass denials without recording secrets or raw payment credentials. Test
network policy and credential isolation, not only application routing.

## 6. Required acceptance tests

All tests run in the buyer sandbox and preserve database and provider evidence.

### Hostile input and status

- Substitute each of the six bound fields separately; every case is denied.
- Present a token-carried self-signed key and a non-empty actual COSE
  unprotected map; both are denied.
- Exercise expired, revoked, consumed, stale, unchecked, unauthenticated, and
  unavailable status. None may reach the provider.
- Present a Spend Receipt or Rail Extract in the Decision Token role; deny it.
- Attempt direct provider access without Gate; network and credential controls
  deny it.

### Atomic replay and concurrency

- Race two requests with the same `singleUseId` and different nonces; at most
  one enters.
- Race two requests with the same nonce and different `singleUseId` values; at
  most one enters.
- Race identical requests across two Gate processes; at most one enters.
- Change only the wrapper or process ID; neither replay fence is bypassed.

### Restart and uncertainty

- Restart after reservation but before provider entry. Recovery reads the
  durable row, keeps both fences, and does not create a second attempt.
- Restart after `PROVIDER_ENTRY_STARTED` but before provider response or local
  commit. Recovery reports `INDETERMINATE`, keeps both fences, and does not
  retry.
- Restart after each terminal state and confirm the state and fences survive.

### Reconciliation

- Accept reconciliation evidence only from an authenticated buyer-configured
  source and bind it to the same provider, provider operation ID, issuer,
  deployment, `singleUseId`, nonce, and exact CAID/action digest.
- Reject stale, partial, unsigned, mismatched, or non-final evidence.
- Prove that no reconciliation outcome, including authenticated final
  `NOT_ENTERED`, releases either replay fence or makes the Decision Token
  reusable.
- Prove that every retry uses a newly issued Decision Token with a fresh
  `singleUseId` and fresh nonce.

## 7. Exit evidence

A pilot is ready for external review only when the buyer returns: the pinned
configuration; test results; database uniqueness definitions; restart traces;
reconciliation evidence; network/credential bypass-denial evidence; and a
statement naming every untested path.

Even then, describe it as one buyer-controlled sandbox pilot. Do not call it a
Cedulon or EMILIA certification, general security proof, production deployment,
authorization standard, payment finality result, or legal/compliance opinion.
