<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recovery Admission v1 threat model

## Security objective

Recovery classification must never create authority. It selects the enforcing
path for an already-authorized exact action and preserves uncertainty after
provider entry. A weaker recovery class, stale reservation, or recovery worker
cannot reopen consumed authority.

## Adversaries

- a presenter who can replay, mutate, downgrade, or cross-bind a signed
  capability;
- an adapter that lies about its transaction or external-effect boundary;
- a compromised recovery worker attempting a second provider invocation;
- a tenant attempting to bind another tenant's reservation or remedy;
- a provider that commits after a timeout or returns an ambiguous response; and
- process, network, or database failure at every acknowledgement boundary.

## Invariants

1. The relying party derives the recovery class from local policy. The signed
   capability must exactly match the ordinary Admission Store snapshot,
   tenant, action, CAID, operation, provider,
   account, environment, adapter, resources, policy snapshot, trust epoch, and
   configuration epoch.
2. `LOCAL_ATOMIC` is valid only when every protected effect is inside one
   transaction owned by the executor. Preventing remote calls is a deployment
   requirement enforced with process isolation, scoped credentials, database
   roles, and egress controls; the JavaScript callback contract cannot prove it.
3. Only `RESERVED` plus authenticated final evidence of no provider entry may
   become released.
4. Once execution authority is consumed, it never becomes reserved or released.
5. Compensation is a fresh admission with a new operation, action/CAID,
   authority, resources, and evidence. The original record is immutable.
6. Unknown reserve, begin, commit, rollback, provider, or terminal
   acknowledgements never authorize an invocation or retry.
7. `INDETERMINATE` remains closed until authenticated evidence bound to the same
   tenant, provider, account, environment, operation, and action resolves it.
8. The reference remedy bridge exposes no provider operation. A deployment must
   separately ensure that recovery workers possess no provider credential or
   alternate egress path.
9. Recovery classification never substitutes for ordinary authorization. The
   executor consumes the exact pre-existing Admission Store reservation before
   entering its transaction or provider.

## Claims prohibited by the profile

- A reservation is not proof that compensation occurred.
- A saga is not an atomic rollback.
- A provider-entry record proves the executor crossed its custody boundary; it
  does not prove the provider received or committed the request.
- A timeout or negative lookup is not proof of non-entry.
- A successful local rollback proves only that the protected mutation in that
  transaction did not commit.

## Required hostile cases

- signed class downgrade and cross-class replay;
- tenant, provider-account, environment, policy-epoch, adapter, and resource-set
  substitution;
- process death before and after each durable transition and acknowledgement;
- release/reaper racing provider entry;
- stale, non-final, wrong-account, or late-invalidated negative evidence;
- compensation expiry, replay, failure, and indeterminate compensation;
- rollback failure and ambiguous commit acknowledgement; and
- malicious recovery code attempting provider entry.

The PostgreSQL callback contract cannot sandbox arbitrary in-process
JavaScript. A hostile or misconfigured adapter that performs external effects
is therefore a deployment-boundary adversary; passing the scaffold's marker
booleans is not proof of confinement.

Every regression test must have a negative control: weakening the discriminator
that prevents the attack must make at least one test fail.
