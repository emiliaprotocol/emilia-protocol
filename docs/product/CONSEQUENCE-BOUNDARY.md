# EMILIA Consequence Boundary

The winning product surface is one executor-side boundary, not one more
authorization format.

The boundary receives the exact provider action and native evidence from AP2,
OAuth, WIMSE, an EMILIA receipt, or another relying-party-approved system. It
then performs the same six operations for every source:

1. Freeze the provider-native action and bind it to a CAID.
2. Verify each native artifact with a relying-party-pinned adapter.
3. Apply the relying party's AEC evidence requirement and local policy.
4. Durably reserve the operation and every native replay unit before dispatch.
5. Invoke a credential-owning provider adapter at most once for the admitted
   attempt. The boundary derives one provider idempotency key from the exact
   action, authorization instance, and provider domain and passes it unchanged
   to the adapter; this does not claim exactly-once physical effect.
6. Record `EXECUTED`, `FAILED`, or `INDETERMINATE`; never infer failure from a
   timeout and never blindly replay an indeterminate attempt. A separate,
   authenticated custody-recovery path may reconcile the attempt later from
   provider-native evidence without resurrecting the original authority.

`@emilia-protocol/gate/consequence-boundary` is the neutral library facade for
that lifecycle. It does not acquire approval, mint a receipt, replace a native
mandate, or decide that one evidence role is always human. The relying party
pins the required roles. A payment profile may require an AP2 mandate plus a
human artifact; a workload profile may require WIMSE possession plus a policy
decision; another deployment may require only its own native authority object.
`EP-AUTHORIZATION-BUNDLE-v1` can supply the human-evidence leg without changing
this executor API. Its optional OAuth/RAR projection remains a separate native
profile; the boundary never treats OAuth as the universal trust model.

## Stable integration contracts

- **Action mapping:** provider request to frozen action and CAID.
- **Evidence adapters:** native artifact to verified, bounded facts.
- **Requirement and policy:** which evidence roles must be present and whether
  this relying party authorizes the exact effect.
- **Admission custody:** owner-fenced durable reservation and replay fencing.
- **Effect adapter:** provider invocation plus authoritative terminal evidence.

The provider adapter may report `FAILED` only with authenticated evidence that
the protected effect did not occur. Exceptions, timeouts, malformed responses,
and missing evidence become `INDETERMINATE`. Both `EXECUTED` and authoritative
`FAILED` burn the one-time authorization: a later attempt needs a new action
instance and fresh authority.

## Provider idempotency binding

For each admitted attempt, the boundary derives a canonical, domain-separated
`provider_idempotency_key` over the tenant, provider, provider account,
environment, CAID, exact-action digest, and AEB `consumption_nonce`. The key is
stored in the owner-fenced attempt record, bound into the request digest,
presented to the provider adapter, and recomputed before reconciliation. It is
therefore one identity for dispatch and later lookup, rather than a caller-
selected retry hint.

The key upgrades the provider-side guarantee only when a pinned adapter profile
establishes all of the following properties for that provider operation:

- native duplicate suppression under the exact key;
- a key scope covering the pinned provider account and environment;
- refusal when the same key is reused with different request parameters;
- retention at least as long as the allowed reconciliation horizon; and
- authenticated lookup or reconciliation by the same key.

Without those properties, the key is a correlation handle only. EMILIA still
guarantees one admitted provider attempt under complete mediation and preserves
`INDETERMINATE`; it does not claim provider-side deduplication. A new
authorization instance derives a new key and MUST NOT be issued merely as a
blind retry of an unresolved attempt.

## Product boundary

The open layer is the protocol, adapters, verifier, and conformance suite. The
commercial layer can operate the policy/configuration plane, managed durable
stores, enterprise provider adapters, fleet reconciliation, and evidence
exports. Evidence and provider credentials remain in the customer's execution
domain; the managed plane distributes pins and policy but does not become the
universal authorization server.
