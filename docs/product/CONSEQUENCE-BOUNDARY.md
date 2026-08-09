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
5. Invoke a credential-owning provider adapter exactly once.
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

## Product boundary

The open layer is the protocol, adapters, verifier, and conformance suite. The
commercial layer can operate the policy/configuration plane, managed durable
stores, enterprise provider adapters, fleet reconciliation, and evidence
exports. Evidence and provider credentials remain in the customer's execution
domain; the managed plane distributes pins and policy but does not become the
universal authorization server.
