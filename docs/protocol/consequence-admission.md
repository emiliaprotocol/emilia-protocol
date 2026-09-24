# Consequence admission

This guide describes the proposed AEB-06 refinement and its reference
implementation. The current published AEB-05 still requires CAID matching and
AEC satisfaction. The staged -06 candidate makes those layers conditional and
has not been submitted or adopted.

Authorization answers whether an operation may proceed. Consequence admission
handles the narrower problem that begins after that answer: admitting one
provider attempt, surviving crashes and retries, and preserving an honest result
when the provider outcome is unknown.

EMILIA does not replace OAuth, AIMS, AuthZEN, COAZ, AP2, or a local policy
engine. Those systems remain authoritative for their own credentials, mappings,
and decisions. AEB applies the relying party's native decision at the protected
provider boundary.

```text
native identity, mandate, or permit
                |
                v
final receiver-observed operation
                |
                v
      [ AEB consequence admission ]
      exact-action check when needed
      stable native replay identity
      durable reserve before entry
                |
                v
           provider entry
                |
        +-------+--------+
        |       |        |
    executed  failed  indeterminate
                         |
                         v
             authenticated reconciliation
             (never a blind redispatch)
```

## Who owns what

| Layer | Responsibility |
| --- | --- |
| Native authorization system | Defines and verifies its credential or decision. With AuthZEN and COAZ, this includes mapping the operation into SARC, obtaining a decision, and enforcing the decision at the PEP. |
| CAID mapping profile | Compares material action meaning when independently encoded native representations must be joined. It is optional when the same PEP derives and enforces a current decision over the final operation without a cross-format join. |
| AEC requirement | Composes multiple evidence legs only when the relying party's policy requires them. A current native permit does not need a second policy engine merely to enter AEB. |
| AEB | Derives stable replay identity from native authority, reserves it in durable state, owns provider-entry custody, refuses blind retry after an uncertain result, and accepts only authenticated reconciliation bound to the same operation, action, and provider. |
| Provider | Performs the external effect and supplies whatever outcome or reconciliation evidence its native interface supports. AEB does not prove a physical effect from a local record alone. |

## When this profile is useful

Use consequence admission when an operation can create an external or
non-idempotent effect and at least one of these conditions applies:

- a transport retry could repeat the effect;
- more than one executor can race to dispatch the same authority;
- the provider can accept an operation before the caller receives a response;
- a crash can occur between reservation, provider entry, and outcome recording;
- the authorization and executable operation use different representations; or
- the relying party requires several independently verified evidence legs.

If one consequence-owning PEP obtains a current decision over the final
operation and the provider already offers sufficient atomic idempotency and
outcome recovery, AEB must not be presented as a mandatory second authorization
layer.

## Required lifecycle

1. Verify the native authorization under the native system's rules.
2. Bind it to the final operation. Use CAID only when a cross-format comparison
   is required; refuse or return `INDETERMINATE` when material meaning is lost.
3. Apply the relying party's local authorization decision. AEB records this
   result but does not make a universal policy decision.
4. Derive replay identity from the native authority, not from a fresh wrapper or
   transport nonce.
5. Reserve the operation and all native replay identities atomically in a
   shared durable state domain.
6. Record provider entry before treating the attempt as dispatchable elsewhere.
7. Record a terminal authenticated outcome, or keep the attempt
   `INDETERMINATE` and refuse redispatch.
8. Reconcile only with authenticated provider evidence bound to the same
   provider, operation, and material action.

The current reference implementation is the
[`consequence-boundary`](../../packages/gate/src/consequence-boundary.ts)
module. The open [AEB-1 conformance pack](../conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
tests the boundary as a self-run profile. A passing self-test is not proof of a
production deployment, complete mediation, independent interoperability, or a
provider effect.

The stable package entry points keep the native verifier and provider boundary
separate:

```js
import {
  verifyAebNativeAuthorizationHandoff,
} from '@emilia-protocol/verify/aeb';
import {
  createNativeConsequenceBoundary,
  createPostgresAebDurableConsumptionStore,
} from '@emilia-protocol/gate/aeb';
```

See the
[`AEB-NATIVE-AUTHORIZATION-HANDOFF-v1`](aeb-native-authorization-handoff-v1.md)
profile for the direct path. `createConsequenceBoundary()` remains the composed
path when the deployment needs CAID or AEC.
