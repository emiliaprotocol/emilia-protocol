<!-- SPDX-License-Identifier: Apache-2.0 -->

# Add Your Protocol to the Consequence Boundary

This guide describes AEB-07 and the repository's reference packages. AEB-07
was posted on 2026-09-25 as an individual Internet-Draft and is not adopted by
any working group. Like AEB-06, it makes the CAID stage conditional on a
cross-format join and the AEC stage conditional on a multi-leg evidence
requirement; the published AEB-05 required both.

Keep the protocol's native authorization model. EMILIA does not ask an OAuth,
AuthZEN, AP2, or local-policy implementation to replace its credential, mapping,
decision, or enforcement rules.

The useful integration starts after that native decision. AEB applies it to one
receiver-observed operation, derives stable replay identity from the native
authority, reserves before provider entry, and refuses blind redispatch if the
outcome is unknown. Read the
[consequence-admission boundary](protocol/consequence-admission.md) before
adding a format.

There are two integration paths:

1. **Native authorization into AEB.** Use this when the surrounding protocol
   already carries a permit, mandate, or policy decision. Preserve that object
   and its native verifier. Add CAID only if independently encoded
   representations must be compared. Add AEC only if the relying party needs
   several evidence legs.
2. **Receipt Required carrier.** Use this when a service must request and carry
   a new exact-action approval artifact. A binding profile describes the
   challenge, proof carrier, and field projection. It does not add a policy
   engine or make EMILIA the surrounding protocol's native verifier.

## Path A: bring an existing native decision

The minimum contribution is one pinned profile, a deterministic native
verifier or verifier result, and hostile lifecycle vectors. It must:

- preserve the native issuer, subject, audience, constraints, status, and
  decision reference where the native profile defines one;
- bind the final operation under the native mapping rules, using a CAID mapping
  profile only for a cross-format join;
- derive the replay unit from the native authorization occurrence rather than
  an AEB wrapper, request ID, or retry nonce;
- state which provider credential and execution paths the boundary controls;
- reserve before provider entry and allow at most one dispatch owner; and
- keep a post-entry timeout indeterminate until authenticated reconciliation
  establishes the same provider, operation, and material action.

The adapter never makes a second AuthZEN, OAuth, AP2, or local-policy decision.
It reports native verification and the information AEB needs to guard provider
entry.

Use the stable package entry points:

```js
import {
  verifyAebNativeAuthorizationHandoff,
} from '@emilia-protocol/verify/aeb';
import {
  createNativeConsequenceBoundary,
} from '@emilia-protocol/gate/aeb';
```

The [direct native handoff profile](protocol/aeb-native-authorization-handoff-v1.md)
defines the signed binding and execution order. The older
`evaluateAebEvidence()` and `createConsequenceBoundary()` path remains available
when a deployment actually needs a CAID cross-format join or an AEC multi-leg
requirement.

## Path B: add a Receipt Required carrier

Receipt Required has a narrower job: a service describes the proof needed for
an exact action, carries that challenge through the surrounding protocol, and
accepts an EMILIA receipt only after native verification and exact-action
binding.

The machine-readable contract is:

- [`bindings/receipt-required/registry.schema.json`](../bindings/receipt-required/registry.schema.json)
- [`bindings/receipt-required/registry.v1.json`](../bindings/receipt-required/registry.v1.json)
- [`conformance/vectors/receipt-required-bindings.v1.json`](../conformance/vectors/receipt-required-bindings.v1.json)
- [`tests/receipt-required-bindings.test.ts`](../tests/receipt-required-bindings.test.ts)

## What one profile costs

A new profile is one closed registry entry with these fields:

1. `protocol_id` and `protocol_version` identify the surrounding carrier.
2. `match_selector` gives one unambiguous discriminator for recognizing the
   carrier profile. Two entries may not claim the same selector.
3. `challenge_carrier` says where the Receipt Required refusal appears.
4. `proof_carrier` says where a retry presents the EMILIA proof.
5. `caid_extraction` names the exact JSON Pointer paths for CAID and action hash.
6. `required_field_mapping` projects every material action field from the
   surrounding object into the server-pinned CAID action type.
7. `conformance_vector_refs` names positive and fail-closed fixtures.
8. `implementation_status` and `claim_boundary` state what actually exists.

No executable adapter is required when the foreign protocol already has a typed
evidence slot. An adapter is appropriate only when code is needed to encode or
decode that carrier. In either case, the profile remains data: foreign native
verification, EMILIA receipt verification, CAID matching, local authorization,
and consequence execution are separate decisions.

## Security requirements

- Treat the registry as relying-party-pinned configuration. Do not accept a
  caller-supplied profile, selector, field mapping, or CAID definition.
- Reject unknown keys and ambiguous selectors. A permissive parser turns a
  profile into a policy-confusion surface.
- Project all required material fields before acquisition. A type-only receipt
  that omits amount, beneficiary, destination, or other required fields is not a
  receipt for the exact action.
- Recompute CAID and the action hash from the projected action. Never trust the
  strings carried by the foreign artifact on their own.
- Verify each foreign artifact under that protocol's native rules and
  relying-party-pinned trust before using its projected binding.
- A matching CAID proves content correlation only. It does not prove authority,
  execution, settlement, identity, safety, or adoption.
- A challenge is not a permission grant. The retry still passes through the
  normal receipt verifier, replay controls, capability budget, and consequence
  boundary.

## Current reference profiles

| Profile                    | Repository status           | Honest boundary                                                                                                                                                      |
| -------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HTTP 428                   | `experimental_reference`   | The shared core and experimental gateway exist; native wire-format interoperability and independent deployment verification are not claimed.                         |
| MCP                        | `documented_profile`        | Documented carrier mapping and synthetic vectors only; no native parser interoperability result, MCP project adoption, or certification is claimed.                  |
| A2A v1.0                   | `reference_implemented`     | `@emilia-protocol/verify/a2a-receipt-binding` implements the namespaced Message extension and signed receipt/Task correlation. The shared carrier fixture remains synthetic; external A2A adoption and independent interoperability are not claimed. |
| x402                       | `experimental_reference`    | Experimental 402-shaped proof rail; not monetary settlement and not an x402 adoption claim.                                                                          |
| AP2 evidence slot          | `synthetic_binding_profile` | Data-only synthetic slot showing where an `ep.authorization_receipt` could bind; no AP2 implementation, conformance, or live `PaymentIntent` integration is claimed. |
| WIMSE verification context | `verification_context_only` | Synthetic context showing composition with workload identity; identity does not authorize the action, and no WIMSE implementation or adoption is claimed.            |

## Submission checklist

Before adding a profile:

1. Choose a selector that cannot collide with an existing entry.
2. Define challenge and proof carrier locations without changing the foreign
   protocol's native trust rules.
3. Map every required field of one registered or locally pinned CAID action type.
4. Add an acceptance vector in which all carriers recompute to the same CAID and
   action hash.
5. Add at least CAID-substitution, action-hash-substitution, missing-binding, and
   missing-material-field negatives.
6. Mark foreign examples as synthetic until a real implementation is tested by
   its independent operator.
7. Run:

   ```sh
   npx vitest run tests/receipt-required-bindings.test.ts
   ```

Passing this suite proves the profile's closed data contract and deterministic
binding logic. It does not certify the foreign protocol, its implementation, or
an external deployment.

## Test the full consequence boundary

A Receipt Required carrier profile only proves that the challenge and proof can
be transported and rebound to the exact action. To test the larger execution
boundary—native verification, relying-party acceptance, CAID/action matching,
evidence satisfaction, atomic one-time reservation, dispatch uncertainty, and
authenticated reconciliation—run the open
[`AEB-1 Consequence Admission Conformance`](conformance/AEB-1-CONSEQUENCE-ADMISSION.md)
pack.

The two suites are complementary. A carrier can pass Receipt Required and still
fail AEB-1 if it treats native verification as local authorization, cannot fence
replay before dispatch, or permits blind retry after an unknown effect.
