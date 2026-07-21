<!-- SPDX-License-Identifier: Apache-2.0 -->

# Add Your Protocol to Receipt Required

Receipt Required has one narrow waist: a service describes the proof needed for
an exact action, carries that challenge through the surrounding protocol, and
accepts an EMILIA receipt only after native verification and exact CAID/action
binding. A binding profile describes carrier locations and field projection. It
does not add a new policy engine and does not make EMILIA a native verifier for
the surrounding protocol.

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
| A2A                        | `documented_profile`        | Carrier description plus synthetic fixture; no production A2A adapter or interoperability result is claimed.                                                         |
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
