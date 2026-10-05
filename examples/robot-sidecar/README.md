# EMILIA Gate — robot/actuator edge sidecar

The Consequence Firewall at the **actuator boundary**, for the physical world. A human (or quorum)
**pre-authorizes a bounded on-the-loop envelope** once (PIP-013): target set, allowed actions,
bounds (e.g. reach), time window, with a halt/revoke authority. Each motion command is then checked
**at the edge, offline, with no cloud, no per-command human, and no consumption** of the envelope.
Out-of-envelope, malformed, expired, or revoked → the actuator does not move.

```bash
npm run test:robot-sidecar   # from the repo root; also runs in CI on Node 20
node demo.mjs                # refuse -> authorize envelope -> in-bounds moves -> out-of-bounds/wrong-action/halt/expired refused
```

`index.js`, `sidecar.test.js`, and `demo.mjs` are generated from the `.ts`/`.mts` sources by
`npm run build:standalone-runtimes`; edit the TypeScript, then regenerate.

## Why a sidecar, not the model

It sits *before* the actuator. A compromised, prompt-injected, or confused planner still cannot move
hardware outside the authorized envelope, provided the sidecar is the only path to the actuator.
This example does not establish that (see "Not enforced" below).

## What the check enforces

`authorizeEnvelope(receipt)` loads an envelope only when:

- the receipt verifies under `trustedKeys` (Ed25519, via `packages/require-receipt`), its outcome is
  `allow` or `allow_with_signoff`, and its `action_type` is `physical.envelope`;
- `receipt_id` is a non-empty string that this gate instance has not revoked;
- `allowed_actions` is a non-empty list of distinct strings (an envelope that names no actions is refused,
  not read as "any action");
- `window.not_after` is a finite number (no open-ended envelopes); `not_before`, if present, is finite
  and not after `not_after`;
- `target_set`, if present, is a non-empty list of distinct strings; `bounds`, if present, holds only
  `max_reach_cm` as a finite, non-negative number;
- the scope contains no key the gate does not understand. An unknown constraint (say `geofence`) or
  bound (say `max_speed_cm_s`) is refused with `envelope_unsupported_constraint` /
  `envelope_unsupported_bound`, because the gate could not enforce it.

The loaded scope is copied and frozen, so mutating the receipt object afterwards does not widen it.

`permit(command)` returns `{ allow: true, reason: 'within_envelope', command }` only when every check
passes; `command` is a frozen snapshot of what was checked, and `SimulatedArm` actuates from that
snapshot. Every refusal is a return value `{ allow: false, reason[, field] }`, never a thrown exception:

| Class | Reason codes |
| --- | --- |
| Gate state | `no_envelope`, `revoked`, `clock_unavailable`, `before_window`, `expired` |
| Command shape | `command_not_plain_object` (null, arrays, primitives, class instances), `command_accessor_field`, `command_symbol_field`, `command_unreadable` |
| Extra fields | `unknown_command_field` for any field the envelope does not constrain, unless it is listed in `allowed_command_fields`; listed extras must be strings, booleans, or finite numbers (`invalid_extra_field_value`) |
| `action` | `missing_action`, `invalid_action` (not a non-empty string), `action_not_in_envelope` |
| `target` (when `target_set` is set) | `missing_target`, `invalid_target`, `out_of_target_set` |
| `reach_cm` (when `max_reach_cm` is set) | `missing_reach_cm`, `invalid_reach_cm_type` (strings, null, booleans, arrays, objects, bigint), `reach_cm_not_finite` (NaN, ±Infinity), `reach_cm_negative_zero`, `reach_cm_negative`, `exceeds_bounds` |

A field the envelope constrains must be present: a command that omits `target` or `reach_cm` is
refused, not waved through. `reach_cm` is itself an unknown field when the envelope sets no
`max_reach_cm`. The pattern follows `checkOrderWithinEnvelope` in `lib/grace/curtailment.ts`: a
missing or unparseable bound or value is a refusal, never an unlimited default.

Revoking halts the current envelope, and re-presenting that same signed receipt is refused
(`envelope_revoked`); a new envelope with a different `receipt_id` is a new signoff and loads.

## Not enforced

- **Revocation is in-memory and unsigned.** `revoke()` sets state on one gate instance. It is not a
  signed revocation, it is not shared between gates, and it does not survive a restart: a fresh
  process will load the same unexpired envelope again.
- **Nothing attests that the sidecar is running** or that it is the only path to the actuator. The
  Attested Gate (device/workload attestation, e.g. WIMSE/SPIFFE) is not built.
- **No hardware adapters.** `SimulatedArm` is a toy; there is no driver integration.
- The gate trusts its clock (`now`). It refuses a non-finite clock value but cannot detect a wrong one.
- The envelope is not bound to a specific planner identity beyond what the signed receipt carries;
  any caller that can reach `permit` is checked against the envelope, not authenticated.
- Only `reach_cm` is a modeled bound. Envelopes that need other physical limits are refused rather
  than partially enforced.

## API

- `new EdgeActuatorGate({ trustedKeys, now? })` · `authorizeEnvelope(receipt)` · `permit(command)` · `revoke()`
- `new SimulatedArm(gate).move(command)` — actuates only if `permit` allows; logs every decision.

Reference implementation, experimental. Apache-2.0.
