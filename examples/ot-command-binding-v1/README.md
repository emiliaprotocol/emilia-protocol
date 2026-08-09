<!-- SPDX-License-Identifier: Apache-2.0 -->
# OT Command Binding

One exact-action authorization, bound to industrial control commands across
three transports with very different envelope capacity.

```zsh
node examples/ot-command-binding-v1/demo.mjs          # narrated run
node examples/ot-command-binding-v1/demo.mjs --json   # machine-readable result
node --test examples/ot-command-binding-v1/*.test.mjs
node examples/ot-command-binding-v1/generate-vectors.mjs --check
```

## The problem this example is about

Control protocols differ in whether they can carry an authorization at all.

| Transport | What it can carry | What it cannot carry | Binding mode |
| --- | --- | --- | --- |
| OPC-UA | Request structures have an extension slot, so an authorization travels with the call. In this example the receipt rides in the request header's extension object. | Nothing relevant. | Inline |
| Modbus TCP | Unit id, function code, register address, value. That is the whole write. | Anything else. The frame this example encodes is 12 octets and every one of them is a protocol-defined field; the MBAP length field pins the rest of the frame at 6 octets, so there is no optional field to grow into. | Out of band, keyed to the command digest |
| DNP3 | A typed object in a typed object space. The control relay output block this example encodes is a fixed 11 octets inside an 18-octet application fragment. | Anything else. No octet of the fragment is free for an envelope. | Out of band, keyed to the command digest |

For Modbus and DNP3 the authorization cannot travel with the command, so it is
held out of band and keyed to a canonical digest of the exact command. **The
gate authorizes the digest; the wire carries only the native command.**

That only works if the digest is recomputable from what actually reached the
wire. So every transport here has a decoder, and the enforcement point sits in
front of the device: it decodes the frame it is about to forward, and derives
the observed action from those bytes plus the link facts it owns because it
terminates the connection (site, device, and for DNP3 the outstation address, a
data-link field). The observed action, never the requester's description of it,
is what the gate binds. `commands.mjs` exposes that as `commandDigest()`, which
is `hashCanonical` from `@emilia-protocol/gate` — the same function the gate
uses to record `observed_action_hash`, so the index key and the authorized
digest are the same value by construction.

The inline case is a transport convenience and nothing more. The OPC-UA receipt
rides with the call, and a drifted call carrying that same receipt is refused
exactly as an out-of-band lookup for a different digest would be
(`scenario.test.mjs`, "an inline OPC-UA envelope is not a trust shortcut").

## Scenes

| Scene | Property it demonstrates | Where the verdict comes from |
| --- | --- | --- |
| 1. `canonical-action-derivation` | Each command shape has one exact-action digest, and changing the register, the value, the unit, the DNP3 point index, the control code, the OPC-UA node, method, or argument produces a different one. A per-request Modbus transaction id does not. | `hashCanonical` and `verifyExecutionBinding` from `@emilia-protocol/gate` |
| 2. `authorized` | An operator authorizes one exact command; the gate admits it once on each transport; the receipt verifies offline. | `gate.run`, then `verifyReceipt` from `@emilia-protocol/verify` with nothing but the pinned issuer key |
| 3. `drift-refused` | A command differing in one field is refused with an action-binding reason, the device is never entered, and the operator's authorization survives the refusal. Separately, the out-of-band index is itself digest-keyed, so an unauthorized command finds nothing. | `gate.run` refusal reason `execution_binding_failed` with `mismatched_fields`, and `receipt_required` on the lookup miss |
| 4. `unresolved-after-dispatch` | The command is accepted and dispatched, the PLC goes quiet, and the outcome is recorded as indeterminate. A blind retry is refused and the authorization does not return to the pool. Recovery is a new human authorization, not a retry. | `gate.run` throwing `EMILIA_GATE_TERMINAL_OUTCOME` with `outcome: 'indeterminate'`, the consumption store backend read directly, and the hash-chained evidence log |
| 5. `spent-once` | Freshness and single-use are different properties. An authorization still inside its freshness window but already consumed is refused, and under a different name than one that is merely stale. | `gate.run` reasons `replay_refused` and `receipt_rejected:receipt_expired`, cross-checked by `verifyEmiliaReceipt` from `@emilia-protocol/require-receipt` |

Scene 4 is the one the Command Authority Envelope does not currently cover. The
repository mechanism is `gate.run()` in `packages/gate/src/index.ts`. Once the
executor has been entered, an exception cannot establish that no external effect
occurred, so the catch block commits the reservation rather than releasing it
(`packages/gate/src/index.ts:2021-2029`), appends an execution record with
`outcome: 'indeterminate'` and `detail.code: 'effect_attempted_outcome_unknown'`
(`:2034-2042`), and throws a terminal-outcome error carrying that outcome
(`:2053-2058`). The example asserts the resulting store value (`committed:v2`,
written by `createDurableConsumptionStore`'s `commit` in
`packages/gate/src/store.ts:164-172`) and the evidence record, not a printed
line.

## Files

- `commands.mjs` — canonical actions, wire encoders, and wire decoders for the three transports.
- `scenario.mjs` — enforcement points, the out-of-band authorization index, and the five scenes.
- `demo.mjs` — narrated terminal run.
- `scenario.test.mjs` — the assertions behind every claim above.
- `vectors.v1.json` — deterministic actions, native command encodings, action
  digests, correlation behavior, and one-field negative cases for independent
  reproduction.
- `generate-vectors.mjs` / `vectors.test.mjs` — generated Node 20 companions
  that rebuild and verify the pinned vectors. The OPC-UA vector carries an
  explicitly invalid illustrative reference; it demonstrates envelope
  carriage, not authorization validity.

Author the `.mts` sources; the `.mjs` companions are generated by
`scripts/build-standalone-runtimes.mjs` and must not be hand-edited.

## Claim discipline

- This is a synthetic local demonstration of binding semantics. No live PLC,
  RTU, or DCS was involved, and no real process was actuated.
- The transport encoders and decoders are minimal models written for this
  example, not a certified protocol stack. Every byte-level statement above is a
  statement about the frames `commands.mjs` produces, not a restatement of any
  protocol specification. The Modbus register reference is mapped to a
  zero-based protocol address by subtracting 40001, and the decoder reverses
  that exact mapping; a deployment must use its own site's addressing.
- No conformance claim is made against IEC 62443 or any other standard. Nothing
  here has been tested against a certification suite.
- This is not a working group item, and nothing here is adopted, endorsed, or
  published by any standards body. It is a contribution offered toward the
  transport-binding gap that
  `draft-morrison-ot-command-authority-01` marks out of scope in its Section 7.
- The consumption store backend is an in-process map, so it is ownership-fenced
  and permanent but not shared durable state; the gate is constructed with
  `allowEphemeralStore: true` for that reason. A deployed enforcement point
  requires a durable backend and drops that flag.
- The issuer and approver keys are generated per run by the EG-1 harness. No
  real operator approved anything.
