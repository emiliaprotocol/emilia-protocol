# Worker → Gate → OT executor joined topology v0.1

Status: executable synthetic conformance pack for cases J0 through J4 and the five supplied first-conduit refusal inputs. J5, durable multi-process admission, a live TrueAlter service, and physical-controller testing remain unexecuted.

The collaborator attachment is retained byte-for-byte as `fixtures/truealter-fc10.synthetic.v2.json` (24,044 bytes; SHA-256 `95e9d734dd689e593352a9cd5fda49acbe2752da149879b34496e45e24951e2c`). Alter Meridian Pty Ltd (True Alter) supplied the fixture and, through Blake Morrison on 24 September 2026, explicitly authorized its retention under Apache-2.0 with that attribution. Blake supplied v2 on 25 September 2026 and confirmed the seven-field CAID definition and resulting identifier as a joint pin. [`NOTICE.md`](NOTICE.md) records the permission and claim boundary. The reference report records the same fixture digest.

Run it with:

```sh
npm run conformance:composition:worker-gate-ot
```

The runner verifies the supplied synthetic ES256 JWS values, reproduces the provisional bare-JCS action digest, independently computes an interoperability-local typed CAID, parses the FC10 bytes, and exercises one synthetic in-memory admission domain. The packaged TrueAlter releases were also checked from fresh installs. `alter-runtime` 0.4.16 passed all 21 Python vector cases. The exported `canonicalStringify` API in `@truealter/sdk` 0.5.14 passed all 16 accepts and three of the five refusal cases, but accepted the unsafe-integer case after `JSON.parse`; its object-only API also cannot detect a duplicate member after parsing. An additional depth-65 probe was accepted even though the packaged profile pins `max_depth` to 64. Blake reports those issues as fixed in `@truealter/sdk` 0.5.15, including strict wire parsing and required invocation claims, but 0.5.15 was not available from the public npm registry during this run and is not verified here. The verified 0.4.16/0.5.14 releases carry `canonical-jcs-v1.json` with SHA-256 `7e345eb09842f65475003a2c6fce9b192a41a7eecb62e898e93e20db35f476cc`.

The v2 fixture contains `aud`, `exp`, and `jti`, and every synthetic JWS verifies locally. Public-package verification of the reported 0.5.15 implementation remains open until npm serves that exact release.

The joint interoperability-local CAID action type and seven-field definition are pinned in [`caid-action-definition.v1.json`](caid-action-definition.v1.json), with the exact file digest and expected CAID in [`caid-pin.v1.json`](caid-pin.v1.json). Blake confirmed `ot.modbus.write-multiple-registers.1`, the definition without a redundant `protocol` field, and the resulting CAID. This makes the tested value reproducible; it does not add the type to CAID's public registry.

## Goal

Run worker provenance, exact-action authority, one-time admission, native-command observation, provider entry, and reconciliation in one test path and one durable admission domain.

The current worker-to-Gate probe and FC10 lost-response fixture prove separate pieces. They do not yet prove that a duplicate arriving after a lost response is refused by the same state that authorized provider entry.

## Guarantee boundary

The joined fixture should demonstrate:

- exact action binding from the worker request through the first OT conduit;
- independent provenance and authority checks;
- one atomic reservation across authority spend and provider attempt;
- at-most-one admitted provider entry across duplicate delivery, redundant paths, and restart;
- no blind retry after provider entry may have occurred;
- reconciliation of the original attempt from authenticated evidence; and
- independence of protective safety functions from the Gate.

It must not claim:

- exactly-once physical effect;
- absence of a bypass path;
- that a valid provenance signature grants authority;
- that a command acknowledgment proves the requested physical effect;
- production durability from an in-memory or single-process store; or
- live PLC, RTU, control-room, or safety certification without those systems being tested.

## Topology

```text
TrueAlter worker / identity adapter
  |  signed provenance P + proposed action A + stable delivery jti
  v
EMILIA relying-party adapter
  |  validate provenance properties
  |  freeze exact action A
  |  verify independent authority R for exactly A
  v
Gate replicas / redundant ingress paths
  |  one atomic reservation in admission domain D
  |  transition provider attempt to INVOKING
  |  authenticated continuation C
  v
First OT conduit
  |  decode actual FC10 bytes as A_observed
  |  require digest(A) == digest(R.action) == digest(A_observed)
  v
Credential-owning executor
  |  verify C against D
  |  record provider entry before waiting for a response
  v
PLC / RTU simulator
  |  acknowledgment may arrive, be lost, or conflict with readback
  v
Reconciler
  |  provider-bound acknowledgment + independent readback / telemetry
  |  terminalize the same attempt without redispatch

Independent safety lane
  protective relays / trips / interlocks / emergency controls
  never wait for provenance, Gate admission, logging, or reconciliation
```

## One authoritative admission domain

All Gate replicas, worker sessions, redundant delivery paths, conduits, and the credential-owning executor in the fixture use the same domain:

```text
D = {
  relying_party_id,
  audience,
  executor_id,
  state_domain_id
}
```

The test must not model `D` as two independent deduplication systems joined only by a signed message.

Within `D`, one atomic reservation coordinates two distinct records:

1. **Authority-spend and native-replay record**
   - provenance `jti`;
   - authorization receipt or evaluation identifier;
   - consumption nonce;
   - exact-action digest; and
   - terminal spend state.

2. **Provider-attempt record**
   - operation and attempt identifiers;
   - stable provider idempotency key;
   - exact-action digest;
   - provider-entry state;
   - provider outcome and evidence; and
   - observed-effect relation and evidence.

One reservation transaction either creates both records or neither. A fresh worker, route, or executor instance does not create fresh authority.

## Inputs

### Signed worker provenance `P`

The adapter requires and verifies:

- issuer;
- audience;
- requester or subject;
- stable delivery identifier `jti`;
- issued-at and expiry;
- intended tool or operation class; and
- request or action hash.

Provenance establishes signed delivery context. It does not authorize execution.

### Frozen exact action `A`

Freeze the action before the first asynchronous boundary. For the FC10 case, the material fields include:

- function code, with Modbus already named by the action type;
- target device;
- register start address or index;
- ordered register values;
- command count; and
- conduit-owned link facts required by the transport profile.

The adapter retains the canonical bytes and digest used for authorization and later comparison.

### Independent authority `R`

`R` is an EMILIA authorization receipt or accepted AEB evaluation for exactly `A`. A valid `P` never substitutes for `R`.

### Authenticated continuation `C`

Before forwarding, Gate produces a continuation bound to:

- admission domain `D`;
- operation and attempt identifiers;
- receipt or evaluation identifier;
- exact-action digest;
- source and destination conduits;
- executor identity; and
- provider idempotency key.

The executor verifies `C` and records provider entry against the same `D` before it waits for the device response.

## State behavior

### Before provider entry

A failed provenance, missing authority, action mismatch, duplicate reservation, or invalid continuation is refused without executor entry. Where the protected operation has not entered the provider boundary, the reservation may be released according to the Gate profile.

### After provider entry

Once provider entry is recorded, the authority remains consumed.

If the command may have been accepted but the response is lost, the provider attempt becomes `INDETERMINATE`. Restart, failover, or redelivery must not create another executor entry.

Only provider-bound acknowledgment, independent readback, or independently authenticated telemetry may reconcile the same attempt to a terminal result. Reconciliation never grants permission to redispatch.

## Required cases

| Case | Stimulus | Required result |
| --- | --- | --- |
| `J0 THROUGH` | Valid provenance, separate exact authority, and matching FC10 bytes | One spend, one attempt, one executor entry, provider `COMMITTED`; effect relation recorded separately |
| `J1 IDENTITY_ONLY` | Valid provenance but no EMILIA authority | Refused before reservation; zero executor entries |
| `J2 CONCURRENT_DUPLICATE` | Same `jti`, authority, and action arrive concurrently through two sessions or Gate replicas | One atomic reservation wins; one forward and one executor entry |
| `J3 LOST_RESPONSE_RESTART` | Executor records entry, response is lost, then worker, Gate, and conduit restart and redeliver | Original attempt remains `INDETERMINATE`; no second executor entry; reconciliation only |
| `J4 ACTION_MUTATION` | Target or ordered value changes after approval, including mutation during an awaited store operation | Exact-action mismatch is refused, or frozen bytes remain unchanged; never authorize one action and execute another |
| `J5 SAFETY_INDEPENDENCE` | Gate and admission services are unavailable while an independent protective path fires | Protective path remains operable and never waits for EMILIA |

The canonicalization vectors remain prerequisites. They are not counted as joined topology cases.

## Evidence collected per run

Each case records:

- provenance verification result and exact provenance digest;
- frozen action bytes and digest;
- authority verification and acceptance result;
- admission-domain identifier;
- atomic reservation result;
- authenticated continuation digest;
- observed native-command bytes and digest;
- executor-entry count and provider idempotency key;
- provider outcome and evidence digest;
- observed-effect relation and evidence digest;
- reconciliation decision; and
- a timestamped event sequence sufficient to prove that no second admitted executor entry occurred in the test model.

## Ownership for the joint fixture

- **EMILIA:** topology, admission-domain contract, authority-spend semantics, Gate state transitions, continuation binding, and expected results.
- **TrueAlter / Blake:** provenance fixture shape, worker adapter behavior, OT command semantics, and first-conduit/native-command representation.
- **TrueAlter / Drew:** restart, handoff, degraded communications, conflicting evidence, and minimum control-room reconciliation view.
- **Joint:** threat review, test vectors, and guarantee wording.

## Decisions before values are frozen

1. Choose the durable store used to demonstrate shared state across at least two Gate processes.
2. Decide whether a new authorization for the same action is refused by default while an earlier attempt is unresolved.
3. Pin the provenance profile, including mandatory audience and expiry behavior.
4. Pin the executor and continuation authentication profile.
5. Pin the FC10 simulator and independent readback source.
6. Agree which evidence is synthetic and which, if any, comes from a live protocol stack or device.

## Executable pack

```text
conformance/composition/worker-gate-ot-v0.1/
  README.md
  NOTICE.md
  caid-action-definition.v1.json
  caid-pin.v1.json
  fixtures/truealter-fc10.synthetic.v2.json
  run.mts
  run.mjs
  run.node-test.mts
  run.node-test.mjs
  report.reference.json
```

The directory name is provider-neutral. TrueAlter is the first identity adapter, not a requirement of the topology.

## Current result and remaining work

`report.reference.json` passes J0 through J4. It records one provider entry for the concurrent duplicate and lost-response/restart cases, zero provider entries for the identity-only and mutation cases, and refusals for all five malformed or context-mismatched FC10 inputs.

This is not yet the durable joined test described by the topology. The current admission domain is a single-process in-memory model. J5 still requires an independent protective-path simulator. The fixture is published under the permission and attribution recorded in `NOTICE.md`; the interoperability-local CAID pin is jointly confirmed, while public registry status remains separate.
