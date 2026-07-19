# EMILIA Gate: enforcement, witness, and control planes

*Architecture note · 2026-07 · Apache-2.0*

## The invariant

A consequential action is permitted only at the executor-side Gate. Network visibility is valuable
independent evidence, but a passive observer cannot block an action and must never be described as
the enforcement point.

```
agent / operator
      |
      v
executor-side Gate  ---- 428 / refuse before mutation
      |
      +---- authorization + execution evidence --------+
      |                                                 |
      v                                                 v
actuator / API                                  control plane
      |                                      policy · coverage
      |                                      evidence · metering
      +---- effect / outcome evidence -------- settlement eligibility
      |
network witness -------- signed observation -----------+
```

## Three distinct planes

### 1. Enforcement plane

EMILIA Gate sits on the only supported path to the executor: the API handler, payment rail, robot
controller, grid actuator, cloud control plane, or other system that can mutate state. It validates
the relying party's policy, exact-action binding, authority and assurance floor, freshness, and
one-time consumption before calling the actuator. A failed or missing receipt yields an HTTP 428 or
the equivalent closed refusal. Once an effect is attempted, uncertainty is recorded as
`indeterminate`; the approval is never blindly replayed.

### 2. Witness plane

A TAP, packet broker, service-mesh observer, or other sensor may issue an
`EP-GATE-NETWORK-WITNESS-v1` statement. The statement is signed by a relying-party-pinned sensor key
and binds a monotonic sequence, capture point, configuration digest, event type, time, and canonical
action digest. It carries only a flow digest and byte count; packet payload capture is forbidden by
the profile.

The witness proves observation by a pinned capture point. It does **not** establish authorization,
blocking, execution, physical truth, or completeness. Online ingestion requires an atomic durable
sequence store so replay, rollback, and same-sequence equivocation fail closed. Historical rollback
detection starts from a relying-party-pinned stream checkpoint. A same-sequence conflict permanently
poisons that stream; later sequence numbers remain refused until the relying party provisions a new
witness or capture-point identity through an explicit recovery process.

### 3. Control plane

The control plane holds the relying party's policy and trust configuration. It composes five things:

1. deployment attestation from a pinned EAT/RATS, platform, or workload verifier;
2. an independently signed canary probe showing the named surface returned 428 without a receipt;
3. the declared inventory of consequential action surfaces;
4. authorization, execution, witness, and measured-outcome evidence joined by action digest; and
5. usage statements for protected actions and evidence retention.

It emits closed decisions, not a proprietary trust score. Settlement is `eligible` only when the
pinned evidence profile is complete. The relying party still owns prices, legal effect, warranty,
and payment execution.

The evidence presenter never supplies the governing inventory or settlement profile. Those are
pinned control-plane inputs. A surface earns `gated` only when its active probe carries the exact
relying-party challenge nonce for the current evaluation; replaying a still-fresh signed block
result does not renew coverage.

## Coverage states

| State | Meaning |
|---|---|
| `gated` | Fresh nonce-bound deployment attestation **and** a pinned, challenge-bound active probe demonstrate a 428 refusal on the declared surface. |
| `witness_only` | A pinned observer saw related traffic, but active enforcement was not proven. |
| `ungated` | A pinned probe demonstrated the action could execute without a receipt. |
| `stale` | Previously usable coverage evidence is outside the relying party's freshness window. |
| `unknown` | The available evidence cannot establish any stronger state. |

`gated` is not a claim that every physical bypass is impossible. It is evidence about the named
surface in the relying-party-declared inventory. An omitted route is inventory risk and stays
outside the denominator; every report carries that limitation. Coverage is encoded in integer basis
points so the report remains deterministic under the EP canonical JSON profile.

## Attested Gate

`EP-GATE-DEPLOYMENT-PROFILE-v1` does not invent a new attestation format. The relying party pins a
verifier, a fresh challenge nonce, and expected workload, image, configuration, and policy measurements. That verifier may
consume EAT/RATS, TPM, confidential-compute, App Attest, Play Integrity, or workload-identity
evidence. The Gate kernel independently checks audience, nonce, gate/environment identity,
freshness, expiry, and every pinned measurement.

Running the expected workload is necessary but not enough to call a route gated. The separate
active refusal probe closes that distinction.

## Settlement eligibility

`EP-GATE-SETTLEMENT-PROFILE-v1` defines which rows a relying party requires. The open kernel accepts
no serialized `verified: true` shortcut: authorization, execution, measured outcome, and coverage
are interpreted by relying-party-pinned verifier functions; the network-witness signature is
checked directly. Every required row must bind the same `sha256:` action digest, and the execution
record must bind the accepted authorization decision digest. Measured outcome evidence must in turn
bind that exact execution digest, so an outcome from another execution cannot be spliced into the
bundle.

The result is evidence completeness, not legal advice and not a payment instruction. A useful grid
profile can require:

- a quorum authorization for the exact curtailment action;
- executor evidence that the accepted order was dispatched once;
- a pinned network observation at the expected boundary;
- separately verified meter evidence within the market rule's tolerance; and
- a `gated` coverage row for that actuator surface.

If any row is absent, stale, mismatched, unpinned, or out of tolerance, settlement eligibility is
refused with the failed row named.

## Runnable proof

```bash
node examples/gate-control-plane/demo.mjs
node --test packages/gate/network-witness.test.js \
  packages/gate/deployment-attestation.test.js \
  packages/gate/coverage.test.js \
  packages/gate/settlement.test.js \
  packages/gate/control-plane.test.js
```

The demonstration runs two otherwise identical views. The complete view is attested, actively
probed, independently witnessed, and settlement-eligible. Removing the Gate while retaining the
healthy network witness changes the surface to `witness_only` and refuses settlement. That negative
is the architecture's central honesty test.

## Commercial boundary

The formats, verifier kernels, and conformance tests can stay open and reproducible. A managed
EMILIA product can charge for operating the trust configuration and evidence network: inventory,
policy compilation, deployment attestation, probe fleets, key rotation, metering, evidence export,
integrations, settlement adapters, risk pricing, and a separately contracted warranty. The managed
service must not secretly alter the open verdict computation.
