# EMILIA Gate — robot/actuator edge sidecar

The Consequence Firewall at the **actuator boundary**, for the physical world. A human (or quorum)
**pre-authorizes a bounded on-the-loop envelope** once (PIP-013) — target set, allowed actions,
bounds (e.g. reach), time window, with a halt/revoke authority. Each motion command is then verified
**at the edge, offline, sub-millisecond, with no cloud, no per-command human, and no consumption** of
the envelope. Out-of-envelope, expired, or revoked → the actuator does not move.

```bash
node --test     # 7 tests
node demo.mjs    # refuse -> authorize envelope -> in-bounds moves -> out-of-bounds/wrong-action/halt/expired refused
```

## Why a sidecar, not the model

It sits *before* the actuator. A compromised, prompt-injected, or confused planner still cannot move
hardware outside the authorized envelope — the gate is the last line, and it fails closed.

## The edge property (the differentiator)

Human signoff has human latency; you cannot approve every motion at machine speed. So the human
authorizes the **envelope** once, and the hot path is pure local crypto: verify each command against
the envelope offline. A cloud-approval system adds a network round-trip and a liveness dependency to
every actuation — unacceptable in contested, air-gapped, or latency-critical deployments. See
`docs/EP-EDGE-OFFLINE-VERIFICATION.md`.

## API

- `new EdgeActuatorGate({ trustedKeys })` · `authorizeEnvelope(receipt)` · `permit(command)` · `revoke()`
- `new SimulatedArm(gate).move(command)` — actuates only if `permit` allows; logs every decision.

Reference implementation, experimental. Composes `@emilia-protocol/require-receipt`. Next: real
hardware adapters + the **Attested Gate** (prove the sidecar is installed and running via
device/workload attestation — WIMSE/SPIFFE). Apache-2.0.
