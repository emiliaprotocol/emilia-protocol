# EP Edge / Offline Verification — a capability flag

*Why EP is uniquely suited to latency-critical, disconnected, and air-gapped deployment — a
differentiator cloud-approval systems structurally cannot match.*

## The claim

An EP receipt is **verifiable offline**: Ed25519 over RFC 8785 (JCS) canonical bytes against a
**pinned** issuer key, with no network call, no account, and no dependency on the operator's (or
EP's) infrastructure. Verification is local and sub-millisecond. This is not an optimization bolted
on — it is the core design property. It means EP works exactly where the highest-stakes autonomous
actions happen and where cloud-approval architectures fail:

- **Contested / disconnected** environments (defense, maritime, expeditionary).
- **Air-gapped** systems (nuclear, classified, OT/ICS).
- **Latency-critical edge** (vehicles, surgical/industrial robots, grid actuators) where a cloud
  round-trip is unacceptable.

## The latency objection, answered

Human signoff has human latency — you cannot get a person to approve every motion command at machine
speed. EP resolves this with the **on-the-loop envelope** (PIP-013), not by speeding up the human:

1. A human (or quorum) **pre-authorizes a bounded envelope** once — effect class, target set,
   geofence, magnitude, time window — and retains a halt/revoke authority.
2. At the edge, each individual action is verified **against that envelope, offline, in
   sub-millisecond** — no human in the per-action path, no cloud call.
3. The system acts only inside the envelope, only while unrevoked and unexpired; the first
   out-of-envelope action fails closed.

So the human latency lives once, at envelope issuance; the hot path is pure local crypto. A
cloud-dependent approval service cannot offer this — it adds a network round-trip and a liveness
dependency to every action, which is exactly what contested/edge deployments cannot tolerate.

## What the edge verifier needs (and what ships)

- The pinned issuer key(s) and (for envelopes) the authorization receipt — both can be cached locally.
- The verifier: `@emilia-protocol/verify` (JS/Web), `python-verify`, `go-verify` — zero-dependency,
  runnable in browser/edge/embedded; the `/web` build uses Web Crypto.
- Revocation/freshness on the edge: a short envelope `expires_at` + portable revocation statements
  (carried, not fetched) keep "current authority" checkable without connectivity; degraded-comms mode
  fails closed on expiry.

## Versus the alternatives

| Approach | Per-action cloud call? | Works air-gapped? | Edge latency |
|---|---|---|---|
| Cloud approval API / CIBA backchannel | yes | no | network round-trip |
| Operator DB / workflow log | yes (DB) | no | DB round-trip |
| **EP offline receipt + on-the-loop envelope** | **no** | **yes** | **sub-ms local** |

## Status

Shipped: offline Ed25519/JCS verification in three languages; the on-the-loop envelope (PIP-013);
portable revocation. To build for full edge/robot deployment: the **Attested Gate** (prove the
verifier is actually installed and running at the actuator boundary via device/workload attestation
— WIMSE/SPIFFE), tracked in the EMILIA Gate roadmap. This document is the standalone capability flag;
the property it claims is real and tested today.
