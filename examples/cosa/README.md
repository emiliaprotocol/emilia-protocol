# COSA L5 + EMILIA L7 — composed reference (not a stub)

The wired reference for the COSA ↔ EMILIA integration: COSA's **L5** broadcast/cache
plane composed with EMILIA's **L7** "Receipt Required" rail. It composes two real,
signed, canonical, offline-verifiable objects — not a placeholder.

> **L5 (authenticity):** the plane computes an answer once, wraps it in a signed
> COGOBJ, and any consumer can verify it's genuine without recomputing.
> **L7 (authorization):** publishing that COGOBJ to N consumers is irreversible
> (they cache and trust it), so it requires an EMILIA receipt — a named human
> signed the exact publish action.
>
> Two applications of one discipline — signed, canonical (RFC 8785 / JCS),
> offline-verifiable objects.

```bash
pip install emilia-verify
python examples/cosa/cosa_l5_l7.py        # offline, no key, no account, no network
```

What it demonstrates (both guarantees are orthogonal, and both failure axes fire):
- **Compute-once / serve-N** — L5 computes the answer once; N consumers serve it from cache at 0 tokens each (the run shows tokens saved vs. each recomputing).
- **L7 authorization** — no receipt → `428` *before any fan-out*; a named human signs → broadcast runs; same receipt replayed → refused; valid receipt for a *different* action → refused (confused-deputy).
- **L5 authenticity** — a tampered COGOBJ reaching a fresh consumer is **rejected even when the publish carried a valid receipt**: L7 authorized the publish, L5 still caught the forged content. The two layers catch different attacks.

The L7 gate is driven by [`agent-actions.json`](agent-actions.json) (`EP-ACTION-RISK-MANIFEST-v0.1`) — the same declaration format in [`docs/RECEIPT-REQUIRED.md`](../../docs/RECEIPT-REQUIRED.md), conformance-checked at level RR-1 ([`docs/RECEIPT-REQUIRED-CONFORMANCE.md`](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md)).

**Adopting it on a real L5 plane** is a small, well-bounded edit — no live coding required to understand it:
1. `L5Plane.compute` → call the real inference/compute path; keep the COGOBJ + plane signature (L5 authenticity).
2. `L5Plane.broadcast_publish` → call the real broadcast fan-out; keep the `authorize(...)` gate in front of it (L7).
3. Point the manifest's `manifest_url` at the service's `/.well-known/agent-actions.json` and pin the approver + plane keys out of band.
