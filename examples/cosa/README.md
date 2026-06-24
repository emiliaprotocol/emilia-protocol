# COSA L5 + EMILIA L7 — manifest-driven reference

The wired reference for the COSA ↔ EMILIA integration: COSA's **L5** broadcast/cache
plane with its irreversible publish path gated by EMILIA's **L7** "Receipt Required"
rail, driven by an Action Risk Manifest.

> COSA L5 attests an inference result is *authentic*. EMILIA L7 attests an
> irreversible action was *authorized*. Two applications of one discipline —
> signed, canonical, offline-verifiable objects.

```bash
pip install emilia-verify
python examples/cosa/cosa_l5_l7.py        # offline, no key, no account
```

What it shows:
- `l5.cache.read` is **read-only** in the manifest → free, no receipt (compute-once / serve-N).
- `l5.broadcast.publish` is **receipt-required** → a named human signs the exact action; the publish refuses to run without a valid receipt.
- Full ritual: no receipt → `428` · signed → runs · same receipt replayed → refused · forged → refused · valid receipt for a *different* action → refused (confused-deputy).

The gate is driven by [`agent-actions.json`](agent-actions.json) (`EP-ACTION-RISK-MANIFEST-v0.1`) — the same declaration format documented in [`docs/RECEIPT-REQUIRED.md`](../../docs/RECEIPT-REQUIRED.md) and conformance-checked at level RR-1 (see [`docs/RECEIPT-REQUIRED-CONFORMANCE.md`](../../docs/RECEIPT-REQUIRED-CONFORMANCE.md)).

To wire this onto a real L5 plane: replace `L5Plane.broadcast_publish`'s body with the
real broadcast path, point the manifest's `manifest_url` at the service's
`/.well-known/agent-actions.json`, and pin the approver/issuer key out of band.
