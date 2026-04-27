# PIP-003: Accountable Signoff Extension

**Status:** Accepted  
**Type:** Extension  
**Created:** 2026-04-07  
**Author(s):** Iman Schrock  
**Requires:** PIP-001, PIP-002  

## Abstract

The Signoff extension adds named human accountability to EP. When policy requires it, a specific principal must explicitly assume responsibility for an action's outcome before execution proceeds. The attestation is cryptographically bound, one-time consumable, and irrevocable.

## Lifecycle

```
challenge_issued → attestation_pending → attested | denied | expired | escalated
```

## Key Properties

- **Named ownership:** The attesting human is identified by entity_ref, not role
- **Consequence visibility:** Challenge includes human-readable consequences_summary
- **One-time consumption:** Attestation consumed exactly once via `consume_signoff_atomic()` RPC
- **Handshake binding:** Every Signoff references a verified Handshake — it cannot exist independently

## Reference Implementation

`lib/signoff/` — challenge.js, attest.js, consume.js, invariants.js
