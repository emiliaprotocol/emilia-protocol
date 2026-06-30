# Receipt Required — PR kit

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](https://www.emiliaprotocol.ai)

**Add "Receipt Required" to one dangerous action in 10 minutes.** Drop this into any repo with an irreversible agent/tool action and it will refuse to run without a verifiable authorization receipt — proof that a named human approved *this exact action*.

```
missing receipt   -> 428 Receipt Required
valid receipt     -> the action runs
replayed receipt  -> refused (one-time consumption)
forged receipt    -> refused (signature / action-binding fails)
```

That set of four is the **RR-1** conformance level. `receipt-required.test.js` re-proves it on every push (including that the secure default below fails closed).

> **Replay scope:** "one-time consumption" holds within the configured store. The **default store is process-local (in-memory)** — it does *not* survive a restart or span multiple instances. For durable / multi-instance replay protection, pass a durable `store` ({ has, add }) to the gate (Redis/DB).

## 10-minute adoption

1. `npm install @emilia-protocol/require-receipt`
2. Copy `agent-actions.json` into your repo and point it at your dangerous tool (set `tool`, `action_type`).
3. Route that tool through `dispatch()` in `example-dangerous-action.js` (or copy the ~15 lines of gate logic into your existing handler).
4. `npm test` — confirms RR-1 (the four checks).
5. Serve `agent-actions.json` at `/.well-known/agent-actions.json` so agents discover what to bring, then set `EMILIA_MANIFEST_URL` to that path. The 428 challenge only advertises a manifest URL once you've configured one — it won't point agents at a 404.

## Files

| File | Purpose |
|---|---|
| `agent-actions.json` | Action Risk Manifest — which tool needs a receipt, at what assurance |
| `example-dangerous-action.js` | The gate in front of one dangerous action (`dispatch`) |
| `receipt-required.test.js` | RR-1 conformance — the four checks, on every push |
| `PR-DESCRIPTION.md` | Copy-paste description for the PR you open |

## What this is (and isn't)

Not auth ("who are you"), not permissions ("are you allowed here"). It's **portable accountability evidence** a service keeps for its own liability — proof a named human accountably authorized an irreversible action. A *necessary, not sufficient* condition: it does not prove the decision was wise or lawful.

Fully offline — the real verifier from [`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt) (Apache-2.0), no API key, no account, no EMILIA server trusted. Spec: IETF Internet-Drafts `draft-schrock-ep-authorization-receipts` + `draft-schrock-ep-enforcement-point` (individual I-Ds, not RFCs).

## Secure by default

This kit will **not** accept a self-signed (inline-key) receipt for a destructive action by default. Posture is set by env, read at call time:

- **`EMILIA_TRUSTED_KEYS`** (comma-separated base64url SPKI) — the issuer key(s) you trust. Set this for production. Receipts not signed by a pinned key are refused.
- **No trusted keys + no inline opt-in → fails closed.** The action is refused (`receipt_enforcement_misconfigured`); it never runs under an untrusted key. For a destructive operation, refusing is the safe outcome.
- **`EMILIA_ALLOW_INLINE_KEY=1`** — accept inline (self-signed) receipt keys. **Non-production demos only** — never for a real destructive action.

Production checklist: pin `EMILIA_TRUSTED_KEYS`; leave `EMILIA_ALLOW_INLINE_KEY` unset; configure a durable replay `store` if you run more than one instance; serve the manifest and set `EMILIA_MANIFEST_URL`.
