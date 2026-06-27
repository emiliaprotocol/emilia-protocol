# Receipt Required — PR kit

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](https://www.emiliaprotocol.ai)

**Add "Receipt Required" to one dangerous action in 10 minutes.** Drop this into any repo with an irreversible agent/tool action and it will refuse to run without a verifiable authorization receipt — proof that a named human approved *this exact action*.

```
missing receipt   -> 428 Receipt Required
valid receipt     -> the action runs
replayed receipt  -> refused (one-time consumption)
forged receipt    -> refused (signature / action-binding fails)
```

That set of four is the **RR-1** conformance level. `receipt-required.test.js` re-proves it on every push.

## 10-minute adoption

1. `npm install @emilia-protocol/require-receipt`
2. Copy `agent-actions.json` into your repo and point it at your dangerous tool (set `tool`, `action_type`).
3. Route that tool through `dispatch()` in `example-dangerous-action.js` (or copy the ~15 lines of gate logic into your existing handler).
4. `npm test` — confirms RR-1 (the four checks).
5. Serve `agent-actions.json` at `/.well-known/agent-actions.json` so agents discover what to bring.

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

> **Production:** the demo uses `allowInlineKey: true` so it runs with no setup. In production, pin `trustedKeys: [<issuer SPKI you trust>]` and drop `allowInlineKey` — otherwise a self-signed receipt would verify.
