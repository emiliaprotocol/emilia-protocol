# Receipt Required — PR kit

[![Receipt Required: RR-1](https://img.shields.io/badge/Receipt%20Required-RR--1-22c55e)](https://www.emiliaprotocol.ai)

**Add "Receipt Required" to one dangerous action in 10 minutes.** Drop this into any repo with an irreversible agent/tool action and it will refuse to run without a verifiable authorization receipt — proof that a named human approved *this exact action*.

```
unlisted tool     -> 403 refused (default closed)
missing receipt   -> 428 Receipt Required
valid receipt     -> the action runs
replayed receipt  -> refused (one-time consumption)
forged receipt    -> refused (signature / action-binding fails)
```

That set of four is the **RR-1** conformance level. `receipt-required.test.js` re-proves it on every push (including that the secure default below fails closed).

> **Replay scope:** "one-time consumption" holds within the configured store. The **default store is process-local (in-memory)** — it does *not* survive a restart or span multiple instances. For durable / multi-instance replay protection, pass an ownership-fenced durable `store` implementing atomic `{ reserve, commit, release }` operations (Redis/DB). An uncertain reservation must remain closed until reconciliation.

## 10-minute adoption

1. `npm install @emilia-protocol/require-receipt`
2. Copy `agent-actions.json` into your repo and point it at your dangerous tool (set `tool`, `action_type`, and the `execution_binding.required_fields` a human is actually approving). **List every tool the dispatcher can reach**, including the reversible ones, with `receipt_required: false` — see "Default closed" below.
3. Route that tool through `dispatch()` in `example-dangerous-action.js` (or copy the ~15 lines of gate logic into your existing handler).
4. `npm test` — confirms RR-1 (the four checks).
5. Serve `agent-actions.json` at `/.well-known/agent-actions.json` so agents discover what to bring, then set `EMILIA_MANIFEST_URL` to that path. The 428 challenge only advertises a manifest URL once you've configured one — it won't point agents at a 404.

## Files

| File | Purpose |
|---|---|
| `agent-actions.json` | Action Risk Manifest — which tool needs a receipt, at what assurance, bound to which fields |
| `example-dangerous-action.js` | The gate in front of your dangerous actions (`dispatch`) |
| `demo-approver.js` | Local-demo approver key and proof minter. Never loaded when `NODE_ENV=production` |
| `receipt-required.test.js` | RR-1 conformance plus the default-closed and binding checks, on every push |
| `PR-DESCRIPTION.md` | Copy-paste description for the PR you open |

## What this is (and isn't)

Not auth ("who are you"), not permissions ("are you allowed here"). It's **portable accountability evidence** a service keeps for its own liability — proof a named human accountably authorized an irreversible action. A *necessary, not sufficient* condition: it does not prove the decision was wise or lawful.

Fully offline — the real verifier from [`@emilia-protocol/require-receipt`](https://www.npmjs.com/package/@emilia-protocol/require-receipt) (Apache-2.0), no API key, no account, no EMILIA server trusted. Spec: IETF Internet-Drafts `draft-schrock-ep-authorization-receipts` + `draft-schrock-ep-enforcement-point` (individual I-Ds, not RFCs).

## Default closed

A tool `dispatch()` cannot resolve to **exactly one** manifest entry is refused (403), never run. Absence of a rule is not a safe default: a new, renamed, misspelled, or differently-cased tool would otherwise walk around the rail simply by not appearing in `agent-actions.json`. This is the same posture as `@emilia-protocol/mcp-guard`'s `defaultIrreversible = true`.

- `action_not_in_manifest` — no entry names this tool. Selector matching is exact and case-sensitive, and the refusal says so when only the case differs.
- `manifest_selector_ambiguous` / `manifest_selector_conflict` — more than one policy could apply. "The manifest does not name one policy" is never "no policy applies, proceed".
- `receipt_required: false` — an author's decision on record. That entry passes through; an absent entry does not.

## Bound to the whole call

The receipt is bound to `<action_type>:sha256:<hash of the tool name and every argument>`, and the arguments are snapshotted **before** the first `await` — the snapshot is what executes. A receipt approving `{ table: "customers" }` cannot carry `{ table: "customers", where: "1=1", hard_delete: true }` past the gate, and a caller object mutated while the gate verifies cannot change what runs.

On top of that, `execution_binding.required_fields` in the manifest names the material fields a human actually approved. The gate demands a signed `canonical_action` whose hash matches the call and which carries every one of those fields, so a call that simply omits the target cannot degrade to the bare action type.

## Secure by default

This kit will **not** accept a self-signed (inline-key) receipt for a destructive action by default. Posture is set by env, read at call time:

- **`EMILIA_TRUSTED_KEYS`** (comma-separated base64url SPKI) — the issuer key(s) you trust. Set this for production. Receipts not signed by a pinned key are refused.
- **No trusted keys + no inline opt-in → fails closed.** The action is refused (`receipt_enforcement_misconfigured`); it never runs under an untrusted key. For a destructive operation, refusing is the safe outcome.
- **`EMILIA_ALLOW_INLINE_KEY=1`** — accept inline (self-signed) receipt keys, and use the local demo approver in `demo-approver.js`. **Local demos only.** It is ignored outright when `NODE_ENV=production`, and `demo-approver.js` refuses to load there at all, so the demo escape cannot survive into a production image.
- **`EMILIA_APPROVER_KEYS_JSON`** — relying-party-owned directory of enrolled approver keys. Each entry names its pinned `public_key`, `key_class`, and `approver_id`; receipt-supplied roles never establish human assurance.
- **`EMILIA_RP_ID`** and **`EMILIA_ALLOWED_ORIGINS`** — the WebAuthn RP ID and comma-separated origin allowlist used to verify the human ceremony. A Class-A action fails closed when any of these three assurance inputs is absent or malformed.

Production checklist: pin `EMILIA_TRUSTED_KEYS`; configure the approver directory, RP ID, and origins; leave `EMILIA_ALLOW_INLINE_KEY` unset; configure a durable replay `store` if you run more than one instance; serve the manifest and set `EMILIA_MANIFEST_URL`.
