# EMILIA Agent Gate

**One file that puts an AI agent's irreversible actions behind EMILIA's real
policy engine — locally, with no network and no API key.**

`scripts/emilia-gate.mjs` runs `lib/guard-policies.js` (the same formally-modeled
decision logic behind GovGuard/FinGuard) in-process and answers one question
about any action: **allow / allow-with-signoff / deny.** Every decision is a
signed, offline-verifiable receipt.

We dogfood it on the highest-stakes agent we have: the one that operates this
company. **EMILIA governs the agent that builds EMILIA.**

> **Productized:** the deployable, framework-agnostic firewall is
> `@emilia-protocol/gate` (the *Consequence Firewall*) — deny-by-default
> `check` / `middleware` / `guard` with assurance-tier enforcement, one-time
> consumption (replay defense), and a tamper-evident evidence log, composing
> `@emilia-protocol/require-receipt`. See `docs/EMILIA-GATE-PRODUCT-BRIEF.md`.

---

## Three ways to use it

**1. Direct / in a script**
```bash
node scripts/emilia-gate.mjs --command "stripe payouts create --amount 5000000 sk_live_…"
#   ✋ HOLD — human signoff required  (engine: guard-policies)
#   exit 2
```

**2. In CI — block a dangerous step**
```yaml
- run: node scripts/emilia-gate.mjs --command "${{ inputs.deploy_cmd }}"
  # exit 2 fails the job until a human approves
```

**3. As an agent harness hook (Claude Code shown; the pattern is universal)**

Add to `.claude/settings.json` in your repo:
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "node --no-warnings \"$CLAUDE_PROJECT_DIR/scripts/emilia-gate.mjs\" --hook" }
      ] }
    ]
  }
}
```
Now the agent **cannot run** a live-payment command, a force-delete of a
protected path, a force-push, or destructive SQL without EMILIA holding it for a
human signed-yes. The agent literally has no path around the gate.

> **Kill switch:** `EMILIA_GATE=off` (env) → always allow. Or remove the hook.

---

## What it gates

| Pattern | Decision | Decided by |
|---|---|---|
| Live Stripe key / payment mutation | `allow_with_signoff` | **guard-policies engine** (the real, formally-modeled one) |
| `--action` with a hard-deny risk flag (impossible travel, compromised device) | `deny` | **guard-policies engine** |
| `rm -rf` of `/`, `~`, `*`, `.git`; force-push; `DROP TABLE`; destructive Supabase | `allow_with_signoff` | agent-gate high-risk rule |
| Everything else | `allow` | agent-gate (no match) |

**Honesty note:** money/benefit decisions come from the formally-modeled engine
(`evaluateGuardPolicy`). Irreversible-infrastructure decisions come from the
gate's own clearly-labeled rule — we don't claim the formal proofs cover
`rm -rf`. The receipt records which engine decided.

## The receipt
Every decision emits an `EP-RECEIPT-v1`, Ed25519-signed by a stable local
agent-gate key, with the public key inline — verifiable offline with
[`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify).
That's the point of the whole protocol: the decision isn't just made, it's
**provable after the fact**.

## Hosted vs. local
This file uses the engine **in-process** (no key, no network) — ideal for hooks
and CI. To gate against the **hosted** network policy (centrally managed
policies, audit, multi-tenant), call `POST /api/trust/gate` with an API key from
[/signup](https://www.emiliaprotocol.ai/signup) instead. Same decision vocabulary.

---
Apache-2.0 · part of [EMILIA Protocol](https://www.emiliaprotocol.ai)
