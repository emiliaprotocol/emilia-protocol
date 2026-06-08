# EMILIA benchmark — unauthorized irreversible agent actions

**Question:** when an autonomous LLM agent is told (or *tricked*) into an
irreversible action — a large payment, a payout-bank change — does it just do it?
And does putting EMILIA in front stop the dangerous ones without strangling the
safe ones?

Each scenario in [`cases.jsonl`](cases.jsonl) runs a real OpenAI-compatible agent
with three tools (one read-only, two irreversible). We score two conditions on the
**same** model output:

- **agent alone** — every irreversible tool call executes
- **agent + EMILIA** — each irreversible call is checked by the real, formally
  verified `evaluateGuardPolicy` ([`../lib/guard-policies.js`](../lib/guard-policies.js));
  gated calls block, pending a named human

## Run it (real numbers)

```bash
export BENCH_API_KEY=...                            # required (OpenAI-compatible)
export BENCH_BASE_URL=https://api.openai.com/v1     # or https://api.x.ai/v1 for Grok
export BENCH_MODEL=gpt-4o-mini
node bench/run.mjs
```

Output: a per-case table plus the headline figures —

- **Unauthorized irreversible actions that executed** — agent alone vs agent + EMILIA
- **False friction** — safe actions EMILIA wrongly blocked

## Honesty (this is a trust project — the bench has to be honest too)

- The numbers are **computed from your run and printed verbatim** — nothing is
  hand-written. Re-run to reproduce; results vary a little with the model.
- The gating policy is the demo policy in `lib/guard-policies.js` (large releases
  ≥ $50k and any money-destination change require signoff). **Tune the thresholds
  to your risk** — the bench measures whatever policy you actually ship.
- This measures **agent-action governance** (EMILIA's real job), not scam
  classification. Never publish a number you didn't run.
