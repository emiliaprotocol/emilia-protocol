# EMILIA — framework integration examples

Guard an irreversible agent action behind EMILIA in every major agent framework. Same idea
everywhere: the high-risk tool/function routes through the trust gate first —
**allow → run, deny → throw, signoff_required → wait for a named human, then run.**
Each example runs offline (a local policy stub), so you see all three outcomes immediately.

| Framework | Example | Run |
|---|---|---|
| LangChain.js | [`../packages/langchain/example.mjs`](../packages/langchain/example.mjs) | `node packages/langchain/example.mjs` |
| CrewAI (Python) | [`crewai_guard.py`](crewai_guard.py) | `python examples/crewai_guard.py` |
| AutoGen (Python) | [`autogen_guard.py`](autogen_guard.py) | `python examples/autogen_guard.py` |
| xAI Grok — **live** | [`grok-guard.mjs`](grok-guard.mjs) | `XAI_API_KEY=… node examples/grok-guard.mjs` |

Shared Python helper: [`emilia_guard.py`](emilia_guard.py) — `guard_action()` and the `guard`
decorator. HTTP is dependency-injected: pass a `fetch` callable (requests/httpx) for live calls;
the examples pass a local `demo_policy` stub so they run with zero setup and zero network.

## xAI Grok — live demo

`grok-guard.mjs` is the one **live** example: a real xAI Grok agent (needs an `XAI_API_KEY`)
whose `release_payment` tool is gated by the **actual** verified engine — `evaluateGuardPolicy`
from [`../lib/guard-policies.js`](../lib/guard-policies.js), imported directly, not stubbed.
Grok proposing an $82k wire trips `allow_with_signoff` and blocks until a named human signs;
a $30 refund flows freely. Point `XAI_BASE_URL` / `XAI_MODEL` at any OpenAI-compatible API
(OpenAI, Together, …) and the accountability layer is identical.

> Scope: EMILIA's 26 TLA+ theorems / 35 Alloy facts cover the policy **engine** (no
> self-approval, no replay, money-destination + $50k+ always gated). They do **not** verify
> Grok. This example is honest glue around a verified core.

## "Works with EMILIA" badge

[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)

```markdown
[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)
```

An honest mark for projects that integrate EMILIA — no certification gate, no audit, just a link.

See also: [`../docs/QUICKSTART.md`](../docs/QUICKSTART.md) · [`../docs/trust-receipt-spec.md`](../docs/trust-receipt-spec.md)
