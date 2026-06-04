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

Shared Python helper: [`emilia_guard.py`](emilia_guard.py) — `guard_action()` and the `guard`
decorator. HTTP is dependency-injected: pass a `fetch` callable (requests/httpx) for live calls;
the examples pass a local `demo_policy` stub so they run with zero setup and zero network.

## "Works with EMILIA" badge

[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)

```markdown
[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)
```

An honest mark for projects that integrate EMILIA — no certification gate, no audit, just a link.

See also: [`../docs/QUICKSTART.md`](../docs/QUICKSTART.md) · [`../docs/trust-receipt-spec.md`](../docs/trust-receipt-spec.md)
