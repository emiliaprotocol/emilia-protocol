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
| Multi-handshake quorum (protocol) | [`multi-handshake/`](multi-handshake/) | `node examples/multi-handshake/compose-and-verify.mjs` |
| Model-to-Matter frontier-science clearance | [`model-to-matter/`](model-to-matter/) | `node examples/model-to-matter/demo.mjs` |
| RSL Media declaration-to-proof compatibility flow | [`rsl-media-clearance/`](rsl-media-clearance/) | `node examples/rsl-media-clearance/demo.mjs` |
| Google Cloud external reliance lab | [`google-cloud-reliance/`](google-cloud-reliance/) | `node examples/google-cloud-reliance/demo.mjs` |

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

> Scope: EMILIA's formal models cover named properties of the policy **engine**,
> including self-approval and replay exclusions. Current counts and exact scope
> live in `lib/proof-stats.json` and `PROOF_STATUS.md`. They do **not** verify Grok.
> This example is glue around the modeled core.

### What the Python guard (`grok_guard.py`) verifies — and what it does not

`grok_guard.py` returns `proceed=true` for a signoff action **only** when every one of
these offline checks passes in-process (each fails closed):

1. **Signature** — the Ed25519 signature over the canonical EP-RECEIPT-v1 payload verifies
   (`emilia_verify`, the same check anyone runs with `pip install emilia-verify`).
2. **Signer pinning** — the signing key is a member of a **server-independent** trusted set
   (`EP_TRUSTED_SIGNER_KEYS` / `trusted_signer_keys=`). The guard does **not** trust the
   `public_key` the `/evidence` response served. With **no** pinned set it fails closed
   (`untrusted_signer`) — it never falls back to the inline key.
3. **Request binding** — the signed `receipt_id` / amount / currency / destination / approver
   equal what the agent actually requested. A genuinely-signed $1 receipt cannot approve an
   $82k wire (`claim_mismatch`).
4. **Single-use** — a `receipt_id` is redeemable at most once via an injectable `replay_store`
   (`replay`); `receipt_status: consumed` is treated as already-spent (`already_consumed`).
5. **Anchor** (opt-in, `require_anchor=True`) — the Merkle inclusion proof must be present and
   valid (`anchor_required`).

It does **not** prove the approver is wise or the action good — only that a *named, pinned key*
signed the *exact* canonical action this agent requested.

**Honest residuals.** With `EP_TRUSTED_SIGNER_KEYS` configured, a fully compromised EMILIA
server cannot make the agent proceed. The optional `/.well-known/ep-keys.json` bootstrap is a
recommended **follow-up** — the app does not serve that route yet, so the configured set is the
required defense today. The default in-memory `replay_store` is **per-process only**; production
MUST inject a persistent, atomic store (the executor's DB) for a real single-use guarantee.
Canonicalization is not yet RFC 8785 / JCS-strict; it currently fails **closed** (Python may
reject some valid JS receipts, never the reverse), so it is a false-negative risk, not a bypass.
For a production-grade verifier that fails closed on a missing inclusion proof, see
`@emilia-protocol/verify`'s `verifyTrustReceipt()` and the EP Internet-Draft §6.3.

The six red-team vectors are re-run permanently by
[`tests/test_grok_guard_redteam.py`](tests/test_grok_guard_redteam.py):

```
PYTHONPATH=packages/python-verify python3 examples/tests/test_grok_guard_redteam.py
# or:  PYTHONPATH=packages/python-verify pytest examples/tests/test_grok_guard_redteam.py
```

## "Works with EMILIA" badge

[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)

```markdown
[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)
```

An honest mark for projects that integrate EMILIA — no certification gate, no audit, just a link.

See also: [`../docs/QUICKSTART.md`](../docs/QUICKSTART.md) · [`../docs/trust-receipt-spec.md`](../docs/trust-receipt-spec.md)
