# EMILIA — framework integration examples

These examples show where to check authority before a tool runs. The Python policy demos
allow a small simulated payment, refuse a blocked destination, and hold a large payment
because no verified human evidence is available. A callback saying "approved" is not proof
of approval. The Python demos run offline and never move money; other examples state their
own dependencies and evidence scope.

| Framework | Example | Run |
|---|---|---|
| LangChain.js | [`../packages/langchain/example.mjs`](../packages/langchain/example.mjs) | `node packages/langchain/example.mjs` |
| CrewAI (Python) | [`crewai_guard.py`](crewai_guard.py) | `python examples/crewai_guard.py` |
| AutoGen (Python) | [`autogen_guard.py`](autogen_guard.py) | `python examples/autogen_guard.py` |
| OpenAI Agents SDK (Python) | [`openai_agents_guard.py`](openai_agents_guard.py) | `python examples/openai_agents_guard.py` |
| xAI Grok — **live** | [`grok-guard.mjs`](grok-guard.mjs) | `XAI_API_KEY=… node examples/grok-guard.mjs` |
| Multi-handshake quorum (protocol) | [`multi-handshake/`](multi-handshake/) | `node examples/multi-handshake/compose-and-verify.mjs` |
| Model-to-Matter frontier-science clearance | [`model-to-matter/`](model-to-matter/) | `node examples/model-to-matter/demo.mjs` |
| Google Cloud external reliance lab | [`google-cloud-reliance/`](google-cloud-reliance/) | `node examples/google-cloud-reliance/demo.mjs` |
| ACTA machine decision + EMILIA human authorization | [`acta-ep-join/`](acta-ep-join/) | `node examples/acta-ep-join/demo.mjs` |
| OAIP offline oversight receipt | [`oaip-oversight-receipt/`](oaip-oversight-receipt/) | `node examples/oaip-oversight-receipt/demo.mjs` |
| Native government mobile approval | [`mobile-government/`](mobile-government/) | `npm run mobile:conformance` |
| Regulatory mobile oversight export | [`regulatory-mobile-oversight/`](regulatory-mobile-oversight/) | `npm run mobile:regulator-demo` |

Shared Python policy helper: [`emilia_guard.py`](emilia_guard.py). Its `fetch` callback is
configured by the application, not the model. Responses must name `allow`, `deny`,
`allow_with_signoff`, or `signoff_required` in `decision` or the legacy `verdict` field.
Optional `allowed` and `signoff_required` booleans must agree; `reason` is a string or null.
Unknown fields, conflicting values, malformed responses, and fetch errors refuse execution.

For signoff, `on_signoff(decision, arguments)` only obtains evidence. A separately configured
`verify_signoff(evidence, action, arguments)` must verify it and return literal `True`.
The verifier receives the exact action and full, detached tool arguments, including defaults.
Each callback gets its own argument copy. Without a verifier, signoff stays blocked.
This stdlib helper does not supply receipt cryptography, freshness checks, or replay storage.

### Python receipt enforcement

Use [`emilia_crewai.require_receipt`](../packages/crewai/) for real receipt-backed tools.
Despite the package name, this decorator also wraps plain synchronous functions and does not
require CrewAI. Configure it at the credential-owning executor:

```python
from emilia_crewai import require_receipt, using_receipt

@require_receipt(
    "payment.release",
    trusted_keys=TRUSTED_ISSUER_KEYS,
    store=CONSUMPTION_STORE,
    assurance_class="class_a",
    verify_assurance=verify_human_receipt,
)
def release_payment(amount, destination):
    return provider.release(amount=amount, destination=destination)

# The application obtains the receipt outside the model's tool arguments.
with using_receipt(receipt):
    release_payment(amount=50000, destination="acct_known")
```

This is a configuration sketch, not a ready-to-run payment integration.
`TRUSTED_ISSUER_KEYS` and the independent `verify_human_receipt` implementation must be pinned
by the executor. The human verifier must check genuine signed affirmative Class-A evidence,
the exact action, enrolled approver and relying-party context; an operator's approval label
does not establish a human ceremony. `CONSUMPTION_STORE` must provide atomic, persistent
reserve/commit/release operations. The core binds the function name and complete arguments
into the receipt action, verifies issuer signature and freshness, and consumes accepted
authority once. Configure the issuer to use the same `bind_call_action` contract.

An in-process wrapper only protects calls routed through it. Keep provider credentials out
of the agent process and mediate every protected execution path for a non-bypassable boundary.

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

### What the Python guard (`executor_approval_gate.py`) verifies — and what it does not

`executor_approval_gate.py` returns `proceed=true` for a signoff action **only** when every one of
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
4. **Freshness** — signed `issued_at` is evaluated against the relying party's local
   `max_receipt_age_s` window (`expired` / `not_yet_valid`).
5. **Single-use** — a `receipt_id` is redeemable at most once via an injectable `replay_store`
   (`replay`); `receipt_status: consumed` is treated as already-spent (`already_consumed`).
6. **Anchor** (opt-in, `require_anchor=True`) — the Merkle inclusion proof must be present and
   valid (`anchor_required`).

It does **not** prove the approver is wise or the action good. The headline receipt establishes
that a pinned operator key attested to the named approval and exact canonical action; deployments
requiring human-held-key proof must verify the separately carried Class-A decision evidence.

**Honest residuals.** With `EP_TRUSTED_SIGNER_KEYS` configured, a fully compromised EMILIA
server cannot make the agent proceed. The optional `/.well-known/ep-keys.json` bootstrap is a
recommended **follow-up** — the app does not serve that route yet, so the configured set is the
required defense today. The default in-memory `replay_store` is **per-process only**; production
MUST inject a persistent, atomic store (the executor's DB) for a real single-use guarantee.
Canonicalization is not yet RFC 8785 / JCS-strict; it currently fails **closed** (Python may
reject some valid JS receipts, never the reverse), so it is a false-negative risk, not a bypass.
For a production-grade verifier that fails closed on a missing inclusion proof, see
`@emilia-protocol/verify`'s `verifyTrustReceipt()` and the EP Internet-Draft §6.3.

Twenty-one checks across seven adversarial classes plus genuine controls are re-run permanently by
[`tests/test_executor_approval_gate_redteam.py`](tests/test_executor_approval_gate_redteam.py):

```
PYTHONPATH=packages/python-verify python3 examples/tests/test_executor_approval_gate_redteam.py
# or:  PYTHONPATH=packages/python-verify pytest examples/tests/test_executor_approval_gate_redteam.py
```

## "Works with EMILIA" badge

[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)

```markdown
[![works with EMILIA](https://www.emiliaprotocol.ai/badge/works-with-emilia.svg)](https://www.emiliaprotocol.ai/mcp)
```

An honest mark for projects that integrate EMILIA — no certification gate, no audit, just a link.

See also: [`../docs/QUICKSTART.md`](../docs/QUICKSTART.md) · [`../docs/trust-receipt-spec.md`](../docs/trust-receipt-spec.md)
