# langchain-emilia

**Before your LangChain agent does anything irreversible, a named human approves
that exact action on their own device.** Face ID / Touch ID / passkey. Fail-closed.
Every approval mints a Trust Receipt that verifies offline — years later, with no
account and no EMILIA server.

```bash
pip install langchain-emilia
export EP_API_KEY=ep_live_...  EP_ORG_ID=your-org
```

```python
from langchain_emilia import EmiliaGuard, guard_tools

guard = EmiliaGuard()                                   # enforce mode
tools = guard_tools([transfer_funds, send_email, calculator], guard)
# hand `tools` to your agent exactly as before — nothing else changes
```

When the agent calls `transfer_funds(amount=82000, beneficiary="Northwind")`:

1. **Gate** — the call is held pre-execution; EP policy returns `allow`,
   `require_signoff`, or `deny`.
2. **Signoff** — on `require_signoff`, a named human approves on their own
   device. The approval is cryptographically bound to the exact action
   parameters — change one digit and it is invalid.
3. **Receipt** — execution releases only after approval; the signed,
   Merkle-anchored receipt is permanent, offline-verifiable evidence.

Denials and pending holds are returned to the model as the tool's output
(`"EMILIA — BLOCKED … transfer_funds was NOT executed."`), so the agent loop
explains itself instead of crashing. The tool body **never runs** unless the
gate allows it.

## Why this is an executor-side precondition, not an "approval tool"

Approval tools the model calls have three failure modes: the model forgets to
call them, approves action A then executes action B, or barrels past an error.
`langchain-emilia` instead wraps the tool itself: the action digest is computed
from the **actual arguments at execution time** and the gate runs before the
tool body, unconditionally. The model-facing schema is unchanged; only the
executor gains the gate.

## Zero-setup dry run (observe mode)

No account, no network, nothing blocked — see what enforcement *would* cover:

```python
guard = EmiliaGuard(mode="observe")
tools = guard_tools(my_tools, guard)
# ... run your agent, then:
for r in guard.records:
    print(r["tool"], r["digest"][:16], r["note"])
```

## Configuration

| Option | Default | Meaning |
|---|---|---|
| `mode` | `"enforce"` | `"observe"` = log-only local dry run, keyless |
| `match` | money/external-action regex | `Callable[[str], bool]` — which tool names are gated |
| `action_types` | auto | map tool name → EP `action_type` (see `ACTION_TYPES`) |
| `wait_for_approval` | `True` | block (≤ timeout) while the human approves; `False` = surface the signoff URL immediately |
| `return_errors` | `True` | denials become tool output for the model; `False` = raise `EmiliaDenied` / `EmiliaApprovalPending` |
| `on_event` | `None` | callback for `observed/allowed/denied/pending/unreachable` events (SIEM hook) |

`EmiliaGateClient(api_key, org_id, base_url, signoff_timeout_s=280, poll_interval_s=3)`
reads `EP_API_KEY` / `EP_ORG_ID` / `EP_BASE_URL` from the environment by default.

## Fail-closed semantics

| Situation | What happens |
|---|---|
| Policy denies | Tool **not executed**; model told why |
| Human rejects on device | Tool **not executed**; receipt records the rejection |
| Signoff window times out | Tool **not executed**; signoff URL surfaced for retry |
| EMILIA unreachable / network error | Tool **not executed** — never fail open |
| Tool name doesn't match `match` | Runs ungated (scope your `match` deliberately) |

## Verify the evidence

Every allowed action carries a `receipt_id`. Anyone can verify it with zero
trust in us or in you:

- In a browser (nothing uploads): **https://www.emiliaprotocol.ai/verify**
- Offline CLI: `npx @emilia-protocol/verify receipt.json`
- Spec: [draft-schrock-ep-authorization-receipts](https://datatracker.ietf.org/doc/draft-schrock-ep-authorization-receipts/) (IETF)

Try the human side yourself (no signup): **https://www.emiliaprotocol.ai/try**

## Development

```bash
cd integrations/langchain-emilia
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

Apache-2.0. The digest layer is pinned byte-for-byte to the JS verifier by
cross-language vectors in `tests/test_digest.py`.

Building with **LangChain.js** instead? The JS sibling is
[`@emilia-protocol/langchain`](../../packages/langchain) — a thin gate Proxy
for `.invoke()`-style tools on npm.
