# EMILIA Guard for the Claude Agent SDK (Python)

The same gate as the [Claude Code plugin](../claude-code-plugin/), for
applications built on
[claude-agent-sdk](https://github.com/anthropics/claude-agent-sdk-python):
a `PreToolUse` hook that **holds irreversible tool calls until a named human
approves on their own device** (Face ID / passkey) and proceeds only with an
offline-verifiable Trust Receipt.

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, HookMatcher
from guard_hook import emilia_pretooluse

options = ClaudeAgentOptions(
    hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[emilia_pretooluse])]},
)
async with ClaudeSDKClient(options=options) as client:
    await client.query("Pay vendor 8841 the $82,000 we owe them")
    # → the payments MCP tool call is HELD; a named human signs on their
    #   device; the call proceeds only on a real signature.
```

Configuration (env): `EP_API_KEY`, `EP_ORG_ID` — without them the hook still
fails closed to `permissionDecision: "ask"` for risky calls (a free safety
net). `EP_SIGNOFF_TIMEOUT_S` (default 280, max 590) bounds the wait; the SDK
hook timeout is the final backstop.

Behavior:

| Call | Decision |
|---|---|
| money/external `mcp__*` tool (pay, wire, send, publish, delete, …) | mint receipt → device signoff → `allow` only on a real signature; `deny` on rejection; `ask` on timeout/error (**fail-closed**) |
| destructive `Bash` (`rm -rf`, `git push --force`, `terraform apply`, …) | `ask` (local human prompt; never sent to the policy engine) |
| everything else | passes through untouched |

Verify any receipt offline — no account, no network trust:
`npx @emilia-protocol/verify <receipt.json>`.

Apache-2.0 · [emiliaprotocol.ai](https://www.emiliaprotocol.ai)
