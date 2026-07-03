<!-- SPDX-License-Identifier: Apache-2.0 -->
# The zero-friction wedge — Claude Code, in 20 minutes

The pitch this proves: **your existing approve step now emits court-grade,
vendor-neutral evidence, and nothing else changes.** Safe commands are
untouched. Dangerous commands require a named-human authorization receipt
bound to the *exact* command — signed by the approver's own key, verifiable
by anyone's code, taking your logs out of the evidentiary chain.

No account, no network, no Anthropic cooperation. Two files:
`receipt-hook.mjs` (the `PreToolUse` gate) and `mint-poc-receipt.mjs` (a
stand-in for the real passkey / Face ID signing surface).

## Run the loop

```sh
# 1. Approve one exact command (stand-in for the device signing ceremony).
node examples/claude-code/mint-poc-receipt.mjs "rm -rf ./build"
#    → writes .emilia/receipt.json and prints the approver key to trust.

# 2. Tell the hook which approver key to trust (printed by step 1).
export EMILIA_TRUSTED_KEYS=<the printed value>

# 3. Wire the hook into Claude Code (see settings.snippet.json), then work.
```

What you will observe:

| Command Claude tries | Result |
|---|---|
| `ls`, `cat`, safe reads/writes | pass through, untouched |
| `rm -rf ./build` (the approved one) | allowed once, then consumed |
| the same command again | **blocked** — replay refused |
| `git push --force …` (not approved) | **blocked** — action mismatch |

Every block writes a machine-readable `AE-CHALLENGE-v1` to stderr, which
becomes Claude's feedback — so the agent is *told* exactly what to bring,
not just stopped.

## Fail-closed, by construction

No trusted key, no receipt, wrong command, stale (>15 min), reused, or
tampered — all block. Consumption is committed to `.emilia/consumed.json`
*before* the command is allowed, so a crash can never leave an unrecorded
(replayable) execution.

## What this is not

A POC signing surface — `mint-poc-receipt.mjs` holds a local key for
convenience. The production surface is a passkey / platform authenticator
(Face ID, security key, or an enterprise IdP like Okta/Entra): the approver
signs on their own device, the private key never leaves it, and the receipt
is byte-identical to what this POC emits. Swapping the surface changes
nothing downstream — the hook and the gate are the same.
