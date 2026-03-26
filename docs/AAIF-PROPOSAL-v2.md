# EMILIA Protocol (EP) — Proposal for AAIF Consideration

EMILIA Protocol is an open protocol for trust decisions and pre-action trust enforcement in machine-mediated systems.

EP Core defines interoperable objects for trust-relevant evidence, trust state, and trust decisions:
- Trust Receipt
- Trust Profile
- Trust Decision

EP Extensions add stronger enforcement where systems must control whether a specific high-risk action should proceed. The most important extension is Handshake, which binds actor identity, authority, policy, action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow.

When policy requires named human ownership, EP can also require Accountable Signoff before execution.

This proposal asks AAIF to consider EP Core as a minimal interoperable trust-decision interface, while recognizing pre-action enforcement as a key extension area for agent systems operating in high-risk environments.

## Why AAIF should care

As systems move from recommendation to execution, the missing governance layer is not only model quality. It is action control.

MCP tells agents how to use tools. EP tells systems whether a high-risk action should be allowed to proceed.

EP is especially relevant where:
- delegated autonomy intersects with regulated workflows
- high-risk actions require policy-bound, replay-resistant authorization
- human ownership must remain attributable even in agent-assisted systems

## Core question

AAIF should evaluate EP against this question:

> should this exact high-risk action be allowed to proceed in this context, under this policy, by this actor?

That is stronger, more specific, and more interoperable than generic software trust or tool preflight alone.
