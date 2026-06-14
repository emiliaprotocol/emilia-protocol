<!-- SPDX-License-Identifier: Apache-2.0 -->

# Proposal: a standard consent + authorization-receipt capability for irreversible MCP tool calls

*Post-ready for an MCP spec Discussion / SEP. Audience: MCP maintainers + community.
Framing: a gap in the protocol + a working reference implementation, not a vendor pitch.*

## The gap
MCP already standardizes how an agent *discovers and calls* tools, how a server *authenticates*
(OAuth), and how a server can *elicit* mid-call input. What it does **not** standardize is the
moment that matters most for safety: **when a tool call is irreversible — releasing a payment,
deleting a record, changing a vendor's bank details, deploying — there is no portable, verifiable
way to prove a named human authorized *that exact call* before it executed.**

Today that proof, if it exists at all, is a log entry on the server that performed the action —
testimony controlled by the party whose conduct is in question. As agents move from answering to
acting, "a human approved this" needs to be **evidence**, not testimony: checkable by a third party,
offline, without trusting the server.

`destructiveHint` / `readOnlyHint` annotations already mark which calls are dangerous. The missing
piece is what *happens* at one of those calls, and what *artifact* it leaves behind.

## The proposal (sketch)
A capability where a tool annotated irreversible triggers, before execution:
1. **Consent/elicitation** of a *named human* approver (reuse MCP elicitation for the prompt).
2. A **device-bound signoff** over the exact action (the canonical tool name + arguments hash),
   not over a paraphrase the human didn't see.
3. Emission of a **portable authorization receipt** — offline-verifiable by anyone with a public
   key, no call back to the server — returned alongside the tool result.
4. **Fail-closed**: no valid receipt → the irreversible call does not run.

This is additive and opt-in: reversible/read-only calls are untouched.

## Working reference implementation (today, Apache-2.0)
- **`@emilia-protocol/mcp-guard`** — middleware that wraps an MCP tool dispatcher: classifies
  reversible vs irreversible (honoring `destructiveHint`/`readOnlyHint`), runs consent → signoff →
  receipt, and refuses the call (a `402`-style "receipt required") otherwise.
- **The receipt format is a published IETF Internet-Draft** — `draft-schrock-ep-authorization-receipts`
  — with offline verifiers in JavaScript, Python, and Go on npm, and a formally-verified core.
- **Multi-agent provenance:** a chained receipt (`EP-PROVENANCE-CHAIN-v1`) carries the whole
  delegation chain (user → agent hops → per-action approval → execution), so a tool call three hops
  deep still answers "who authorized this?"

We're not proposing EMILIA *as* the standard — we're offering it as a reference + a starting point.
The receipt is an open format; the goal is one interoperable consent+evidence hook for the agent
ecosystem, however the community chooses to shape it.

## The ask
Is there appetite for a Spec Enhancement Proposal (or a focused discussion) on a standard
**consent + authorization-receipt** capability for irreversible tool calls? We'll do the drafting
work, bring the reference implementation and conformance vectors, and adapt the receipt framing to
whatever the maintainers prefer. Happy to demo: `npx @emilia-protocol/issue demo` issues a receipt
and verifies it offline in ~60 seconds.

— Iman Schrock, EMILIA Protocol · team@emiliaprotocol.ai · github.com/emiliaprotocol/emilia-protocol
