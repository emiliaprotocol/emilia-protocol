<!-- SPDX-License-Identifier: Apache-2.0 -->
# Candidate dimension for draft-foroughi-agent-protocol-dimensions: Authorization Evidence

**Status:** written as ready-to-adopt input for the dimensional model
(`draft-foroughi-agent-protocol-dimensions`, P. Foroughi). Offered whole: take it, trim
it, or reject it. The text below follows the draft's own conventions (protocol-visible
values, "not specified" where a proposal defers to deployment, no ranking).

## The gap this dimension closes

D4 (Authorization Derivation) captures where the authority under which an agent acts
comes from: direct, derived-1hop, derived-chain. EXT-CHKPT captures that a task can pause
awaiting an out-of-band authorization decision and resume. Neither captures a
protocol-visible property that distinguishes real proposals: **when the checkpoint
resolves, what survives of the decision?** Two protocols can both be suspend-resume at D3
and derived-chain at D4 and still differ here: one emits a durable artifact bound to the
exact operation, the other flips a bit in session state that is gone once the task
resumes.

This is not the audit facet. Audit records what happened, for accountability, after the
fact, and is verifiable by trusting the recorder. The property here is whether the
authorization decision itself is re-verifiable by a downstream relying party or auditor
without trusting the mediator that logged it.

## Proposed dimension text (drop-in)

### Dimension: Authorization Evidence (D-AE)

The durability and independent verifiability of an authorization decision at the protocol
layer. Values:

- **ephemeral**: the decision exists only as a session-state transition (a flag, a resumed
  task, an accepted elicitation). Nothing survives the exchange that a third party could
  verify.
- **recorded**: the decision is written to a log or trace. A relying party can discover
  that a decision was recorded, but verifying it means trusting the recorder's pipeline.
- **artifact**: the decision is emitted as a signed, portable artifact cryptographically
  bound to the specific operation it authorized, verifiable by a relying party or auditor
  independently of the mediator, including offline against keys the relying party has
  pinned.

Relations: orthogonal to D4 (derivation says where authority comes from; this dimension
says what survives of its exercise). Complements EXT-CHKPT (the checkpoint pauses the
task; this dimension classifies what the resume leaves behind). Adjacent to the audit
substrate facet, from which it differs as stated above.

### Application to the surveyed proposals

| Proposal | D-AE value | Basis |
|---|---|---|
| A2A | not specified (protocol layer) | TASK_STATE_INPUT_REQUIRED / AUTH_REQUIRED pause the task; the resolution is a follow-up message on the same task or context identifier. No signed decision artifact is defined at the protocol layer; a deployment may record decisions in its own trace. |
| MCP | ephemeral | Tool-call consent is a host obligation ("MCP itself cannot enforce these security principles at the protocol level"); elicitation returns accept/decline/cancel in-session. No message type carries a durable decision artifact. |
| ACP (AGNTCY invocation surface) | not specified (protocol layer) | Delegated authorization carriage exists; a durable per-operation decision artifact is not defined. |

Existing work already occupies the **artifact** value and can serve as the worked example
for the dimension without ranking anyone: authorization receipts bound to a canonical
digest of the exact operation, offline-verifiable against pinned keys
(draft-schrock-ep-authorization-receipts and related efforts; FIDO's Verifiable Intent
work describes the same value in the payments vertical). The dimension is
mechanism-neutral: any proposal emitting an independently verifiable, operation-bound
decision artifact sits at **artifact**, whatever its format.

### Why the value is protocol-visible

The wire either carries a verifiable decision object or it does not; a receiver can
determine the value from the exchange alone, which is the draft's stated test for a
dimension. And the value changes integration behavior: an **artifact** consumer can build
dispute, compliance, and reliance flows on the decision; an **ephemeral** consumer must
re-prompt or trust the session.

---

Contact: Iman Schrock, EMILIA Protocol (team@emiliaprotocol.ai). License Apache-2.0; use
freely with or without attribution.
