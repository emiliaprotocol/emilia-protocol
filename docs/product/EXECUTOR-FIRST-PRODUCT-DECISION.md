# Executor-First Product Decision

Date: 2026-08-05

## Decision

Adopt the memo's developer painkiller direction, but do not rename the protocol,
collapse active Internet-Drafts, or merge authorization, execution, and outcome
into one alleged proof. The near-term product is an executor-side control plane:
exact-call circuit breaking, exact-action admission, one-time consumption,
post-effect evidence, and a truthful local/cloud operating view.

The seven-document diagram is useful as a commercial explanation of seven
capabilities. It is not an IETF filing plan. The repository already records 22
active individual Internet-Drafts, a four-document presentation surface, a
four-document runtime spine, and a 90-day new-name freeze. Those records remain
authoritative.

## Adopt now

- A free MCP loop breaker as the sharp developer wedge.
- One shared JavaScript exact-action binder used by receipt-required, MCP,
  LangChain, and OpenAI adapters.
- Mandatory complete-argument binding in the CrewAI and LangChain wrappers.
- Atomic consume before Python LangChain tool entry and exact execution
  attestation after return.
- `INDETERMINATE` plus explicit no-retry guidance when post-effect evidence
  cannot be confirmed.
- Cloud status that distinguishes delivered, retrying, failed, unsupported,
  and not configured instead of returning acknowledgement-only success.
- Local Authority Engine and operated Gate as enterprise deployment models,
  while customer-owned evidence remains the product boundary.

## Reject or hold

- **One receipt proves authorization, execution, and outcome.** These are
  separate evidence classes. An executor report can attest what it attempted or
  observed; it cannot prove correct external effect by itself.
- **"Executed correctly."** Correctness, lawfulness, safety, provider effect,
  and business outcome require independent predicates and evidence.
- **Silent secret redaction.** Rewriting an authorized payload produces a
  different action. Secret detection must block or quarantine the original call
  and require a new exact authorization for any replacement.
- **Automatic compensation.** A compensating action is a new consequential
  action with its own authority, failure modes, and evidence. It is not an
  automatic consequence of an outcome label.
- **Agent FICO, liability bonds, insurance, and zero-knowledge competence.** No
  interoperable identity, actuarial model, external provider, or deployed proof
  system currently supports those claims.
- **Universal compatibility and fixed adoption/pricing projections.** These are
  hypotheses to test with installations and design partners, not protocol facts.
- **Immediate draft consolidation.** Presentation can be simplified without
  making inaccurate Datatracker relationships or abandoning distinct profiles.

## Product boundary

EMILIA establishes executor-side authority and evidence for one exact action.
It does not become a bank, custodian, money mover, effect oracle, insurer, or
generic agent score. Sentinel controls must preserve that boundary:

1. Fingerprint the exact call before any effect.
2. Block loops or unsafe content without mutating the call.
3. Consume authority before tool entry.
4. Record execution evidence only after the executor has evidence to report.
5. Treat missing post-effect evidence as indeterminate and never blind-retry.

## Shipped by this decision

- `createMcpLoopBreaker` and `withMcpLoopBreaker`, with bounded memory and a
  truthful local 429 after the configured identical-call budget.
- Mandatory exact-call binding across the public JavaScript and Python
  framework adapters.
- Removal of callback/hosted-boolean execution authority from legacy LangChain.
- Consume-before-effect and attest-after-effect in `langchain-emilia`.
- Truthful cloud signoff pending, notification-delivery, and durable escalation
  behavior, including a one-escalation database invariant.
- An executable cross-package regression matrix covering the failure patterns
  surfaced through the Anton/Claude Cookbook collaboration.

This is a build decision, not a roadmap placeholder. Further Sentinel work must
land as blocking/quarantine enforcement with tests before public claims change.
