# PIP-008: Agent Binding (Identity & Delegation Reference)

**Status:** Draft
**Type:** Extension
**Created:** 2026-06-23
**Author(s):** Iman Schrock
**Requires:** PIP-001 (Core Freeze)

## Abstract

This PIP adds an OPTIONAL `agent_binding` object to the `ep.signoff.v1`
Authorization Context (I-D `standards/draft-schrock-ep-authorization-receipts`,
Section 4). The object attributes the authorized action to an external **agent
identity** (`agent_id`) and, optionally, the external **delegation** that
authorized that agent to act (`delegation` = `{scheme, ref, hash?}`), plus an
optional length-capped `statement`. Because the context an approver signs is
canonicalized whole (JCS, RFC 8785), the approver's signature **automatically
covers** the binding — no verifier change is required and the EP Core v1.0
freeze (PIP-001) is untouched. The binding is **purely additive**: existing
verifiers verify receipts carrying it without modification.

Crucially, `agent_binding` is a **claim, not proof**. EMILIA does not mint,
resolve, or verify agent identity or delegation; it **composes** with external
agent-identity and delegation standards (e.g. IETF WIMSE, the Delegated-Receipt
Protocol) by *referencing* them inside a signed human-authorization context. The
receipt proves that *a named human authorized this exact action, and that the
action was presented as being taken by agent `agent_id` under delegation `ref`* —
it does not prove the agent's identity or the delegation's validity. Those
remain the responsibility of the referenced external system.

## Motivation

"Who/which agent, acting on whose behalf?" (identity + delegation) and "was this
exact action authorized?" (EP) are different layers. EP's defensible, frozen
contribution is the offline-verifiable **authorization receipt**; rebuilding an
identity/delegation registry would (a) make EP a worse, late entrant in a
crowded, standardizing space, and (b) turn EP into a system-of-record, eroding
its core "verify without trusting the issuer" property.

But buyers and reviewers legitimately ask EP to *carry* an agent-identity and
delegation reference so a single signed artifact answers "a human authorized
action X, attributed to agent A under delegation D." PIP-008 supplies exactly
that link — a thin, signature-bound reference — without EP owning the identity
layer. It is the composition seam between EP and WIMSE/DRP-class standards.

## Specification

### §1 — Producer (issuer)

A context MAY carry an `agent_binding` object. When present it MUST contain only
these members:

- `agent_id` (REQUIRED) — a non-empty string: an external agent identity
  reference (URI, DID, or opaque id). EP does not constrain its scheme.
- `delegation` (OPTIONAL) — an object with only:
  - `scheme` (REQUIRED) — non-empty string naming the external standard
    (e.g. `"DRP"`, `"WIMSE"`).
  - `ref` (REQUIRED) — non-empty string: the external receipt/credential id.
  - `hash` (OPTIONAL) — content hash of the referenced artifact, formatted
    `"sha256:<64-lowercase-hex>"`.
- `statement` (OPTIONAL) — free-text string, MUST NOT exceed 280 characters.

The issuer MUST validate the object and fail closed on any violation (unknown
member, missing/empty `agent_id`, malformed `delegation`, malformed `hash`,
over-cap `statement`). When a receipt has multiple contexts, the issuer MUST
copy the **identical** validated object into every context so its canonical form
matches across all of them. Reference implementation: `validateAgentBinding()`
and `buildContexts({ agentBinding })` in `@emilia-protocol/issue`.

### §2 — Verifier

`agent_binding` is covered by the approver signature via whole-context JCS
canonicalization, so a standard verifier already detects any tampering (the
signature fails). A verifier:

- MUST NOT treat `agent_binding` as proof of agent identity or delegation
  validity; it is a signed **claim**.
- MAY surface `agent_id` and `delegation` to the relying party as part of the
  verified context, clearly labeled as a reference to an external system.
- SHOULD, when an application supplies the referenced external artifact (e.g. a
  DRP delegation receipt), verify it under that artifact's own scheme and check
  that its content hash matches `delegation.hash` when present. This cross-check
  is out of EP Core scope and lives in the application/composition layer.

### §2.1 — Freshness of L4 evidence (optional, L4→L7 binding)

A governance decision (L7 PDP) is only as trustworthy as the upstream identity
evidence (L4) it relies on. If a decision is enforced correctly against an
upstream delegation claim that was never constrained or has since expired, the
failure surfaces at L7 but originates at L4 (raised by K. Maralla on the IETF
`agent2agent` list). EP makes that dependency **explicit and recordable**:

- **Producer:** `delegation` MAY carry an OPTIONAL `observed_at` (RFC 3339)
  recording when the external L4 evidence was observed/valid. It is covered by
  the approver signature like the rest of the binding.
- **Verifier (PDP):** `evaluateAgentBinding(context, { maxAgeSec, at })`
  (`@emilia-protocol/verify`) RECORDS the relied-on evidence
  (`agent_id`, `delegation {scheme, ref, hash}`, `observed_at`) and, when
  `maxAgeSec` is supplied, enforces freshness **fail-closed**: a missing
  `observed_at`, a future timestamp, or an age beyond `maxAgeSec` yields
  `fresh:false` with a reason. With no `maxAgeSec`, freshness is not evaluated
  (`fresh:null`) and the evidence is still surfaced for the audit record.

This keeps EP **agnostic to which L4 scheme wins** (WIMSE, OAuth identity
chaining, AIMS, EAT): the PDP binds to and records whatever evidence was
presented rather than requiring L4 to converge — and a stale or unconstrained
upstream claim becomes detectable after the fact rather than silently absorbed.

### §3 — Client conformance

As with PIP-007, whether the approving human *saw* the agent attribution is a
client-conformance property (I-D Section 11.3), not a cryptographic one.
Conforming signing clients SHOULD render `agent_id` (and `delegation` if present)
alongside the Action Object during the signoff ceremony.

## Security Considerations

- **No new trust.** A signed `agent_binding` says only that the human's approval
  was presented with this attribution. A forged or false `agent_id` is the
  referenced identity system's failure, not EP's; EP neither asserts nor
  launders agent identity.
- **Composition over ownership.** `delegation.hash` lets an application bind the
  EP receipt to a specific external delegation artifact, enabling end-to-end
  verification (human authorization ∘ agent delegation) without EP defining the
  delegation format.
- **Fail-closed issuance.** Malformed bindings never reach a context.

## Backwards Compatibility

Purely additive and OPTIONAL. Receipts without `agent_binding` are unchanged;
existing verifiers verify receipts with it unmodified (it rides the signature).
EP Core v1.0 (PIP-001) is untouched; conformance vectors are unaffected.

## Reference Implementation

`@emilia-protocol/issue`: `validateAgentBinding()`, and the `agentBinding`
parameter on `buildContexts()`, `issueAuthorizationReceipt()`, and
`issueFromKeyBundle()`. TypeScript types `AgentBinding` / `AgentDelegationRef`.
