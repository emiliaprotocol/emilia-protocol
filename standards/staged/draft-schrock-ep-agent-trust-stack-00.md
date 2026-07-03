# The Agent Trust Stack: Composing Identity, Delegation, Policy, Transparency, and Human Authorization
## draft-schrock-ep-agent-trust-stack-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               28 June 2026
Expires: 30 December 2026
```

> STATUS (repo): staged I-D. Render to .xml/.txt via xml2rfc and file with the EP cluster batch.
> Companion to draft-schrock-ep-architecture (EP-internal) and -authorization-evidence-chain (the
> composition seam). This draft is the cross-effort interoperability map: how independent IETF
> efforts compose into one verifiable account of an agent action.

## Abstract

Agent authorization spans several layers, each being standardized by a different effort. This
informational document maps the "agent trust stack" and the binding points between layers, so an
agent action can be checked as one verifiable chain: who the agent is (identity), what authority it
was delegated (delegation), whether policy permitted the effect (policy), that a named human
authorized the specific irreversible act (human authorization), and that the record is durably
transparent (transparency). It names the composing efforts and the artifact each contributes, and
positions the EMILIA Protocol (EP) human-authorization receipt as the apex that the other layers
reference but do not themselves produce.

## 1. The layers and their efforts

- **Identity** — who the agent/workload is. WIMSE / SPIFFE; [I-D.draft-klrc-aiagent-auth].
- **Delegation** — the scope an agent was authorized to act within.
  [I-D.draft-nelson-agent-delegation-receipts] (DRP); the Agent Authorization Profile for OAuth (AAP);
  OAuth token-exchange / agent-grant profiles.
- **Policy / permit** — whether machine policy allows the effect (a decision point with a standardized
  input contract).
- **Human authorization** — a named, accountable human (or quorum) authorized the *exact* irreversible
  action, offline-verifiable, one-time, separation-of-duties. EP
  ([I-D.draft-schrock-ep-authorization-receipts], -quorum, -enforcement-point). This layer is thin and
  largely unfilled; it is EP's.
- **Transparency** — append-only, tamper-evident logging. SCITT / COSE Receipts.

## 2. Binding points (how they compose)

Each layer emits a verifiable artifact. EP's authorization context records, by reference, the
upstream evidence a decision relied on (an identity attestation, a delegation receipt, a policy
decision) and can enforce its freshness fail-closed (the L4→L7 agent-binding). The
Authorization-Evidence-Chain ([I-D.draft-schrock-ep-authorization-evidence-chain]) binds these
heterogeneous artifacts plus the human authorization into a single, order-preserving record checkable
as one chain. Transparency anchoring (SCITT) is optional and additive; EP receipts verify offline
without it.

## 3. Cede the rest, claim the apex

EP does not re-solve identity, delegation, policy, or transparency, and composes with whichever
standard prevails at each layer. Its contribution is the named-human authorization apex and the
composition seam. AAP and agent-communication frameworks (e.g. AIPF) state the human-approval/audit
requirement but defer the artifact; EP is the concrete fill. DRP delegates a bounded scope; EP proves
a named human authorized the specific act inside it (per-action, identity-bound, fully offline).

## 4. Security Considerations

The chain is only as strong as its weakest upstream artifact; EP records and freshness-checks what it
relied on rather than asserting upstream correctness. Over-trust (treating any one layer as the whole)
is the dominant risk. EP proves authorization, not wisdom — necessary, not sufficient.

## 5. IANA Considerations

This document has no IANA actions.
