# The EMILIA Protocol Architecture: A Human-Authorization and Oversight Evidence Layer for Agentic and Autonomous Systems
## draft-schrock-ep-architecture-00

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                              28 June 2026
Expires: 30 December 2026
```

### Abstract

Autonomous and agentic systems now take consequential, often irreversible
actions — moving money, changing records, routing benefits, releasing
effects — at machine speed, while the evidence systems that establish
accountability were built for the speed of humans taking those actions.
Across regulation, audit, and insurance the same requirement recurs and
the same artifact is missing: portable, offline-verifiable proof that a
named, accountable human authorized a specific action before it executed,
checkable by a third party without trusting the operator that produced it.

This document is the architectural overview of the EMILIA Protocol (EP):
a **human-authorization and oversight evidence layer** for agentic and
autonomous systems. It defines the layer's position relative to agent
identity, delegation, policy, and transparency work; states the design
invariants; and ties together the component specifications — the
authorization receipt, multi-party quorum, the enforcement point, the
authorization evidence chain, long-term evidence-record renewal, identity
binding, and the human-oversight profile. EP composes with the other
layers rather than replacing them; its contribution is the human-
accountability apex and the composition seam that binds the layers'
artifacts into one verifiable record.

EP proves *authorization* — that a named human (or quorum) approved the
exact action. It does not prove the action was understood, lawful, wise,
or proportional. It is a necessary, not sufficient, condition for
accountable autonomy, and this document is explicit about that boundary.

## 1. Introduction

Fifty years of access control answered "who is allowed in?" The dominant
actors in software are no longer humans but agents that act on their
behalf, and the unanswered question is no longer authentication but
**authorization at the moment of action**: who approved *that exact
action*, before it executed, and can anyone prove it later without
trusting the system that produced the record?

Today that proof is an operator-controlled log: forgeable, backfillable,
and unverifiable by an outside party. Every governing instrument — the EU
AI Act's logging and human-oversight articles, NIST AI RMF, US sectoral
controls requiring authorization and separation of duties, cyber/crime
insurance conditions precedent, and, for defense autonomy, DoD Directive
3000.09's "appropriate levels of human judgment" — *requires* verifiable
human authorization and *specifies no format for it*. EP supplies the
format.

The architectural thesis is one sentence: **no irreversible autonomous
action without a verifiable human receipt.**

## 2. Position in the Agent Stack

EP is deliberately narrow in mechanism and broad in reach: it occupies the
human-authorization layer and composes downward. Adjacent layers, and the
relationship EP takes to each:

- **Identity — who the agent is.** Workload and agent-identity efforts
  (WIMSE/SPIFFE, [draft-klrc-aiagent-auth]) authenticate the agent. EP
  does not re-solve this; it *references* the identity evidence a decision
  relied on (Section 3.6 and the L4 binding, below) and authorizes the
  action above it.
- **Delegation — the agent is authorized to act for a principal.**
  [draft-nelson-agent-delegation-receipts] (DRP), OAuth token-exchange /
  identity-chaining, and agent-grant profiles establish delegated
  authority. EP composes with these by reference; it does not duplicate
  them.
- **Policy / permit — machine policy allows the effect.** Policy-decision
  and route/permit efforts (AgentROA, permit-receipts, decoupled
  authorization models) decide whether an effect is allowed. EP's
  enforcement point (Section 3.3) consumes such a decision and records the
  human authorization that backed it; EP is not the policy engine.
- **Transparency — append-only logging.** Transparency substrates (SCITT,
  COSE Receipts, CT-style logs) provide tamper-evident records. EP can
  anchor to them, but its receipts are **self-contained and verifiable
  offline** without a mandatory external log.
- **Human authorization and oversight — a named, accountable human
  approved this exact action.** This layer is thin and largely unfilled.
  It is EP's.

**L4 → L7 binding.** Because a human authorization is only as trustworthy
as the upstream identity/delegation evidence it relied on, EP records that
evidence inside the signed authorization context and can enforce its
freshness fail-closed (see [I-D.draft-schrock-ep-authorization-receipts]
agent binding). This keeps EP agnostic to which identity or delegation
standard prevails while making a stale or unconstrained upstream claim
detectable after the fact.

## 3. Components

EP is a small family of specifications around one primitive. Each makes a
distinct, independently verifiable claim; together they form the
human-authorization and oversight evidence layer.

### 3.1. Authorization Receipt — the core primitive
[I-D.draft-schrock-ep-authorization-receipts]. A named human's
device-bound signoff over one exact, canonicalized action (RFC 8785 / JCS,
Ed25519), producing a Trust Receipt that a third party verifies fully
offline. The apex of the layer.

### 3.2. Quorum — multi-party human authorization
[I-D.draft-schrock-ep-quorum]. M-of-N approval by *distinct* humans with
ordering and separation-of-duties — the cryptographic form of the
two-person rule, which a single compromised or coerced approver cannot
satisfy alone.

### 3.3. Enforcement Point — the Receipt-Required rail
[I-D.draft-schrock-ep-enforcement-point]. The fail-closed gate: a
high-risk action is refused (HTTP 428-style) unless a valid, in-scope,
unrevoked authorization receipt is present. "No receipt, no execution,"
expressed as a manifest-driven policy enforcement point.

### 3.4. Authorization Evidence Chain — the composition seam
[I-D.draft-schrock-ep-authorization-evidence-chain]. A standard for
binding the artifacts of the adjacent layers — an identity attestation, a
delegation receipt, a policy decision, a transparency inclusion proof, and
the EP human authorization — into a single, order-preserving, verifiable
evidence record. This is the connective tissue that lets independently
produced proofs be checked as one chain.

### 3.5. Evidence Record — long-term, crypto-agile preservation
[I-D.draft-schrock-ep-evidence-record]. An RFC 4998-style renewal chain so
a receipt verifiable today remains verifiable after its original
algorithms weaken (e.g. sha256 → sha384), meeting the multi-year retention
schedules that regulation imposes on the records EP produces.

### 3.6. Identity Binding — the named human, not a raw key
[I-D.draft-schrock-emilia-eye]. A profile binding a signing key to a real,
named, accountable person (and, where required, a device-bound,
user-verified authenticator), closing the gap left by peers that bind only
to an opaque public key.

### 3.7. Human-Oversight Profile — oversight of autonomous action
[work in progress]. An applicability profile for human-in-the-loop and
human-on-the-loop oversight of autonomous and cyber-physical systems,
mapping the components above to the human-oversight requirements of DoD
Directive 3000.09, NIST AI RMF, and (for civilian high-risk systems) EU AI
Act Article 14. It introduces no new cryptography; it applies the receipt
primitive at authorization boundaries.

## 4. Relationship to Other Work

A per-component treatment appears in each component document; see in
particular [I-D.draft-schrock-ep-authorization-receipts] Section 10, which
positions EP against DRP, CIBA, WIMSE, receiver-attested logging,
AgentROA/AIIP/CIRP, the Entity Attestation Token (RFC 9711), OAuth
Transaction Tokens, and Evidence Record Syntax (RFC 4998). Two recent
efforts are worth naming at the architectural level:

- **Agent Authorization Profile for OAuth (AAP).** AAP can express that an
  action *requires* human approval (an `approval_required`-style signal)
  but states that the approval itself is out of scope and is not an
  offline-verifiable artifact. AAP and EP compose cleanly: AAP (or any
  policy layer) signals that approval is required; the EP receipt is the
  evidence that a named human gave it.
- **Decoupled authorization models** (an authorization decision point with
  a standardized input contract). EP's enforcement point consumes such a
  decision; the EP receipt records the human authorization that the
  decision point required.

## 5. Design Invariants

Every component upholds the following, and any profile claiming EP
conformance MUST preserve them:

1. **Named human.** The authorizing party is a real, accountable person
   (or a quorum of distinct persons), not a device, wallet, or vendor key.
2. **Exact action.** The signature covers the precise canonical action
   (tool and arguments), not a coarse scope or capability label.
3. **Offline verifiable.** A third party verifies the receipt without an
   account, without contacting the issuer, and without trusting the
   operator that produced it.
4. **Fail closed.** Absent a valid authorization, the action does not
   execute; absence of a receipt is the anomaly, not the default.
5. **Non-repudiable and tamper-evident.** Altering any covered byte
   invalidates verification; the record survives the issuer's
   disappearance.
6. **Authorization, not wisdom.** EP proves a human authorized the action.
   It does not prove the human understood it, or that the action was
   lawful, wise, or proportional. Necessary, not sufficient.

## 6. Security Considerations

The dominant risk is **over-trust**: treating the existence of a receipt
as proof that an action was legitimate. A receipt proves authorization
occurred at a stated scope, currency, and authority — nothing more.
Deployments and downstream representations MUST NOT overstate it.

EP proves a *key* signed; binding that key to the intended natural person
is the identity-binding trust root (Section 3.6) and the explicit boundary
of the architecture. Coercion of an authorized human, and a human
authorizing an action they did not truly comprehend, are out of scope of
the cryptographic guarantees; device-bound user verification and the
display-fidelity requirements of the component specifications raise but do
not eliminate these. Per-component security considerations are normative
in each component document.

## 7. IANA Considerations

This document has no IANA actions.

## 8. Normative and Informative References

Component specifications: [I-D.draft-schrock-ep-authorization-receipts],
[I-D.draft-schrock-ep-quorum], [I-D.draft-schrock-ep-enforcement-point],
[I-D.draft-schrock-ep-authorization-evidence-chain],
[I-D.draft-schrock-ep-evidence-record], [I-D.draft-schrock-emilia-eye].

Related work: [draft-klrc-aiagent-auth],
[draft-nelson-agent-delegation-receipts], RFC 8785, RFC 4998, RFC 9711.

## Author's Address

Iman Schrock
EMILIA Protocol, Inc.
United States
Email: team@emiliaprotocol.ai
