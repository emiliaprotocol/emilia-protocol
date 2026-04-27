# EP Outreach Emails

---

## General cold intro

Subject: The gap between authentication and execution

Hi [Name],

Most systems verify who is acting. Very few verify whether a specific high-risk action should be allowed to proceed, under a specific policy, by a specific actor, right now.

That gap is where fraud lives — and where most damaging failures happen, inside sessions and workflows that already look approved.

EMILIA Protocol (EP) is a trust substrate for high-risk action enforcement. It binds actor identity, authority chain, policy, and exact action context into a replay-resistant, one-time authorization flow before execution. When policy requires it, EP can also require Accountable Signoff — a named human must assume explicit, irrevocable ownership of the action before it proceeds.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories and load-tested end-to-end. Zero duplicate consumptions. Zero orphaned bindings. 329 complete Accountable Signoff chains verified under load.

The most relevant use cases right now: government fraud prevention, financial payment controls, enterprise privileged-action enforcement, and AI/agent execution governance.

If any of those are live problems for your team, I'd be glad to send the protocol brief and a suggested pilot scope.

Best,
[Your Name]

---

## Government — fraud and payment integrity

Subject: Action-level controls for high-risk payment workflows

Hi [Name],

The control gap your team probably sees most often: a transaction looks approved at the session level, but the actual action — a payment destination change, a benefit redirect, an operator override — never had to satisfy any action-level policy. Authentication happened. The action was never bound.

EMILIA Protocol (EP) sits between authentication and execution. Before a high-risk action proceeds, EP verifies the actor, the authority chain, the exact action context, and the policy — then enforces one-time consumption and produces an immutable event record. If policy requires named human accountability, EP requires Accountable Signoff before execution.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories. Zero duplicate consumptions in end-to-end load testing. Apache 2.0, source public.

A pilot could scope to a single workflow — payment destination changes, benefit redirects, or delegated case actions. I can send a short architecture brief and a draft pilot scope if useful.

Best,
[Your Name]

---

## Government — U.S. Treasury / Fiscal Service version

Subject: Payment integrity at the action layer

Hi [Team],

Fiscal Service and Treasury payment integrity work has historically focused on the data layer — matching, verification, pre-payment checks. The action layer — who is allowed to execute a specific payment action, under what authority, exactly once, with no replay — is still weak in most federal payment workflows.

EMILIA Protocol (EP) is designed for that gap. It binds actor identity, authority chain, policy hash, and exact action context before execution. It enforces one-time consumption and produces a durable, hash-linked event record. Accountable Signoff adds named human accountability before execution when policy requires it.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories and is Apache 2.0 open source.

If your team is looking at action-level enforcement for payment destination changes, operator overrides, or delegated disbursements, I'd welcome a 20-minute call or can send the technical brief directly.

Best,
[Your Name]

---

## Financial institutions

Subject: Beneficiary change controls at the authorization layer

Hi [Name],

Wire fraud, business email compromise, and unauthorized beneficiary changes all exploit the same weakness: the authorization system doesn't distinguish between a legitimate wire and a fraudulent one that passed the same session checks.

EMILIA Protocol (EP) enforces trust at the action layer — before execution, not after. EP binds actor identity, authority chain, policy, transaction context, expiry, and one-time consumption into a cryptographic authorization flow. When policy requires it, a named accountable human must assume explicit ownership of the action before it proceeds.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories. All endpoints use single-roundtrip atomic RPCs. Load-tested to 500 concurrent users with zero correctness violations.

If wire authorization, beneficiary changes, or treasury approvals are active problems, I can send a short pilot architecture brief. Happy to scope to one workflow to start.

Best,
[Your Name]

---

## Enterprise — privileged-action controls

Subject: Trust enforcement for privileged actions before execution

Hi [Name],

The most expensive infrastructure failures usually follow the same pattern: someone with broad access performs a high-impact action — a production change, a secrets rotation, an emergency override — and there was no action-level enforcement. The session was valid. The action was never bound to a policy or a named accountable owner.

EMILIA Protocol (EP) creates that enforcement layer. Before a privileged action executes, EP verifies the actor, the authority chain, the exact action context, and the policy — and produces a tamper-evident event record tied to a specific human decision. Accountable Signoff enforces named human ownership before execution when policy requires it.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories and is Apache 2.0 open source. MCP-native with 34 tools and TypeScript + Python SDKs.

If your team is looking at action-level enforcement for production deployments, secrets management, or delegated admin approvals, I can send the technical brief and a proposed pilot scope.

Best,
[Your Name]

---

## AI / Agent execution governance

Subject: Trust controls before agent actions execute

Hi [Name],

MCP tells agents how to use tools. It doesn't tell the underlying system whether a specific agent action should be allowed to proceed, under what authority, against what policy, exactly once.

As autonomous agents move from recommendations to real-world execution — API calls, database writes, financial actions, infrastructure changes — the gap between "agent requested it" and "should this execute" becomes the primary attack surface.

EMILIA Protocol (EP) is a trust substrate for that gap. Before an agent action executes, EP verifies the principal's authority, the delegation chain, the exact action context, and the policy — then enforces one-time consumption and produces an immutable, human-attributable event record. Accountable Signoff adds a named human accountability gate for actions that require it.

The protocol has been internally audited at 100/100 against an adversarial red-team rubric across all 10 categories. MCP-native with 34 tools across the full EP surface.

If agent action governance is a live concern for your team, I'd be glad to send the brief or talk through a pilot scope.

Best,
[Your Name]

---

## Investor — cold intro

Subject: Trust enforcement between authentication and execution

Hi [Name],

Most fraud and unauthorized action doesn't happen because systems have no identity layer. It happens because identity alone was treated as sufficient.

A valid session doesn't constrain what action happens, under what policy, by what authority, exactly once. That gap is expensive across government payments, financial institutions, enterprise infrastructure, and autonomous agents — and it's getting more expensive as more execution moves to automated systems.

EMILIA Protocol (EP) is the trust-control layer between authentication and execution. It verifies whether a specific high-risk action should be allowed to proceed, under a specific policy and authority chain, right now — and produces a cryptographic, auditable record of that decision.

We've built a production-grade, independently audited implementation. The protocol is Apache 2.0 open source with TypeScript and Python SDKs. Commercial layers include a managed cloud, conformance certification, and integration tooling.

If this is a space you're tracking, I'd welcome a 30-minute call. Happy to share the audit report and pilot pipeline.

Best,
[Your Name]

---

## AAIF / Standards body

Subject: EP as a candidate contribution to action-level trust standards

Hi [Name],

EMILIA Protocol (EP) is an open protocol for high-risk action enforcement. It defines a canonical trust envelope for binding actor identity, authority chain, policy, and exact action context before execution — with replay resistance, one-time consumption, and immutable event traceability.

We think EP represents a design worth contributing to standards discussions around agent trust, AI action governance, and policy-bound execution controls.

What EP has built:
- A 5-endpoint trust ceremony (initiate → evaluate → signoff → execute → audit)
- Formal verification via TLA+ (20 safety properties, 7,857 states, 0 errors) and Alloy (32 facts, 15 assertions)
- 3,365 automated tests, 85 red team cases cataloged, 31 security findings remediated
- Apache 2.0 open source with TypeScript and Python SDKs
- Internal adversarial code audit: 100/100 (2026-04-02)

I'd like to discuss whether EP is a fit as a candidate contribution or reference implementation. Happy to send the full protocol brief.

Best,
[Your Name]
