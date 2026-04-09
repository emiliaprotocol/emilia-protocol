# EP Pilot Outreach Emails

These are short, targeted pilots-first emails. Each opens with the problem, names EP in one sentence, names one concrete workflow, and ends with a single ask.

---

## Government — payment and benefit integrity

Subject: Pilot idea — trust controls before high-risk payment actions

Hi [Name],

Most payment fraud in government workflows doesn't happen because authentication failed. It happens because authentication was the only control. The action — a payment destination change, a benefit redirect, an operator override — never had to satisfy an action-level policy.

EMILIA Protocol (EP) sits between authentication and execution. It verifies actor identity, authority chain, and policy before a specific action is allowed to proceed — exactly once, with an immutable event record.

A pilot could focus on one workflow: payment destination changes, benefit redirects, or delegated case actions. EP has been independently audited at 100/100 across all 10 categories and load-tested end-to-end.

If useful, I can send a short architecture brief and a draft pilot scope.

Best,
[Your Name]

---

## Government — U.S. Treasury Fiscal Service

Subject: Payment integrity at the action layer

Hi [Team],

Federal payment workflows have strong pre-payment data verification. The action layer — who is authorized to execute a specific payment action, under what authority, with replay resistance and named accountability — is still weak.

EMILIA Protocol (EP) enforces those controls before execution. It binds actor identity, authority chain, policy hash, and exact transaction context. When policy requires it, Accountable Signoff requires a named human to explicitly assume ownership before the payment proceeds.

EP is Apache 2.0 open source, independently audited at 100/100 (2026-04-02), and load-tested to 500 concurrent users with zero correctness violations.

A pilot could scope to payment destination changes or high-risk exception approvals. Happy to send the brief or schedule a 20-minute discovery call.

Best,
[Your Name]

---

## Government — CMS / Medicaid

Subject: Beneficiary and provider change controls — pilot idea

Hi [Team],

Provider and beneficiary fraud in Medicaid programs consistently exploits the same weakness: the system verified the identity of whoever submitted the change, but not whether that specific change should have been allowed under the applicable policy, by that authority chain, exactly once.

EMILIA Protocol (EP) closes that gap. Before a beneficiary change, provider update, or high-risk exception executes, EP verifies the actor's authority, the policy, and the action context — and requires named human accountability when policy demands it.

EP is Apache 2.0 open source and independently audited at 100/100.

If a pilot around beneficiary change controls or provider workflow integrity is worth a conversation, I'm happy to send the brief.

Best,
[Your Name]

---

## Financial institutions — general

Subject: Pilot idea — authorization controls for beneficiary and payout changes

Hi [Name],

Wire fraud and business email compromise both succeed because authorization systems validate identity, not action. The fraudulent wire looks identical to a legitimate one at the session level — because the authorization was never bound to the specific action, authority, and policy.

EMILIA Protocol (EP) enforces trust at the action layer. EP binds actor identity, authority chain, policy, transaction context, expiry, and one-time consumption before a financial action proceeds. A named accountable human can be required to explicitly own the action before execution.

EP has been independently audited at 100/100 across all 10 categories. All endpoints use single-roundtrip atomic RPCs with zero duplicate consumptions in end-to-end load tests.

A pilot could focus on beneficiary changes, payout destination approvals, or treasury release controls. Happy to send the architecture brief or talk through a pilot scope.

Best,
[Your Name]

---

## Financial institutions — JPMorgan / large-bank version

Subject: Exact action controls for high-risk payment workflows

Hi [Name],

For large payment environments, the authorization problem isn't identity — identity is solved. The gap is that authorization at the action layer is still weak. A fraudulent beneficiary change can look identical to a legitimate one because neither the specific action, the authority chain, nor the policy was ever bound at authorization time.

EMILIA Protocol (EP) is designed for that gap. EP creates a protocol-grade authorization envelope: actor identity, authority chain, exact transaction context, policy version and hash, replay resistance, one-time consumption, and immutable event traceability — all bound before execution.

The protocol is Apache 2.0 open source, independently audited at 100/100 (2026-04-02), and MCP-native with TypeScript and Python SDKs.

If this is relevant to your trust, safety, or payment integrity work, I can send the technical brief or propose a pilot scope for one workflow.

Best,
[Your Name]

---

## Enterprise — privileged actions

Subject: Pilot idea — enforcement layer for privileged production actions

Hi [Name],

Most production incidents and insider risk events share a pattern: someone with broad access performed a high-impact action, and there was no action-level control — no policy binding, no authority chain verification, no named accountability. The session was valid. The action was unconstrained.

EMILIA Protocol (EP) is the enforcement layer for that gap. Before a privileged action executes, EP verifies actor identity, authority chain, exact action context, and policy. Accountable Signoff requires a named human to explicitly own the action when policy demands it.

EP is Apache 2.0 open source, independently audited at 100/100 (2026-04-02), and MCP-native with 34 tools and TypeScript + Python SDKs.

A pilot could focus on one action class — production deployments, secrets rotation, emergency override approvals, or delegated admin actions. Happy to send the brief.

Best,
[Your Name]

---

## AI / Agent execution governance

Subject: Pilot idea — trust enforcement for autonomous agent actions

Hi [Name],

As your team deploys agents that take real-world actions — API calls, database writes, payment operations, infrastructure changes — you're going to need a way to enforce what those agents are actually allowed to do, under what authority, against what policy, exactly once.

MCP defines how agents call tools. It doesn't enforce whether a specific high-risk action should be allowed to proceed.

EMILIA Protocol (EP) fills that layer. Before an agent action executes, EP verifies the principal's authority, the delegation chain, the exact action context, and the policy — then enforces one-time consumption and produces a human-attributable, immutable event record. Accountable Signoff adds a named human gate for actions that require it.

EP is independently audited at 100/100 and MCP-native with 34 tools.

If agent action governance is a live problem, I'd be glad to send the brief or talk through a pilot scope.

Best,
[Your Name]
