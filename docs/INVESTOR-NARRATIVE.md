# EP Investor Narrative

## Core thesis

EMILIA Protocol (EP) is infrastructure for one of the most expensive blind spots in modern systems: high-risk actions that occur inside authenticated, approved-looking workflows but are weakly constrained at the action layer.

EP creates the trust-control layer between authentication and execution. It determines whether a specific actor, operating under a specific authority chain, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance, one-time consumption, and immutable event traceability.

## Why this matters

Most damaging failures do not happen because a system had no identity layer. They happen because identity alone was treated as sufficient.

That breaks down in:
- government fraud and administrative overrides
- payment destination and beneficiary changes
- treasury and high-risk disbursement approvals
- privileged enterprise actions
- delegated software actions
- agent-assisted or autonomous execution

In all of these environments, the missing control is the same: action-level trust enforcement.

## What EP has accomplished

EP is no longer a broad trust idea. It is a shipping product with protocol-grade internals.

**Protocol core** — canonical action binding, policy-bound decisions, actor and authority enforcement, replay resistance, one-time consumption, immutable events, formal conformance surfaces, and Accountable Signoff for named human accountability when policy requires it.

**EP Cloud control plane** — the revenue engine, now built:
- Policy management with versioning, simulation, and staged rollout
- Event explorer with full-text search and timeline reconstruction
- Signoff orchestration dashboard with pending queue, analytics, and escalation
- Tenant management with environment separation and API key isolation
- Alerting with threshold, anomaly, absence, and pattern rules
- Webhooks with HMAC-SHA256 signatures and exponential backoff retry

**SDKs shipped** — TypeScript and Python, zero dependencies, 10 protocol methods plus 15 cloud methods. Integration in 5 lines of code.

**Vertical packs** — pre-built policy configurations across three pricing tiers:
- Government Control Pack: benefits fraud detection, operator override controls, IG/GAO audit readiness
- Financial Control Pack: wire transfer protection, dual signoff enforcement, SOX evidence generation
- Agent Governance Pack: risk classification, signoff thresholds, EU AI Act mapping

**Engineering proof points:**
- 1,511 tests across 58 files
- 14 CI quality gates including write discipline, invariant coverage, and language governance
- 19 TLA+ safety theorems, 32 Alloy facts, 15 assertions
- 85 red team cases with zero write discipline exceptions
- Protocol-grade refactor: single sha256, single actor resolver, bounded caches, deterministic idempotency

## Product differentiator: Accountable Signoff

Accountable Signoff is what turns EP from a strong handshake into a complete trust-control substrate. Most trust systems stop at machine verification. EP adds named human accountability — a specific person, under a specific policy, approving a specific action, with an immutable record that the approval happened and who owned it. This is the gap that auditors, regulators, and compliance teams cannot close with identity or workflow tools alone.

## Why now

1. **Fraud is moving inside approved workflows.** Valid sessions and approved-looking flows are no longer enough.
2. **AI and automation increase execution risk.** As systems move from recommendation to action, institutions need stronger controls between intent and execution.
3. **Buyers increasingly want evidence, not assertions.** EP produces policy-bound, auditable trust decisions that can be reconstructed later.

## Market wedge

EP should be positioned first around high-risk action enforcement in:
- government fraud prevention
- financial infrastructure and payment-change fraud
- high-risk enterprise approvals
- agent execution controls

## Investor one-liners

- Identity tells you who is acting. EP tells you whether this exact high-risk action should be allowed.
- The market is moving from access control to action control.
- EP becomes more valuable as enterprises and governments automate more decisions and more execution.
- EP is the trust-control layer between authentication and execution.

## Business model

The protocol remains open while the company monetizes the control plane and vertical packs:
- **EP Cloud** — managed policy engine, signoff orchestration, event exploration, alerting, and webhooks
- **Vertical packs** — pre-built policy configurations for government, financial, and agent governance use cases at three pricing tiers
- **SDKs** — TypeScript and Python with zero-dependency integration
- Audit and evidence tooling
- Enterprise deployment and support
