# EP Pilot Outreach Emails

## Government

Subject: Pilot idea — payment integrity and operator override controls

Hi [Name],

I’m reaching out because I think your team may be facing a control gap that EMILIA Protocol (EP) is built to address.

EP is a protocol-grade trust substrate for high-risk action enforcement. It sits between authentication and execution and determines whether a specific actor, under a specific authority chain, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and durable traceability.

A pilot could focus on one workflow such as:
- payment destination changes
- benefit redirects
- operator overrides
- delegated case actions

EP has been independently audited at 100/100 (2026-04-02) across all 10 categories, and load-tested end-to-end: 329 complete Accountable Signoff chains with zero correctness violations, 3,277 automated tests across 125 files, and 31 security findings identified and remediated.

If useful, I can send a short architecture brief and proposed pilot scope.

Best,
[Your Name]

## Financial institutions

Subject: Pilot idea — beneficiary and payout-control architecture

Hi [Name],

EMILIA Protocol (EP) is infrastructure for a specific control problem: high-risk actions that occur inside approved-looking workflows but are weakly constrained at the action layer.

EP binds actor identity, authority chain, policy, exact transaction context, nonce, expiry, and one-time consumption before a financial action is allowed to proceed.

A pilot could focus on:
- beneficiary changes
- payout destination changes
- vendor remittance updates
- treasury approvals

EP has been independently audited at 100/100 (2026-04-02) across all 10 categories. Load-tested end-to-end: all endpoints use single-roundtrip atomic RPCs, handshake p95 87ms at 500 concurrent users, zero duplicate consumptions, zero orphaned bindings, and 11/11 post-load-test DB integrity checks passing.

If relevant, I’d be glad to send a short technical brief and pilot outline.

Best,
[Your Name]

## Enterprise

Subject: Pilot idea — privileged-action control before execution

Hi [Name],

EMILIA Protocol (EP) is designed to enforce trust before high-risk action in workflows where broad access is not enough.

A pilot could focus on one enterprise action class such as:
- privileged production changes
- secrets rotation
- emergency override approvals
- delegated admin actions

EP has been independently audited at 100/100 (2026-04-02) across all 10 categories: 116 red team cases documented, 20 TLA+ safety properties machine-verified in CI, Stryker.js mutation testing at ≥80% kill threshold, MCP-native with 34 tools and TypeScript + Python SDKs, and database isolated to 46 EP-only tables with zero foreign artifacts.

If useful, I can send a short brief and pilot architecture.

Best,
[Your Name]
