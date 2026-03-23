# EMILIA Protocol (EP) — Proposal for AAIF Consideration

EMILIA Protocol is an open protocol for pre-action trust enforcement in machine-mediated systems. While agent safety is one wedge, EP applies equally to government fraud prevention and financial infrastructure controls — anywhere high-risk actions require policy-bound authorization before execution.

EP Core defines interoperable objects for trust-relevant evidence, trust state, and trust decisions:
- Trust Receipt
- Trust Profile
- Trust Decision

EP Extensions add stronger enforcement where systems must control whether a specific high-risk action should proceed. The most important extension is Handshake, which binds actor identity, authority, policy, action context, nonce, expiry, and one-time consumption into a replay-resistant authorization flow.

When policy requires named human ownership, EP can also require **Accountable Signoff** before execution.

This proposal asks AAIF to consider EP Core as a minimal interoperable trust-decision interface, while recognizing pre-action enforcement as a key extension area for agent systems operating in high-risk environments.

## Why AAIF should care

As systems move from recommendation to execution, the missing governance layer is not only model quality. It is action control.

MCP tells agents how to use tools. EP tells systems whether a high-risk action should be allowed to proceed.

EP is especially relevant where:
- delegated autonomy intersects with regulated workflows
- high-risk actions require policy-bound, replay-resistant authorization
- human ownership must remain attributable even in agent-assisted systems
- government benefit disbursement requires pre-action fraud prevention
- financial infrastructure demands enforceable control gates before transactions execute

## Accountable Signoff

Accountable Signoff is EP's strongest differentiator for AAIF. It provides named human accountability for agent-initiated high-risk actions — not generic human-in-the-loop, not MFA. Each signoff is action-specific, policy-bound, and non-replayable.

The flow is **challenge / attest / consume**:
1. The system issues a challenge bound to a specific action, actor, policy, and nonce
2. A named human attests using a cryptographically bound signoff method
3. The signoff is consumed exactly once — replay is structurally impossible

EP supports 5 signoff methods:
- `passkey` — FIDO2/WebAuthn hardware or platform key
- `secure_app` — dedicated authenticator application
- `platform_authenticator` — OS-level biometric (Touch ID, Windows Hello)
- `out_of_band` — separate channel confirmation (e.g., SMS, push)
- `dual_signoff` — two independent humans must both attest

Policy drives which actions require signoff and at what assurance level. A wire transfer above a threshold might require `dual_signoff`. A routine data lookup might require no signoff at all. The protocol enforces the policy; the deployer defines it.

## Proof of engineering maturity

EP is not a whitepaper. It is a working, tested, formally verified protocol implementation:

- **1,511 tests** across **58 files** — covering core, extensions, edge cases, and adversarial scenarios
- **19 TLA+ safety theorems** — formal verification of protocol invariants (no double-spend, no replay, no unauthorized escalation)
- **32 Alloy facts, 15 assertions** — structural constraint verification across protocol states
- **85 red team cases** — adversarial test suite covering replay, escalation, bypass, and timing attacks
- **14 parallel CI quality gates** — every merge is validated across lint, type-check, unit, integration, formal verification, and security scanning
- **Zero write-discipline exceptions** — `SERVICE_CLIENT_ALLOWLIST` is empty; no component bypasses the trust boundary

## EP Cloud

EP Cloud is the managed control plane for deploying EP in production:
- Policy management — define, version, and deploy trust policies
- Event explorer — inspect trust decisions, handshake flows, and signoff events
- Signoff orchestration — route signoff challenges to the right humans via the right methods
- Tenant management — multi-tenant isolation for SaaS and enterprise deployments
- Alerting and webhooks — real-time notification on policy violations, signoff failures, and anomalous patterns

## SDKs

EP ships TypeScript and Python SDKs — zero external dependencies, designed for embedding in any stack:
- **10 protocol methods** — core trust operations (create receipt, evaluate profile, issue decision, initiate handshake, challenge, attest, consume, etc.)
- **15 cloud methods** — policy CRUD, event queries, signoff orchestration, tenant management, webhook configuration

## Positioning

EP is pre-action trust enforcement for high-risk workflows. Agents are one wedge, but EP's architecture is workflow-agnostic:

- **Agent safety** — enforce trust gates before tool execution, with accountable signoff when policy requires human ownership
- **Government fraud prevention** — pre-action controls on benefit disbursement, eligibility verification, and claims processing
- **Financial infrastructure** — enforceable authorization gates on wire transfers, account changes, and high-value transactions

The protocol does not assume the actor is an agent, a human, or a hybrid. It assumes the action is high-risk and the system needs a policy-bound decision before proceeding.
