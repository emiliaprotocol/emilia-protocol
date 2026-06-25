# EP Investor Narrative

## Core thesis

EMILIA Protocol (EP) is infrastructure for one of the most expensive blind spots in modern systems: high-risk actions that occur inside authenticated, approved-looking workflows but are weakly constrained at the action layer.

EP creates the trust-control layer between authentication and execution. It determines whether a specific actor, operating under a specific authority chain, should be allowed to perform a specific high-risk action under a specific policy, exactly once, with replay resistance and immutable event traceability.

## Why this matters

Most damaging failures do not happen because a system had no identity layer. They happen because identity alone was treated as sufficient.

That breaks down in:
- government fraud and administrative overrides
- payment destination and beneficiary changes
- treasury and high-risk disbursement approvals
- privileged enterprise approvals
- delegated software actions
- agent-assisted or autonomous execution

In all of these environments, the missing control is the same: action-level trust enforcement.

## What EP has now accomplished

EP is no longer a broad trust idea. It is now a reference protocol implementation with an internal adversarial code review and open formal-verification models with:
- canonical action binding
- policy-bound decisions
- actor and authority enforcement
- replay resistance
- one-time consumption
- immutable events
- formal conformance surfaces
- Accountable Signoff when policy requires named human ownership
- MCP-native implementation (36 tools, 17 core by default; TypeScript + Python SDKs)
- three independent verifiers — JavaScript, Python, Go — that agree on 8 adversarial cross-language conformance suites (receipts, device signoffs, multi-party quorum, revocation, time-attestation, trust-receipt, provenance, long-term evidence records): the IETF bar for a real standard
- an **Authorization Evidence Chain (EP-AEC)** — specified and implemented (tri-language, with conformance vectors) — that composes EP's human-authorization receipt with the machine-side delegation and policy-permit receipts of the broader IETF cluster into one offline ALLOW/DENY, positioning EP as the verifier-side convergence point rather than one of a dozen competing formats
- production observability stack (structured JSON logging, Sentry on 3 runtimes, graceful shutdown)
- supply chain security (SHA-pinned Actions, SBOM, provenance attestation on every release)

**Internal adversarial code audit: 100/100** (2026-04-02) — all 10 categories scored at maximum: formal verification, test quality, documentation, security, CI/CD, developer experience, MCP server, performance, licensing, and production readiness.

Reconciliation proof:
- 4,220 automated tests across 173 files
- 26 TLA+ safety properties verified (TLC 2.19, 413,137 states, 0 errors); 35 Alloy facts + 22 assertions verified (Alloy 6.0.0, 0 counterexamples) — both run in CI on every change
- 85 red team cases documented; 31 security findings identified and remediated
- Stryker.js mutation testing — ≥80% kill threshold on protocol core
- 19 fast-check property-based tests covering protocol invariants generatively
- Full 7-step Accountable Signoff chain proven end-to-end under load
- 329 complete chains executed with zero correctness violations
- 11/11 post-load-test DB integrity checks passing
- Zero duplicate consumptions, zero orphaned bindings, zero missing events
- All endpoints use single-roundtrip atomic RPCs
- Database: 46 EP-only tables, zero foreign artifacts
- Staircase load tested: 10 → 50 → 100 → 200 → 500 concurrent users; handshake create p95 575ms at 50 VUs
- CI quality gates across ~13 automated workflows, all Actions SHA-pinned
- **Independently re-verified by an outside implementer (June 2026):** a third party ran the public crash-test and the cross-language conformance harness on their own machine — offline receipt verification, forged-copy rejection, and JS/Python/Go agreement all confirmed. The first external reliance event, and the strongest possible signal for a verifiability claim. *(Now public: the implementer posted the verification to the IETF authorization-evidence survey thread — on the record, independently runnable.)*

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
- **healthcare** — the high-alert-medication *independent double-check* and capital procurement, where EP's two-person rule is *already mandated practice* (ISMP / Joint Commission). Receipts are PHI-free by construction, and the same primitive answers EU AI Act Article 14 human-oversight for high-risk medical AI. Entry is via the healthcare-AI vendors and procurement platforms (B2B2H), not direct hospital sales.

## Investor one-liners

- Identity tells you who is acting. EP tells you whether this exact high-risk action should be allowed.
- The market is moving from access control to action control.
- EP becomes more valuable as enterprises and governments automate more decisions and more execution.
- EP is the trust-control layer between authentication and execution.
- A dozen efforts are racing to define "a receipt for an agent's action." EP defined the layer that **composes them** — and supplies the one leg none of the others do: a named human's authorization.

## Business model

The protocol remains open while the company builds monetizable layers around it:
- managed policy and control plane
- hosted verification and signoff orchestration
- workflow integrations
- sector-specific policy packs
- audit and evidence tooling
- enterprise deployment and support

## The long-term arc — why EP becomes inevitable, not just useful

The near-term wedge and the long-term moat are different things, and both are now evidenced from the field.

**The wedge that's converting: the verifiability gap.** The strongest signal is not "buyers want receipts" — it is that the people who *write oversight requirements* recognize, in one sentence, a problem they already have: **human oversight is easy to require and almost impossible to verify after the fact.** A California legislative committee consultant called this "very interesting" on first contact; a Joint Legislative Audit Committee staffer engaged against a $500M state fraud finding. EP turns "a human was in the loop" from an unfalsifiable claim into checkable evidence.

**The moat: bounded claims, in the one market where honesty compounds.** Stating precisely what a receipt proves and does *not* prove is not a weakness — it is the entry credential into the only buyers that matter here (auditors, insurers, regulators), for whom an overselling competitor is disqualified the first time a claim fails under review, in a small community that talks. Honesty is the wedge into the skeptics; the durable moat underneath is open-core: the **format and verifier are free and permissionless** (that creates ubiquity), while the **operated trust root** — enrollment/approver directory, federated transparency log, revocation, compliance-grade evidence pipelines — is the revenue layer an organization cannot casually self-host.

**The 5-year object: one verifiable receipt that carries everything that matters about an irreversible action —**
- *who/what acted* — the agent's identity and its delegated authority (EP composed with a delegation layer such as DRP): the action carries a checkable "this agent was authorized to attempt this at all";
- *who approved* — one or a quorum of named humans, device- and biometric-bound (the two-person rule, shipped today);
- *bound to exactly what* — the canonical action hash, offline-verifiable forever;
- *provably unaltered* — tamper-**evident** custody in an append-only transparency log (a public anchor of the log *root* is optional; the data never goes on-chain);
- *with anomalies surfaced* — an advisory layer flagging velocity, rubber-stamping, structuring, and off-pattern approvals to **escalate** scrutiny, never to relax the deterministic gate.

**Why inevitable.** Capability does not make a standard inevitable — public-key cryptography existed two decades before the browser padlock made its absence unacceptable. EP becomes obvious the same way: when a party with leverage makes the *absence* of a receipt unacceptable — an insurer's coverage condition on wire/benefit fraud, an auditor's controls framework, or a government AI-auditor registry (e.g., California AB-1405, which stands up an enrolled AI-auditor profession that needs something verifiable to audit against). The path is **precedent → recommendation → requirement.**

**Design principles that keep this defensible:** EP binds, records, and verifies — it does not own the workflow, mint the identities, or become the dashboard. It composes with whatever agent-identity and policy standards win. It claims tamper-**evidence**, never tamper-proof. It is offline-verifiable, so a receipt stays valid even if EMILIA disappears — which is exactly why third parties can build on it without permission.
