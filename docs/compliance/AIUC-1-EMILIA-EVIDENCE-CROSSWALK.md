<!-- SPDX-License-Identifier: Apache-2.0 -->

# AIUC-1 to EMILIA implementation and evidence crosswalk

**AIUC-1 baseline:** July 15, 2026 release

**Controls in scope:** D003, B006, and E015

**Repository review date:** July 21, 2026

**Status:** Public evidence map; not a certification or audit opinion

This document maps the current AIUC-1 subcontrols below to public EMILIA code,
configuration, tests, and operational guidance already present in this
repository. It is deliberately a repository-coverage assessment, not a claim
that any deployment satisfies AIUC-1.

## Primary AIUC-1 sources

- [D003 — Restrict unsafe tool calls](https://www.aiuc-1.com/reliability/restrict-unsafe-tool-calls)
- [B006 — Prevent unauthorized AI agent actions](https://www.aiuc-1.com/security/enforce-contextual-access-controls)
- [E015 — Log AI system activity](https://www.aiuc-1.com/accountability/log-model-activity)
- [AIUC-1 changelog](https://www.aiuc-1.com/changelog)

The changelog identifies July 15, 2026 as the current release. It specifically
records a revision to B006.3 extending execution-level safeguards to
agent-executed code as well as first-party MCP servers. The current control
pages, rather than descriptions from an earlier release, are therefore the
source for the subcontrol language summarized here.

## How to read the status

| Status | Meaning in this document |
| --- | --- |
| **Implemented** | The repository contains a direct technical mechanism for the subcontrol's evidence objective and corresponding verification code or tests. Production configuration and operating effectiveness still require deployment evidence. |
| **Partial** | EMILIA supplies a relevant mechanism or evidence component, but the repository does not establish the full agent-system, deployment, or operational scope described by the subcontrol. |
| **Gap** | No qualifying implementation or completed operational evidence artifact was found in the public repository. Related telemetry or tooling is not counted as completion. |

The rows below are assessed individually. They are intentionally not reduced
to one coverage score: AIUC distinguishes primary evidence from examples that
may supplement it, and a repository count would give those categories false
equivalence. Every label describes only the public repository state reviewed
on the date above; none is an AIUC determination.

## D003 — Restrict unsafe tool calls

AIUC-1 describes D003 as a preventive requirement for keeping tool calls from
performing unauthorized actions, reaching restricted information, or acting
beyond intended scope.

| Subcontrol | Status | EMILIA implementation and evidence | Verification boundary |
| --- | --- | --- | --- |
| **D003.1 — Tool authorization and validation** | **Implemented** | [`gateMcpTool()`](../../packages/gate/src/mcp.ts) constructs a `{ protocol, tool }` selector and calls `gate.run()` before the wrapped handler. The [action-control manifest](../../packages/gate/src/action-control-manifest.ts) binds tool selectors to receipt, assurance, replay, and system-of-record field requirements. The [Gate check path](../../packages/gate/src/index.ts) verifies signature, freshness, action, assurance, pinned business policy and approvers, execution-field binding, and one-time reservation before an effect. [`verifyExecutionBinding()`](../../packages/gate/src/execution-binding.ts) compares the signed claim with executor-observed material fields. The [scanner](../../packages/scan/src/index.ts) inventories visible MCP/OpenAPI actions and defaults unclassified mutating actions to receipt-required review. Negative and success paths are exercised in [MCP tests](../../packages/gate/mcp.test.ts) and [Gate tests](../../packages/gate/gate.test.ts). | This covers tools actually wrapped by the Gate and correctly represented in the deployed manifest. It does not prove that every agent tool, MCP server, alternate API path, or direct backend credential is mediated. EMILIA validates authorization and material action binding; the deployer must also validate each tool's complete input/output schema and eliminate bypass paths. |
| **D003.2 — Rate limits for tools** | **Partial** | The [capability-receipt runtime](../../packages/gate/src/capability-receipt.ts) signs a monetary budget and atomically reserves spend before execution; the Postgres store refuses operations that exceed the remaining budget. [Capability tests](../../packages/gate/capability-receipt.test.ts) cover budget exhaustion, immutable action scope, duplicate operations, and indeterminate effects. A separate [API rate limiter](../../lib/rate-limit.ts) provides time-windowed quotas for protocol writes and other endpoint classes. | The budget control applies to capability-backed amount/currency actions, not every MCP tool. The API limiter is endpoint-category based and is not wired by `gateMcpTool()` as a general per-tool quota or circuit breaker. A deployment needs evidence that every in-scope tool has an appropriate rate, count, value, or transaction cap and that the durable limiter is active. |
| **D003.3 — Tool call log** | **Partial** | The [Gate decision and execution log](../../packages/gate/src/index.ts) records timestamp, action, selector (including MCP protocol/tool when supplied), allow/refuse reason, receipt and subject identifiers, assurance tier, policy/tenant/approver evaluation, observed-action hash, execution outcome, and the authorization-to-execution link. The [hash-chained evidence log](../../packages/gate/src/evidence.ts) records allows and denials and fails closed on strict-log failure. The [SIEM mapper and forwarder](../../packages/gate/src/siem.ts) exports OCSF API Activity or CEF events; [SIEM tests](../../packages/gate/siem.test.ts) exercise deny, allow, execution, malformed-entry, and delivery-failure cases. | Logging is complete only for calls routed through this Gate. The default evidence deliberately records an action hash rather than cleartext parameters and does not universally record an originating MCP server identity, tool version, full handler result, or model context. SIEM forwarding is optional and non-blocking; the operator must prove configuration, delivery monitoring, and alert handling. |
| **D003.4 — Human-approval workflows** | **Implemented** | The [MCP wrapper](../../packages/gate/src/mcp.ts) refuses a guarded call without a valid, unused human or quorum receipt before invoking the handler. The [Gate verifier](../../packages/gate/src/index.ts) re-verifies Class-A WebAuthn or quorum evidence against pinned keys, RP/origin context, assurance requirements, exact action fields, and one-time consumption. The [secure-app signoff core](../../apps/secure-app/lib/ep-signoff.ts) binds a device-key approval to the canonical authorization context. [MCP tests](../../packages/gate/mcp.test.ts), [Gate assurance tests](../../packages/gate/gate.test.ts), and the [secure-app signoff test](../../apps/secure-app/lib/ep-signoff.test.mjs) cover missing approval, low assurance, tampering, action drift, replay, and successful approval. | The deployed policy determines which operations require a human or quorum. EMILIA proves cryptographic action binding and the configured credential ceremony; it does not establish real-world identity proofing, authority assignment, comprehension, voluntariness, or that the signing UI rendered the action faithfully. Those require deployer evidence. |
| **D003.5 — Tool call log reviews** | **Gap** | No completed, periodic tool-usage review record was found. The [SIEM export](../../packages/gate/src/siem.ts) and [Gate metrics](../../packages/gate/src/metrics.ts) can provide review inputs, but neither is evidence that a scheduled review occurred or that permissions and tools were changed as a result. | Close this gap with dated review records identifying scope and period, reviewer and approval, queries or samples used, anomalies and unauthorized attempts examined, permission changes, and tools retained, restricted, deprecated, or retired with rationale. A dashboard or raw log alone is not a review record. |

## B006 — Prevent unauthorized AI agent actions

AIUC-1 describes B006 as a preventive requirement for keeping agents within
their intended scope and authorized privileges.

| Subcontrol | Status | EMILIA implementation and evidence | Verification boundary |
| --- | --- | --- | --- |
| **B006.1 — Agent service access restrictions** | **Partial** | The [production Gate configuration](../../apps/gate-service/src/production-config.ts) requires authenticated requests, pins tenant/gate evidence scope, and allowlists repositories for the reference GitHub deletion service. The [request authenticator](../../apps/gate-service/src/auth.ts) enforces one bearer credential with constant-time comparison, while the [service routes](../../apps/gate-service/src/routes.ts) authenticate protected routes and reject unknown methods and paths. The [Helm NetworkPolicy](../../packages/gate/deploy/helm/emilia-gate-service/templates/networkpolicy.yaml) defaults ingress and egress to explicit peers/CIDRs, and the [reference values](../../packages/gate/deploy/helm/emilia-gate-service/values.yaml) separate Postgres, GitHub, KMS, and SIEM destinations. At the tool boundary, [`gateMcpTool()`](../../packages/gate/src/mcp.ts) limits execution to explicitly wrapped handlers and manifest policy. | The concrete service restrictions cover the reference Gate service, not an organization's complete agent backend or MCP registry. The chart is configurable and does not prove the installed cluster policy. The generic library does not itself maintain a global approved-MCP-server inventory or revoke agent credentials outside Gate. Operators must show the service inventory, network/API policy, credential scope, and absence of direct paths around Gate. |
| **B006.2 — Agent security monitoring and alerting** | **Partial** | Every Gate decision, including refusals, is recorded by the [evidence log](../../packages/gate/src/evidence.ts). The [runtime monitor](../../packages/gate/src/runtime-monitor.ts) detects authorization/effect ordering, double-consumption, and signoff-binding divergence, emits a `SPEC_DIVERGENCE` event, and enters fail-closed degraded or lockdown mode; [runtime-monitor tests](../../packages/gate/runtime-monitor.test.ts) cover those transitions. The [SIEM integration](../../packages/gate/src/siem.ts) turns denial and execution records into security events. The [Gate service runtime](../../apps/gate-service/src/runtime.ts) forwards telemetry and counts successful and dropped deliveries. | The process-local monitor keeps a bounded buffer unless an operator wires `onDivergence` to durable storage. SIEM forwarding is optional, and the repository does not include deployment-specific alert rules, recipients, escalation policy, dashboard evidence, or proof that dropped telemetry is alarmed. Monitoring covers Gate-observed activity, not every agent connection. |
| **B006.3 — Execution-level safeguards** | **Partial** | The [MCP wrapper](../../packages/gate/src/mcp.ts) is a pre-execution hook that refuses before the real handler. The [Gate lifecycle](../../packages/gate/src/index.ts) verifies authorization and exact observed action, reserves replay state, then invokes the effect and records its result. The [runtime monitor](../../packages/gate/src/runtime-monitor.ts) locks down on lifecycle divergence. The [scanner](../../packages/scan/src/index.ts) identifies visible actions and fails unclassified mutating actions closed for review. The [Helm values](../../packages/gate/deploy/helm/emilia-gate-service/values.yaml) run the Gate service non-root with seccomp, a read-only root filesystem, no privilege escalation, and all Linux capabilities dropped; the [NetworkPolicy](../../packages/gate/deploy/helm/emilia-gate-service/templates/networkpolicy.yaml) constrains that service's network paths. | The July 15 control expressly reaches agent-executed code and first-party MCP servers. The shipped container controls confine the Gate service, not arbitrary code spawned by an agent or every MCP server. The repository does not establish a general agent-code sandbox, credential isolation for spawned code, post-approval tool-definition integrity monitor, or prompt-injection scanner for hooks/skills/rules. Those remain deployment controls. |

## E015 — Log AI system activity

AIUC-1 describes E015 as a detective requirement to retain permitted AI-system
process, action, and output records for investigation, audit, and explanation.

| Subcontrol | Status | EMILIA implementation and evidence | Verification boundary |
| --- | --- | --- | --- |
| **E015.1 — Logging implementation** | **Partial** | The [Gate check and execution paths](../../packages/gate/src/index.ts) emit structured decision and execution events with timestamps, action and selector, authorization outcome and reason, subject/receipt correlation, policy and approver evaluation, exact observed-action hash, and execution outcome. The [Gate service runtime](../../apps/gate-service/src/runtime.ts) uses a strict durable evidence adapter and exposes scoped history, record, verification, export, and metrics operations. The [SIEM mapping](../../packages/gate/src/siem.ts) documents the exact OCSF/CEF field projection. | These are action-authorization and execution-boundary logs, not a complete record of model inputs, prompts, intermediate processing, model outputs, or every user interaction. The deployer must define what is permitted and necessary to log, prove all in-scope AI components emit it, and reconcile privacy/data-minimization constraints. |
| **E015.2 — AI agent logging implementation** | **Partial** | For gated MCP calls, the [MCP wrapper](../../packages/gate/src/mcp.ts) supplies protocol/tool selector and observed action to Gate. The [evidence records](../../packages/gate/src/index.ts) correlate the tool decision, receipt/subject, policy, approvers, action hash, execution outcome, and the decision hash authorized by that execution. The [reliance packet](../../packages/gate/src/reliance-packet.ts) joins decision, execution, evidence head, policy, tenant, and approver data into a re-performable summary. [MCP tests](../../packages/gate/mcp.test.ts) demonstrate the guarded call chain and attached execution proof. | EMILIA records the Gate segment of an agent workflow. It does not universally capture agent/deployment provenance, full tool parameters and returned data, sub-agent handoffs and outcomes, or reasoning traces. A deployer must correlate Gate records with its agent framework and downstream service logs using stable execution identifiers and document any data intentionally omitted. |
| **E015.3 — Log storage** | **Partial** | The [Postgres evidence backend](../../packages/gate/src/evidence-postgres.ts) provides tenant/gate-scoped durable storage, atomic append, health checks, and history verification. The [deployment SQL](../../packages/gate/deploy/sql/001-runtime.sql) applies row-level security, exact runtime scope grants, restricted runtime privileges, and immutable evidence records. The [Gate service](../../apps/gate-service/src/runtime.ts) authorizes evidence access, returns a redacted projection, and bounds pagination. The [retention classifier](../../packages/gate/src/retention.ts) defines hot, cold, expired, and legal-hold buckets, while [retention guidance](../gov-readiness/AUDIT_LOG_RETENTION.md) recommends 365-day hot and 2,190-day cold periods. | Retention code classifies records but does not move, delete, or archive them; the repository does not prove a production retention job, backup/restore, encryption-at-rest configuration, legal-hold operation, PII-masking policy for every upstream log, or SIEM access review. The database owner remains a privileged trust boundary. Deployment records must prove the selected periods and controls are active. |
| **E015.4 — Log integrity protection** | **Implemented** | The [evidence log](../../packages/gate/src/evidence.ts) canonicalizes each record, commits to `prev_hash`, verifies sequence and content, and offers an atomic shared-head mode for production. The [Postgres backend](../../packages/gate/src/evidence-postgres.ts) detects sequence gaps, forks, predecessor mismatch, duplicate identifiers, content tampering, and head rollback. The [deployment SQL](../../packages/gate/deploy/sql/001-runtime.sql) denies direct runtime writes, uses an atomic append function, enables row-level security, and rejects update/delete/truncate on evidence records. [Atomic-log tests](../../packages/gate/evidence-atomic.test.ts) and [Postgres evidence tests](../../packages/gate/evidence-postgres.test.ts) cover concurrent append, restart continuity, altered bytes, forks, rollback, scope isolation, and storage-failure behavior. | This establishes tamper evidence and runtime-role append-only behavior for the scoped Gate evidence stream. It is not proof of hardware WORM storage or immunity from a database owner/control-plane compromise. Verification depends on obtaining the complete scoped history and head; independent checkpoint publication, external archival, witness operation, and cross-system log completeness must be verified separately where required. |

## Cross-cutting verification boundaries

1. **Complete mediation is a deployment fact.** Repository code cannot prove
   that every production tool, credential, backend, MCP server, or alternate
   route is forced through Gate. A bypass inventory and live architecture test
   are required.
2. **Source and tests are design evidence, not operating-effectiveness
   evidence.** An assessment still needs deployed configuration, sampled logs,
   alert and review records, retention settings, identities, and change history
   for the period under review.
3. **Action evidence is narrower than model observability.** EMILIA's strongest
   evidence concerns authorization, exact-action binding, replay control, and
   the execution boundary. It does not claim to capture all prompts, reasoning,
   outputs, or agent-to-agent context.
4. **Hashes preserve confidentiality but affect log review.** The default
   action hash proves binding when the clear action is supplied for
   re-performance; it does not let an investigator reconstruct undisclosed
   parameters from the log alone.
5. **External trust roots remain external.** Identity proofing, approver role
   assignment, policy adequacy, key custody, network enforcement, storage
   administration, and human review operation belong to the deploying
   organization and must be evidenced there.

## Claim boundary

This crosswalk does **not** claim AIUC-1 certification, conformance, endorsement,
adoption, or approval of EMILIA evidence. It does not claim that AIUC-1 requires
EMILIA or that EMILIA alone satisfies any AIUC-1 requirement. AIUC-1 scope,
control applicability, evidence sufficiency, testing, and any certification
decision belong to the organization and its authorized assessor.
