<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Gate Enforcement Profile

**Status:** operational architecture profile  
**Applies to:** EMILIA Gate deployments protecting consequential machine actions  
**Primary rule:** no valid evidence, no protected mutation  
**Product boundary:** Protocol proves. Gate prevents.

## 1. Purpose

This profile defines how to place and operate EMILIA Gate so that a protected
executor refuses an action unless the relying party's evidence and policy
requirements have been met. It covers four deployment topologies:

1. an MCP or other protocol-specific proxy;
2. a service-mesh enforcement point;
3. a network-egress enforcement point; and
4. a domain or system-of-record enforcement point.

The profile also defines the shared consequence lifecycle:

`challenge -> verify -> match -> satisfy -> authorize -> reserve -> invoke ->
commit executed | freeze indeterminate -> reconcile`

The topology selects which paths reach Gate. It does not change the meaning of
the evidence or the lifecycle states.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** in this document express requirements of this repository profile.
They do not imply IETF adoption or standardization.

## 2. Claim Boundary

An integration conforms to this profile only for a declared set of protected
actions and execution paths.

Gate can establish that:

- the configured verifier evaluated the presented evidence under
  relying-party-pinned trust;
- independently verified artifacts were bound to the same material action;
- the evidence bundle filled the relying party's declared requirement;
- the local executor authorized the protected action;
- one-time or bounded state was durably reserved before invocation;
- an execution result or indeterminate outcome was recorded without reopening
  the action for blind retry.

Gate does not establish that:

- an action was wise, legal, safe, or commercially appropriate;
- a signature proves civil identity, comprehension, or freedom from coercion;
- a pre-execution permit proves that the external effect succeeded;
- an MCP proxy, middleware library, sidecar, or egress gateway covers a path
  that can reach the protected system without traversing it;
- a passive observer proves inventory completeness or non-bypassability;
- a provider timeout proves success or failure.

The non-bypassability claim is valid only when every path capable of the
declared mutation reaches an enforcement point at the actual system of record
or actuator, or the system of record independently rejects the path.

## 3. Decision Vocabulary

The following states are deliberately separate. A deployment MUST NOT collapse
them into a single `valid`, `allow`, or `success` flag.

| State | Meaning | Does not mean |
| --- | --- | --- |
| **VERIFIED** | One native artifact passed its own structural and cryptographic verifier under relying-party-pinned trust anchors and freshness rules. | The artifact fills an authorization role, refers to the executor's action, or permits execution. |
| **MATCH** | Independently verified artifacts denote the same material action by direct action-identifier equality or an exact, relying-party-pinned mapping profile. | Either artifact is authoritative, sufficient, or permitted. |
| **SATISFIED** | The verified and matched bundle fills every slot in one relying party's evidence requirement. | A universal policy decision or permission to execute. |
| **AUTHORIZED** | The local executor's policy permits this exact action, at this time, for this audience, using this satisfied evidence bundle. | The effect has started or succeeded. |
| **EXECUTED** | The consequence-owning executor has authoritative evidence that the exact protected effect was applied. | That the effect was wise or that no later reversal occurred. |
| **INDETERMINATE** | Invocation began, but the executor cannot prove whether the effect was applied. The operation remains closed to blind retry. | Failure, success, or permission to try again. |

`VERIFIED`, `MATCH`, and `SATISFIED` are evidence conclusions. `AUTHORIZED` is
an executor policy conclusion. `EXECUTED` and `INDETERMINATE` are consequence
lifecycle conclusions.

## 4. Architecture at a Glance

![Four Gate deployment topologies and the shared consequence lifecycle. The diagram shows MCP proxy, service mesh, egress gateway, and system-of-record placements, followed by challenge, evidence decisions, authorization, reservation, invocation, execution or indeterminate state, and reconciliation.](../diagrams/gate-enforcement-topologies.svg)

The four topologies are composable. A high-assurance deployment commonly uses
a broad upstream placement for early refusal and a domain/system-of-record
placement for final enforcement.

| Topology | Covered paths | Paths not covered by placement alone | Required closure control |
| --- | --- | --- | --- |
| MCP or protocol proxy | Calls to the named MCP servers or protocol endpoints behind Gate | Direct SDK calls, shell commands, alternate APIs, direct database access, in-process effects | Remove direct endpoint credentials and routes, or add mesh, egress, or system-of-record enforcement. |
| Service mesh | Calls that cross an enforced mesh boundary | In-process calls, local files or sockets, direct databases outside the mesh, workloads that escape sidecar routing | Mesh authorization, workload identity, sidecar immutability, and network policy that rejects non-mesh paths. |
| Egress gateway | Outbound network calls forced through the gateway | Local mutations, in-process effects, direct storage paths, opaque traffic whose material action cannot be derived | Deny direct egress and add a protocol/domain verifier wherever exact action fields cannot be reconstructed at egress. |
| Domain/system of record | Mutations accepted by the protected payment, data, code, infrastructure, or actuator boundary | Administrator or break-glass paths not governed by the same boundary | Make Gate evidence a write precondition, remove direct mutation credentials, and separately govern every break-glass path. |

## 5. Trust Boundaries

### TB-1: Requester domain

The agent, orchestrator, prompt, tool arguments, retrieved content, and
presenter-supplied metadata are untrusted. They MAY propose an action and
present evidence. They MUST NOT select verifier code, trust anchors, policy
roots, mapping profiles, evidence requirements, or consumption keys.

### TB-2: Native evidence issuers

Identity, delegation, policy, human-authorization, status, and transparency
artifacts retain their native semantics and trust roots. Gate MUST invoke the
registered native verifier for each artifact and preserve its result and reason.
An embedded key, issuer label, or self-declared assurance level carries no trust
unless the relying party pinned the applicable profile and root.

### TB-3: Gate enforcement domain

Gate runs outside the governed agent's decision context. It owns:

- verifier and trust-root configuration;
- action-risk and evidence-requirement policy;
- action mapping and execution-field binding;
- the local authorization decision;
- one-time and bounded-state transitions;
- the execution adapter and evidence record.

Production signing and trust secrets MUST use deployment-controlled key custody.
The requester MUST NOT be able to replace Gate code or mutate its configuration
for the request being evaluated.

### TB-4: Durable state domain

Replay, capability budget, reservation, evidence-head, and reconciliation state
MUST be shared across replicas and survive process restart. Reservation and
commit operations MUST be atomic and ownership-fenced. A production deployment
MUST NOT silently fall back to process-local state.

### TB-5: Executor or system-of-record domain

The executor derives material action fields from its own request parsing,
database state, provider configuration, or actuator command. It MUST NOT accept
the requester's description as proof of what will be mutated.

The system of record is the final authority on whether an effect was accepted.
For complete mediation, it MUST require a valid downstream Gate decision or
perform the full Gate evaluation itself before mutation.

### TB-6: Provider observation and reconciliation domain

Provider and system-of-record observations used to resolve an indeterminate
effect MUST be authenticated, audience-bound, and matched to the original
operation identifier, action digest, amount or resource, destination, and
provider environment. A webhook notification or unauthenticated status string
is not authoritative reconciliation evidence.

## 6. Required Processing Model

### 6.1 Declare and challenge

The deployment MUST maintain a deny-by-default manifest for protected actions.
An unrecognized action on a protected path is a configuration error and MUST be
refused.

When required evidence is absent, Gate returns a machine-readable challenge
that identifies the action and required evidence or assurance profile. The
challenge MUST NOT permit the requester to choose trust anchors or weaken the
policy. No reservation or external effect occurs at this stage.

### 6.2 Construct the observed action

Before evidence evaluation, the executor constructs an immutable observed
action from effect-relevant facts it controls. Depending on the adapter, these
facts include:

- protocol, method, tool, operation, and target;
- tenant, account, record, repository, branch, or environment;
- amount, currency, destination, and provider instruction;
- input, document, policy, or artifact digests;
- an action-instance nonce or unique operation identifier.

Every material field that can alter the protected consequence MUST participate
in action binding. If Gate cannot determine which fields are material, the
action MUST be refused or routed to a profile that can.

### 6.3 Verify native artifacts

Gate verifies each artifact independently under its native rules and
relying-party-pinned configuration.

A successful native result is **VERIFIED** only for that artifact. Machine
identity, delegated scope, machine policy, human approval, revocation status,
transparency, and execution evidence remain distinct roles.

Malformed, unsupported, stale, revoked, ambiguous, or unverifiable required
evidence MUST fail closed with a bounded reason. A verifier exception MUST be
converted to refusal; it MUST NOT crash into an allow path.

### 6.4 Match the material action

Gate compares the verified artifacts with the executor-owned observed action.
Direct canonical-action equality MAY establish **MATCH**. Cross-format
comparison MUST use the exact mapping profile and type-definition sources
pinned by the relying party.

Lossy, missing, or ambiguous mappings return no match. They MUST NOT be guessed
into equivalence.

### 6.5 Evaluate evidence satisfaction

Gate evaluates the verified and matched bundle against a
constructor-configured evidence requirement. Every required role must be
filled by an artifact accepted for that role.

Examples include:

- delegated machine scope;
- a current machine-policy permit;
- one named-human authorization;
- a distinct-human quorum;
- current revocation or status evidence;
- an authority or license proof;
- a required transparency or provenance record.

Filling every slot yields **SATISFIED**. A machine-policy ALLOW cannot silently
fill a required human-approval slot, and a human approval cannot silently fill
a machine-policy slot.

### 6.6 Make the local authorization decision

Only the consequence-owning executor makes **AUTHORIZED**. It evaluates:

- evidence satisfaction;
- exact action and audience binding;
- issuer, authority, tenant, and organization pins;
- assurance floor and separation of duties;
- policy epoch, validity, revocation, and freshness;
- execution fields observed from the system of record;
- requested capability amount, currency, expiry, and remaining budget;
- local risk and break-glass policy.

The authorization decision MUST be recorded before invocation. Evidence
satisfaction alone MUST NOT enter the effect.

### 6.7 Reserve one-time and bounded state

Before invoking the external effect, Gate atomically reserves:

- the one-time authorization or action key;
- the unique operation identifier;
- any capability budget required by the action; and
- the predecessor evidence-log head where a shared atomic log is required.

The reservation key MUST be derived from verified or executor-owned action
material, never from a presenter-selected decoy. The capability amount and
currency MUST equal the observed action.

If the state store is unavailable, stale, non-atomic, or reports an ambiguous
reservation result, Gate MUST refuse before invocation. An abandoned
high-risk reservation does not expire back into availability automatically.

### 6.8 Invoke the protected effect

Gate passes the adapter:

- a frozen snapshot of the authorized observed action;
- a stable, action-bound idempotency key;
- the authorization decision reference; and
- only the minimum evidence required by the downstream interface.

The adapter MUST NOT recompute a different action from mutable caller data
after authorization. The invocation transition is durably observable before
the deployment can report execution success.

### 6.9 Commit executed or freeze indeterminate

If the configured executor returns authoritative, action-matched success, Gate
commits the operation and capability spend and records **EXECUTED**.

If an exception, timeout, response loss, process crash, or evidence-write
failure occurs after invocation begins, Gate MUST:

1. commit the spend as `indeterminate` when possible, or preserve the
   ownership-fenced reservation;
2. record **INDETERMINATE** without including provider secrets in the portable
   evidence;
3. refuse reuse of the authorization and operation identifier; and
4. prohibit automatic retry.

An error after invocation is not evidence that the provider did nothing.

### 6.10 Reconcile

An indeterminate operation remains closed until an authenticated provider or
system-of-record query resolves the exact original operation.

Reconciliation MUST use the original action digest and idempotency key. It MUST
verify provider identity, environment, audience, transaction or record
identifier, amount or resource, destination, and authoritative status.

The reconciler MAY transition:

- to **EXECUTED** when authoritative evidence proves the exact effect occurred;
- to a terminal `not_executed` state only when authoritative evidence proves
  the effect did not occur and the local policy defines whether a new,
  separately authorized operation may be created; or
- remain **INDETERMINATE** when evidence is absent, stale, conflicting, or
  unauthenticated.

Reconciliation does not resurrect the original authorization. Any subsequent
effect requires the lifecycle and policy defined for a new action instance.

## 7. External Composition Inputs

AgentROA and ORPRG are external, work-in-progress protocol sources. EMILIA does
not rename or claim ownership of their semantics.

| Native artifact | Native question it can answer | EMILIA composition role | It does not establish by itself |
| --- | --- | --- | --- |
| AgentROA ROA envelope and ARA chain | Was this agent session and delegation chain within a signed, monotonically narrowed capability scope? | Delegated machine-scope evidence, verified under AgentROA's native rules and relying-party pins. | Named-human approval, EMILIA evidence satisfaction, local authorization, or successful execution. |
| AgentROA AER | Did an AgentROA Border Gateway record a pre-execution permit or denial for the bound invocation and policy? | Machine-policy or enforcement-decision evidence. Its `enforcement_mode` and deployment topology remain visible to local policy. | That the target effect executed; AgentROA defines the AER commitment before execution. |
| ORPRG PermitReceipt | Did the selected ORPRG profile authorize the canonical effect request under the named policy epoch, scope, status, and anti-replay rules? | Machine-policy permit evidence, verified under ORPRG's native rules and relying-party pins. | Named-human approval, universal authorization, complete mediation, or successful execution. |
| ORPRG DecisionReceipt or capability token | Did a local ORPRG verifier derive action- and audience-bound downstream evidence? | A dual-enforcement input at the downstream boundary. | Permission for a different audience, action, epoch, or operation; execution success. |

An adapter for either protocol MUST:

1. use the exact supported native revision and schema;
2. fail closed on unknown fields or proof types where the native profile
   requires refusal;
3. take trust roots, policy, status, and verifier configuration from the
   relying party, never the transaction;
4. return a bounded native result and reason;
5. expose the native action commitment and freshness observations for matching;
6. preserve `degraded`, constrained-mode, denial, and topology metadata;
7. avoid converting a machine permit into human authorization or execution
   evidence.

The current official sources used for this profile are:

- [AgentROA -01](https://www.ietf.org/archive/id/draft-nivalto-agentroa-route-authorization-01.txt)
- [ORPRG Permit Receipts -00](https://www.ietf.org/archive/id/draft-lee-orprg-permit-receipts-00.txt)

They are individual Internet-Drafts and therefore works in progress. This
profile makes no adoption, endorsement, or ownership claim about them.

## 8. Deployment Topologies

### 8.1 Topology A: MCP or protocol-specific proxy

**Placement.** Gate is a reverse proxy in front of one or more MCP servers or
named protocol endpoints.

**Flow.**

```text
agent -> Gate protocol adapter -> protected MCP/API endpoint
```

The adapter parses the tool or method and derives the material action. Missing
evidence produces a challenge before forwarding. An allowed request enters the
shared reserve/invoke/finalize lifecycle.

**Complete-mediation conditions.**

- The protected endpoint is not reachable directly from the agent network.
- Agent credentials authorize only the Gate endpoint.
- DNS, service discovery, firewall, and workload policy reject alternate
  endpoints.
- Every protected tool and alias maps to a closed action profile.
- Direct SDK, shell, database, and non-MCP paths are either impossible or
  separately gated.

Without those controls, this topology is an adoption and early-refusal layer,
not proof of complete mediation.

### 8.2 Topology B: service mesh

**Placement.** Gate logic runs in a mesh sidecar, ingress, or policy-enforcement
component for calls crossing a workload boundary.

**Flow.**

```text
agent workload -> mesh Gate -> target workload
```

The mesh establishes workload identity and forces covered calls through the
enforcement component. Application protocols still need an adapter capable of
deriving the exact material action; an L4 allow/deny decision alone does not
establish action binding.

**Complete-mediation conditions.**

- Mesh bypass and direct pod-to-pod routes are denied.
- Sidecar or node enforcement cannot be disabled by the governed workload.
- Workload identity and tenant context are authenticated.
- The exact protected mutation necessarily crosses the mesh boundary.
- In-process, local-socket, file, database, and node-privileged paths are
  inventoried and separately closed.

### 8.3 Topology C: egress gateway

**Placement.** All outbound network traffic from the governed execution domain
is routed through Gate-controlled egress.

**Flow.**

```text
agent domain -> Gate egress -> external provider
```

This topology gives broad transport coverage. It provides exact-action
enforcement only where the gateway can authenticate the destination and derive
the complete effect-relevant request. Opaque or unsupported traffic MUST be
denied or forwarded only to a downstream domain Gate that performs the
application-level checks.

**Complete-mediation conditions.**

- Default network policy denies direct egress, alternate interfaces, tunnels,
  and ungoverned proxies.
- DNS and destination identity are controlled.
- TLS termination or a downstream token preserves action and audience binding.
- Local mutations and non-network effects are outside the claim unless
  separately gated.
- Redundant gateways share durable replay, reservation, policy, and evidence
  state.

### 8.4 Topology D: domain or system-of-record boundary

**Placement.** Gate is installed in the write path of the protected payment
rail, database service, code host, cloud control, clinical workflow, or
actuator.

**Flow.**

```text
any caller -> domain Gate -> protected mutation
```

This is the preferred consequence-owning placement. The target reconstructs
the material action from its own request and state, verifies the required
evidence or a tightly bound upstream decision, reserves one-time state, applies
the mutation, and records the outcome.

**Complete-mediation conditions.**

- No caller, worker, migration, scheduled job, plugin, or alternate API can
  perform the declared mutation without the same enforcement invariant.
- Direct database, provider, signing, and actuator credentials are unavailable
  to the governed agent and ordinary application path.
- Stored procedures, row policies, IAM, or target-side verification reject
  missing or invalid Gate evidence.
- Administrative and break-glass paths are separately authorized, logged,
  tested, and excluded from the ordinary coverage claim when they bypass Gate.
- The system-of-record mutation and Gate finalization use an atomic transaction
  where possible, or an idempotent provider operation plus conservative
  indeterminate handling where not.

## 9. Dual Enforcement

High-risk effects SHOULD combine an upstream Gate with a downstream
system-of-record Gate.

The upstream Gate:

1. refuses obviously invalid requests early;
2. verifies native evidence and action binding;
3. emits a signed, short-lived, audience-bound decision artifact or forwards
   the complete evidence bundle;
4. never describes that pre-execution result as `EXECUTED`.

The downstream Gate:

1. reconstructs the material action from system-of-record facts;
2. verifies the upstream artifact or re-performs native verification;
3. checks action, audience, tenant, policy epoch, freshness, and operation ID;
4. owns the final durable reservation and replay domain;
5. invokes and finalizes the protected mutation.

The final reserve MUST occur in the consequence-owning domain. Two independent
gateways MUST NOT create separate replay domains and then claim fleet-wide
at-most-once execution.

If the upstream Gate is unavailable, the downstream boundary still rejects
missing evidence. If the downstream Gate is unavailable, the protected system
does not mutate. An upstream `ALLOW` string, HTTP header, or unsigned log entry
is not sufficient downstream evidence.

## 10. Bypass Resistance and Coverage Evidence

A deployment claiming complete mediation MUST maintain a versioned inventory
of:

- protected action types and material fields;
- all principals and credentials capable of the mutation;
- protocol endpoints, alternate APIs, queues, schedulers, workers, plugins,
  migrations, and administrative paths;
- Gate placements and their exact coverage;
- break-glass controls;
- active negative probes and expected refusal reasons.

Coverage is established by controls at the protected boundary, not by the
absence of observed bypass traffic.

A deployment attestation plus a separately pinned active probe can establish
that a declared surface behaved as `gated` at the evaluation time. A passive
network witness can corroborate observed traffic but remains `witness_only`; it
cannot prove that the path inventory was complete.

Any newly discovered mutation path is unclassified coverage debt. Until it is
closed or explicitly removed from the claim, the deployment MUST narrow its
complete-mediation statement.

## 11. Failure and Degraded-Mode Behavior

Protected actions fail closed by default.

| Failure | Before invocation | After invocation begins |
| --- | --- | --- |
| Verifier, trust registry, status, or policy source unavailable | Refuse. Cached evidence is accepted only under an explicit profile whose freshness window is still satisfied. | Preserve the existing operation state; do not infer effect outcome. |
| Required evidence missing, malformed, stale, conflicting, revoked, or unsupported | Refuse with a bounded challenge or denial reason. | Not applicable because invocation must not have started. |
| Durable consumption, capability, or evidence store unavailable | Refuse; do not invoke. Ambiguous reservation remains closed. | Preserve or commit the reservation as indeterminate; do not reopen. |
| Gate instance or upstream network unavailable | The target rejects the missing downstream evidence. | Reconcile using the stable operation identifier; do not repeat the effect. |
| Provider timeout, reset, or malformed response | Not applicable. | Record indeterminate, consume or freeze authorization and budget, and reconcile. |
| Reconciliation source unavailable or unauthenticated | No new effect. | Remain indeterminate. |
| Runtime lifecycle monitor detects divergence | Enter fail-closed safe mode; disable pass-through and require the configured elevated assurance floor. | Preserve closed state and require operator-authorized recovery; recovery does not re-authorize an earlier receipt. |

An external artifact marked `degraded`, including an AgentROA AER produced from
cached registry material or an ORPRG constrained-mode result, remains
**VERIFIED** only under its native profile. Local Gate policy SHOULD reject
degraded evidence for high-risk protected effects. If a deployment permits it
for a lower-risk action, the allowance MUST be explicit, short-lived,
auditable, audience-scoped, anti-replay protected, and visible in the decision
record.

No degraded mode may silently become fail-open.

## 12. Evidence and Audit Requirements

For every decision, Gate SHOULD record:

- protected action type and canonical action digest;
- verifier names, supported revisions, native outcomes, and reasons;
- pinned trust and policy identifiers, never secret key material;
- `VERIFIED`, `MATCH`, `SATISFIED`, and `AUTHORIZED` conclusions separately;
- reservation and operation identifiers;
- capability amount, currency, and outcome where applicable;
- invocation transition and executor identity;
- `EXECUTED`, `INDETERMINATE`, or terminal reconciliation result;
- predecessor and current evidence-log heads;
- topology and declared coverage surface.

Logs containing these records are sensitive. Retention, disclosure, and
transparency policy MUST minimize targets, identities, denial reasons, and
commercial details while preserving the evidence needed for authorized
re-performance.

## 13. Reference Implementation Mapping

The current repository maps this profile to:

| Profile requirement | Reference implementation |
| --- | --- |
| Challenge, receipt verification, assurance, observed-action binding, one-time reservation, invocation, and execution evidence | `packages/gate/index.js` |
| Atomic bounded-spend reserve and commit, replay refusal, Postgres adapter, and indeterminate spend | `packages/gate/capability-receipt.js` |
| Constructor-pinned heterogeneous evidence requirement and action-keyed execution custody | `packages/gate/aec-execution.js` |
| Lifecycle divergence detection and fail-closed safe mode | `packages/gate/runtime-monitor.js` |
| Shared-head durable evidence | `packages/gate/evidence.js` and `packages/gate/evidence-postgres.js` |
| Authenticated external-provider reconciliation for Action Escrow | `packages/gate/action-escrow-custodian.js` and `packages/gate/action-escrow-state.js` |
| Deployment isolation, network policy, database posture, backup, restore, and rollback | `docs/EMILIA-GATE-DEPLOYMENT.md` |
| Narrow executable Consequence Firewall claim | `docs/CONSEQUENCE-FIREWALL-CONFORMANCE.md` |

This mapping identifies the code that implements the profile. It does not claim
that every possible deployment has complete mediation. Each deployment must
prove its own declared coverage and failure behavior.

## 14. Deployment Acceptance Checklist

A production owner SHOULD NOT mark a protected surface ready until all answers
below are yes.

- [ ] Is the protected consequence and every material action field declared?
- [ ] Is the observed action derived from executor-owned facts?
- [ ] Are native verifiers, trust roots, mapping profiles, and evidence
      requirements pinned outside transaction input?
- [ ] Are `VERIFIED`, `MATCH`, `SATISFIED`, `AUTHORIZED`, and `EXECUTED`
      represented separately?
- [ ] Do missing, malformed, stale, revoked, ambiguous, and unsupported inputs
      refuse without throwing into an allow path?
- [ ] Is reservation durable, atomic, ownership-fenced, shared across replicas,
      and non-expiring while outcome is uncertain?
- [ ] Does capability spending bind exact amount and currency to the observed
      action and refuse overspend before invocation?
- [ ] Is the provider operation idempotent under the stable operation ID?
- [ ] Does every post-invocation exception become indeterminate and block blind
      retry?
- [ ] Does reconciliation authenticate and match the authoritative provider or
      system-of-record observation?
- [ ] Can every mutation path, credential, worker, alternate API, and
      break-glass path be accounted for?
- [ ] Does the system of record independently reject a missing or invalid
      downstream decision?
- [ ] Do active negative probes demonstrate bypass refusal?
- [ ] Do failover, restart, stale-cache, store-loss, timeout, and reconciliation
      drills preserve the closed state?
- [ ] Is the coverage claim no broader than the paths actually tested?

## 15. Source Notes

The topology categories, external trust-boundary observations, dual-enforcement
concept, and degraded metadata in this profile were informed by the official
AgentROA -01 and ORPRG -00 texts linked in Section 7. EMILIA's decision
vocabulary, durable consequence lifecycle, and claim boundaries follow the
current repository implementation and canonical context.

No private draft text is reproduced here. Nothing in this document states or
implies that an EMILIA document, AgentROA, or ORPRG has been adopted or endorsed
by the IETF.
