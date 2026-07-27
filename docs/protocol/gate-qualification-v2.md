<!-- SPDX-License-Identifier: Apache-2.0 -->
# Gate Qualification v2 Profile

**Status:** implemented public reference profile with exported verifier, Gate,
Admission Store, PostgreSQL adapter, CLI, vectors, tests, and bounded formal
results; not an Internet-Draft, standard, managed deployment, certification,
or independent-interoperability claim

## 1. Scope

Gate Qualification v2 defines how a relying party can:

1. identify an evaluated candidate exactly;
2. verify a closed evaluation campaign and its terminal evidence;
3. determine whether the candidate remains current for one protected request;
4. compose that result with AEB, AEC, and local policy without confusing
   evidence satisfaction with authorization;
5. admit one immutable action into a shared one-time execution domain; and
6. preserve provider and effect truth through invocation, crash, reconciliation,
   supersession, and remedy.

This profile extends, and does not modify, the objects or verification algorithm
frozen by [PIP-001](../../PIPs/PIP-001-core-freeze.md). A qualification is
evidence considered by a local Gate. It is not a Trust Receipt replacement, an
authorization, a capability, or proof that a resulting action is wise, legal,
safe, or successful.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** state requirements of this public implementation profile. They do
not imply IETF adoption.

## 2. Trust and authority separation

A conforming implementation MUST keep these propositions distinct:

- **VERIFIED:** an artifact passed its structural and cryptographic verifier.
- **ACCEPTED:** the artifact's verified signer set satisfies the relying
  party's pinned trust policy.
- **QUALIFIED:** the accepted campaign graph, candidate measurement, assignment,
  qualification policy, and current status satisfy this profile.
- **SATISFIED:** AEB/AEC evidence fills a named relying-party requirement.
- **AUTHORIZED:** local policy permits this exact action.
- **ADMITTED:** the action and all required resources were atomically reserved.
- **INVOKING:** one-time execution authority was consumed before provider entry.
- **COMMITTED**, **PROVEN_NOT_COMMITTED**, or **INDETERMINATE:** authenticated
  provider outcomes, kept separate from the observed effect relation.
- **OBSERVED_AS_REQUESTED**, **DIVERGED**, or **INDETERMINATE:** independently
  evidenced relations between the admitted request and the observed effect.

`QUALIFIED` MUST NOT substitute for AEB, AEC, local authorization, capability
reservation, or provider/effect evidence. Upstream evaluation adapters MUST
classify their output as evaluation evidence only and MUST NOT assert execution
authority.

## 3. Closed artifact and evidence profiles

All `sha256:` references in this section identify the canonical decoded payload,
not a mutable signature envelope. Unknown fields, malformed Unicode, accessors,
non-canonical encodings, duplicate signature key IDs, untrusted keys, invalid
signatures, and resource-limit violations MUST fail closed.

### 3.1 Candidate Manifest

`EP-CANDIDATE-MANIFEST-v1` identifies one candidate and a closed `static`
measurement containing:

- code, dependency, prompt-template, and tool-definition digests;
- the effective-permissions digest;
- model provider, identity, version, optional artifact digest, and pinning
  strength;
- retrieval-configuration digest; and
- builder/orchestrator digest.

Model pinning strength is ordered:
`UNPINNABLE < MUTABLE_ALIAS < VERSION_PINNED < IMMUTABLE_DIGEST`.
`IMMUTABLE_DIGEST` requires a model artifact digest. A relying party MUST set
and enforce its minimum acceptable strength.

### 3.2 Evaluation Campaign

An Evaluation Campaign is a canonical DSSE-wrapped in-toto Statement with
predicate type
`https://emiliaprotocol.ai/attestation/evaluation-campaign/v1`.
It MUST bind:

- campaign ID and Candidate Manifest payload digest;
- assignment and qualification-policy digests;
- harness, evaluator-configuration, and environment digests;
- hidden challenges as a sorted salted-digest set or a Merkle root and count;
- scenario-selection commitment;
- planned and maximum batches;
- per-challenge attempt ceiling;
- `not_before` and `not_after`; and
- the predecessor campaign payload digest, or `null` for the first campaign.

Campaigns MUST form one ordered predecessor chain. Reordering, omission,
forking, an unbound predecessor, or a changed candidate, assignment, or policy
MUST make the graph non-qualifying.

### 3.3 Test Result

A native test result is a canonical DSSE-wrapped in-toto Test Result Statement.
It MUST name the Candidate Manifest as its only subject and MUST bind exactly
the campaign's environment, evaluator configuration, and harness. `PASSED`
supports only `PASS`; `FAILED` supports only `FAIL`. `ABORTED` and `EXPIRED`
terminal references MUST have no native test-result digest.

### 3.4 Agent Evaluation Evidence

Agent Evaluation Evidence uses predicate type
`https://emiliaprotocol.ai/attestation/agent-evaluation-evidence/v1`.
For one campaign it MUST bind the candidate, assignment, policy, campaign
payload, batch closure, issued-challenge count, canonical terminal references,
outcome counts, terminal-outcomes root, measurements, and evaluation window.

Each `(batch, challenge_index)` slot MUST appear. Attempts for a slot MUST be
contiguous from one and MUST NOT exceed the campaign ceiling. Each terminal
reference MUST prove its hidden-challenge commitment, reuse the campaign's
scenario-selection commitment, remain inside the campaign and evidence time
windows, and reference at most one native test result. Every supplied test
result MUST be referenced exactly once. A selective omission, insertion,
duplication, reordered terminal list, non-contiguous retry, unreferenced test
result, or aggregate mismatch MUST fail closed.

Terminal outcomes are `PASS`, `FAIL`, `ABORTED`, and `EXPIRED`. A source adapter
MAY retain a more detailed source status such as `ERROR`, but it MUST preserve
that status honestly and MUST NOT launder it into `PASS`.

### 3.5 Qualification Statement

The Qualification Statement is a canonical DSSE-wrapped, closed subset of the
in-toto Software Verification Summary v0.2 predicate. It MUST have exactly
three subjects:

1. Candidate Manifest;
2. head Evaluation Campaign; and
3. the digest of the complete qualification graph.

Its verifier MUST bind the assignment and qualification-policy resources and
its properties MUST include `EMILIA_GATE_QUALIFICATION_V2`. Its creation time
MUST be no earlier than campaign completion and no later than trusted
evaluation time.

### 3.6 Qualification Status

`EP-QUALIFICATION-STATUS-v1` is a canonical DSSE envelope under the dedicated
qualification-status payload type. Entries form a zero-based, predecessor-bound
sequence under one pinned authority and bind the Qualification Statement,
candidate, assignment, and policy.

Status values are `QUALIFIED`, `SUSPENDED`, `REVOKED`, and `EXPIRED`. The relying
party MUST compare the signed head to a fresh, authority-bound observation,
enforce its minimum sequence, `next_update`, `valid_until`, and maximum
observation age, and refuse equivocation. `CURRENT_AS_OBSERVED` means only that
the supplied head was current under that observation; it is not global
freshness proof.

### 3.7 Runtime Candidate Measurement and influence cutoff

`EP-RUNTIME-CANDIDATE-MEASUREMENT-v1` MUST bind:

- Candidate Manifest and assignment digests;
- `measured_at` and `candidate_influence_cutoff`;
- whether the candidate remains in the execution path;
- the exact static candidate;
- dynamic retrieval root;
- memory-state snapshot, user-input, and protected-request digests.

`candidate_influence_cutoff` is the last instant at which candidate-controlled
or candidate-selected material capable of changing the protected request may
enter the measured execution. It is not a model-response timestamp.

The verifier MUST require:

- `measured_at <= candidate_influence_cutoff <= trusted_now`;
- measurement age within the relying party's limit;
- canonical equality between measured and manifested static candidate;
- exact assignment and protected-request binding; and
- the configured minimum model-pinning strength.

If `remains_in_execution_path` is true, the decision MUST set
`remeasure_at_begin_invocation`. Gate MUST then re-read the candidate,
qualification status, AEB, AEC, local policy, and protected-request binding
immediately before consuming execution authority. Any later candidate influence
invalidates the measurement and MUST prevent provider entry.

## 4. Pure qualification decision

Qualification evaluation MUST be deterministic and side-effect free. It MUST
NOT reserve storage, call a provider, resolve an ambient `latest` alias, fetch
trust roots implicitly, or authorize an action.

The decision vocabulary is:

- `QUALIFIED`: every required schema, signature, trust, graph, status,
  candidate, assignment, and protected-request check succeeded.
- `NOT_QUALIFIED`: verified evidence or exact binding establishes a definitive
  negative result, including mismatch, out-of-scope assignment, insufficient
  pinning, revoked/suspended/expired status, or trust-policy non-acceptance.
- `INDETERMINATE`: the verifier cannot safely establish either qualification or
  a definitive accepted negative, including malformed input, invalid
  signature, stale observation, stale runtime measurement, missing campaign
  closure, or verifier failure.

Every decision MUST include one bounded reason, individual check results,
semantic result axes, and payload digests. Only `QUALIFIED` MAY satisfy the
qualification leg of Gate composition, and it still MUST NOT authorize by
itself.

## 5. Gate composition and immutable invocation binding

The pure Gate composition MUST require all of:

- qualification `QUALIFIED` or locally normalized `allow`;
- AEB `allow` under one named requirement;
- AEC `allow` under one named requirement; and
- local policy `allow` under one named policy.

Every leg MUST bind the same CAID and action digest and carry its own evidence
digest. The resulting decision MUST derive its effect key internally from
`tenant_id + operation_id`; a caller-supplied effect key MUST be ignored.

The protected invocation implemented by `GateQualificationV2` contains only the
immutable `AdmissionSnapshot` returned by `beginInvocation` and the
store-issued invocation capability. The snapshot freezes tenant, admission,
operation, candidate and runtime measurements, assignment and policy, signed
qualification payloads, qualification status, CAID, action and effect-request
digests, provider account and environment, adapter digest, idempotency key,
trust/configuration epochs, typed evidence inputs, resource reservations, and
expiry. It contains neither a provider credential nor a raw prompt. Provider
credentials and the mutation implementation remain inside the protected
adapter at the consequence boundary.

## 6. Canonical Admission Store

### 6.1 Immutable snapshot

The implemented `createAdmissionSnapshot()` creates one canonical,
content-addressed `EP-GATE-ADMISSION-SNAPSHOT-v2`. It validates and
deterministically sorts the closed typed input and resource sets, computes a
domain-separated digest, returns a deeply frozen copy, and binds the complete
operation tuple described in Section 5.

Its expiry MUST be the earliest expiry of its inputs, reserved resources, and
any relying-party ceiling. The snapshot MUST be immutable after admission.
Ordinary `reserve()` refuses a `supersedes_admission_id`; `supersede()` creates
that relation atomically and clears `remedy_for`; a remedy uses `remedy_for`
and a fresh operation.

### 6.2 Separate CAS record and append-only journal

The immutable snapshot is not the mutable lifecycle head. The operational head
is the separate `EP-GATE-ADMISSION-RECORD-v2`, selected by tenant plus
admission or by the permanent tenant-operation head. Every mutation is fenced
by the record revision and an opaque owner capability whose stored
representation is only a digest.

The journal is a third, separate object. Every accepted transition atomically
updates the CAS record and resource fences and appends exactly one
`EP-GATE-ADMISSION-JOURNAL-v2` entry. Journal sequence equals record revision;
entries carry predecessor and record digests. Snapshots and journal entries are
append-only, and the tenant-operation head is permanent even after release,
failure, or supersession.

### 6.3 Semantic state

Admission state, execution right, provider attempt, provider outcome, and effect
relation are separate axes:

| State | Execution right | Meaning |
| --- | --- | --- |
| `RESERVED` | `RESERVED` | Current inputs and resources are held; provider entry is forbidden. |
| `RELEASED` | `RELEASED` | Uninvoked authority was intentionally released. |
| `EXPIRED` | `RELEASED` | Earliest admission expiry passed before invocation. |
| `SUPERSEDED` | `RELEASED` | A new admission replaced the uninvoked head for the same canonical operation. |
| `INVOKING` | `CONSUMED` | `beginInvocation` consumed the one-time right; provider entry may be imminent or uncertain. |
| `INDETERMINATE` | `CONSUMED` | Provider/effect truth is unresolved; replay remains forbidden. |
| `COMMITTED` | `CONSUMED` | The authenticated provider outcome is committed; the effect relation is still read independently. |
| `PROVEN_NOT_COMMITTED` | `CONSUMED` | The authenticated provider outcome is not committed; the effect relation is still read independently. |

Resource state in the canonical record is separately `RESERVED`, `RELEASED`,
or `CONSUMED`. `CONSUMED` execution authority and resources MUST never return
to `RESERVED` or `RELEASED`, including after crash. The PostgreSQL reference
materializes only live `RESERVED` or permanent `CONSUMED` resource fences;
released unconsumed rows are deleted while the record and journal preserve the
release.

### 6.4 Guarantee classes

`local_atomic` means one transaction domain atomically enforces tenant and
operation uniqueness, all named resource reservations, admission revision,
owner fencing, transactional currentness, and journal append. Its guarantee is
fleet-wide only for replicas that share that domain. The public PostgreSQL
adapter exposes `guaranteeClass: "local_atomic"`, `durable: true`,
`singleTenant: true`, and `deploymentBound: true` as its reference contract.
Those flags and checked-in SQL are not evidence that an operated deployment
exists. The process-local memory store is atomic only for one JavaScript
process and test scheduling; it is explicitly non-durable and test-only.

`federated` means evidence or reservations originate in multiple independent
administrative or transaction domains. This profile does not claim distributed
atomic commit, global exactly-once execution, or globally fresh status across
those domains. A federated deployment MUST still designate one
consequence-owning domain whose final `beginInvocation` is `local_atomic`.
Remote receipts, statuses, or reservations are verified inputs to that
decision. A partial federated failure remains closed or becomes
`INDETERMINATE`; compensating work is a remedy, not rollback of history.
No federated coordinator or cross-domain recovery implementation is included.

## 7. `beginInvocation`

Immediately before invocation, the canonical Admission Store performs the
transactional currentness check against the frozen candidate/runtime,
qualification status, AEB, AEC, local-policy, authorization,
protected-request, trust, configuration, and external-lease bindings. The
observation MUST be within the configured maximum age. Gate separately calls
its authoritative `InvocationRemeasurerV2` immediately before this transaction
and recomposes every leg; a failed or changed reread releases only an
unconsumed reservation and prevents provider entry. The transaction then
atomically:

1. verify tenant, operation, revision, owner, snapshot, action, and resource
   bindings;
2. verify the admission has not expired;
3. change `RESERVED` to `INVOKING`;
4. change execution right to `CONSUMED`;
5. change every resource reservation to `CONSUMED`;
6. record invocation start; and
7. append the journal transition.

Only the exact deeply frozen snapshot returned by a successful transition may
reach the protected adapter. A PostgreSQL acknowledgement loss is accepted as
success only when authoritative readback proves the exact generated invocation
token digest committed; otherwise Gate refuses provider entry or returns
`reconciliation_required`. Once success may have occurred, no caller may retry
the provider effect from a fresh admission.

## 8. Provider truth, effect truth, and reconciliation

Provider outcome and effect relation are independently authenticated and
persisted:

- provider: `COMMITTED`, `PROVEN_NOT_COMMITTED`, or `INDETERMINATE`;
- effect relation: `OBSERVED_AS_REQUESTED`, `DIVERGED`, or `INDETERMINATE`.

Provider evidence MUST bind tenant, admission, operation, snapshot, CAID,
action, effect request, provider account/environment, adapter, idempotency key,
and observation time. Effect evidence additionally binds the accepted provider
evidence digest and an observed-effect digest when determinate. `COMMITTED`
does not by itself mean `OBSERVED_AS_REQUESTED`; the implemented store and
runtime intentionally preserve combinations such as `COMMITTED + DIVERGED`.
Consumers MUST NOT collapse either axis into the other.

An adapter exception, response loss, evidence-verifier failure, relation
failure, or unconfirmed terminal store write after `beginInvocation` MUST yield
`INDETERMINATE` or `reconciliation_required`. Reconciliation MUST use an
evidence-only adapter path and MUST NOT call the provider mutation method.
If exact authoritative evidence is unavailable, the admission MUST remain
indeterminate.

Crash recovery requires the existing owner capability, rotates the
invocation/reconciliation capability, replaces its stored digest, and moves a
stranded `INVOKING` record to `INDETERMINATE`. The old invocation capability is
then refused. Recovery does not rotate the owner capability and never restores
consumed execution or resource rights. The runtime requires an
`InvocationAuthorityCustodyV2` boundary and writes rotated authority before
provider entry or reconciliation. Test-only memory custody is non-durable;
production deployments MUST supply protected restart-safe custody, normally
backed by KMS/HSM-wrapped storage and a separately authorized recovery role.

## 9. Supersession and remedy

Supersession is valid only while the predecessor is `RESERVED` and uninvoked.
One transaction MUST:

- mark the predecessor `SUPERSEDED` and release its unconsumed resources;
- create a successor in `RESERVED`;
- bind the exact predecessor snapshot;
- require a new admission but the same tenant, operation, CAID, action digest,
  effect-request digest, provider binding, adapter digest, and idempotency key;
- transfer any shared resource reservation without an unlocked interval.

The permanent operation head moves to the successor. A changed operation or
canonical effect identity is an `operation_conflict`; after
`beginInvocation`, supersession is refused.

A remedy is a separately qualified and authorized admission that references an
`INVOKING`, `INDETERMINATE`, `COMMITTED`, or `PROVEN_NOT_COMMITTED` original.
It MUST have a new operation, admission, CAID, action digest, evidence set, and
local authorization. It MUST NOT erase, mutate, release, or reinterpret the
original execution right, provider outcome, effect relation, or journal.

## 10. Migration, shadow, and cutover

Shadow mode is structurally non-actuating in the public runtime: its constructor
rejects an Admission Store, protected adapter, provider-evidence verifier, or
effect relator. It may compute the pure v2 decision and call an optional legacy
qualification comparator, but it cannot reserve, call `beginInvocation`,
reconcile, or enter the provider.

Before enforce cutover, an operator MUST:

1. inventory every protected mutation path and consequence owner;
2. deploy one durable shared Admission Store for old and new paths;
3. prove tenant, operation, and resource-key parity;
4. import or drain open legacy reservations without reopening consumed or
   uncertain authority;
5. classify every ambiguous legacy record as consumed/indeterminate until
   reconciled;
6. demonstrate shadow decision parity or document bounded intentional
   differences;
7. exercise crash, failover, stale-status, provider-loss, and reconciliation
   drills; and
8. atomically route the consequence-owning path to v2.

Rollback MAY redirect requests that have not passed `beginInvocation`.
Rollback MUST NOT replay, delete, or downgrade a v2 `INVOKING`,
`INDETERMINATE`, `COMMITTED`, or `PROVEN_NOT_COMMITTED` record. Those records
remain under the v2 reconciliation contract.

## 11. Implemented reference, release, and deployment boundaries

### 11.1 Public implemented reference

The Apache-2.0 tree includes:

- exported `@emilia-protocol/verify` qualification and Promptfoo modules;
- exported `@emilia-protocol/gate` composer, orchestrator, canonical memory
  store, and PostgreSQL adapter;
- the deployment-bound single-tenant PostgreSQL SQL/RPC contract;
- the offline `ep-qualify` CLI;
- focused verifier, Gate, memory-store, PostgreSQL-contract, CLI, and
  environment-gated real-PostgreSQL tests;
- a checked-in closed TypeScript reference-vector corpus and strict adapter; and
- the authenticated bounded TLC checker, safe result, and deliberately unsafe
  supersession control.

This is implemented reference status, not a certification. The vector adapter
and bounded model are same-team evidence, not independent interoperability,
arbitrary-concurrency proof, or mechanized TypeScript/SQL refinement.

### 11.2 Release order

The release metadata in this tree requires
`@emilia-protocol/verify@3.16.0` first. Only after the exact registry tarball is
available at the pinned digest may `@emilia-protocol/gate@0.18.0` and
`ep-qualify@0.1.0` release; those two downstream packages may then release
independently. Package versions and workflows in a checkout do not establish
that any package was published.

### 11.3 Public/private and deployment split

The public SQL and adapter are intentionally bound to exactly one deployment
and one tenant. They contain no managed tenant-to-principal map and are not a
multi-tenant service schema or deployment migration. Public verification MUST
NOT depend on private company material.

A managed or private Gate deployment may supply tenant assignment and policy,
protected provider adapters and credentials, principal mapping, KMS/HSM
custody, database provisioning and migrations, backup/failover, monitoring,
reconciliation roles and runbooks, protected-path inventory, and service
commitments. None of those operational facts is established merely by the
public source, SQL, adapter flags, tests, package metadata, or formal result.
No managed-production deployment, provider-truth, federated-atomicity,
certification, legal-compliance, or package-publication claim follows from this
profile.

## 12. Standardization boundary

Gate Qualification v2 is an implementation profile over existing public
formats and EMILIA extension points. It creates no new IETF Internet-Draft and
makes no claim that IETF has adopted, reviewed, or endorsed it. Publication or
implementation of this document MUST NOT be described as an IETF submission.
Any future standards action requires a separate governance and submission
decision.
