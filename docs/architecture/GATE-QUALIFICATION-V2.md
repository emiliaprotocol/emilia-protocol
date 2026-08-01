<!-- SPDX-License-Identifier: Apache-2.0 -->
# Gate Qualification v2 Implementer Architecture

**Status:** implemented public reference architecture; not a certification,
package-publication claim, managed-production deployment, or independent
interoperability claim

## 1. Architecture objective

Gate Qualification v2 turns a content-pinned evaluation campaign into one
input to a consequence-owning Gate without letting evaluation evidence become
authorization. It joins five independently controlled planes:

```text
candidate and campaign artifacts
              |
              v
pure Qualification verifier ----> QUALIFIED / NOT_QUALIFIED / INDETERMINATE
              |
              v
AEB + AEC + local policy --------> pure composed Gate decision
              |
              v
immutable AdmissionSnapshot -----> atomic resource and operation reserve
              |
              v
beginInvocation CAS --------------> consume authority before provider entry
              |
              v
protected adapter ----------------> provider evidence + effect relation
              |
       +------+------+
       |             |
   terminal      INDETERMINATE
       |             |
       +------ authenticated reconciliation only
```

The normative behavior is
[Gate Qualification v2 Profile](../protocol/gate-qualification-v2.md). The
threat analysis is
[Gate Qualification v2 Threat Model](../threat-models/GATE-QUALIFICATION-V2.md).

## 2. Component boundaries

### 2.1 Pure qualification verifier

`packages/verify/src/gate-qualification.ts` owns:

- strict canonical JSON and DSSE verification;
- role-specific threshold trust policies;
- Candidate Manifest and Runtime Candidate Measurement validation;
- campaign lineage, hidden-challenge, terminal-closure, and test-result joins;
- Qualification Statement graph binding;
- Qualification Status chain and observed-head currentness; and
- the pure three-way decision.

It has no storage or network dependency. The caller supplies trusted time,
expected digests, freshness limits, minimum model-pinning strength, and public
keys. Implementers must preserve that dependency direction: the artifact must
not supply its own trust policy or trusted clock.

`packages/verify/src/gate-qualification-promptfoo.ts` is an upstream adapter. It
accepts a closed Promptfoo v3 output plus out-of-band immutable pins, re-derives
artifact, attempt, payload, count, metric, and lineage bindings, and emits
`EP-GATE-QUALIFICATION-EVALUATION-EVIDENCE-v2` with
`classification: EVALUATION_ONLY` and `authorizes: false`. It does not emit a
Qualification Statement and cannot authorize provider entry.

### 2.2 Pure Gate composer

`composeQualificationDecisionV2()` in
`packages/gate/src/gate-qualification-v2.ts` is deterministic and performs no
store, provider, legacy, or policy lookup. It requires matching qualification,
AEB, AEC, and local-policy legs and freezes the resulting invocation and
requirement bindings.

The request contains no caller-selected effect key. The implementation derives
the effect fence from tenant plus operation.

### 2.3 Orchestrator

`GateQualificationV2` supports:

- `shadow`: compare v2 with an optional legacy decision without reservation,
  store access, protected adapter, provider-evidence verifier, effect relator,
  or actuation;
- `enforce`: reserve through the canonical `AdmissionStore`, atomically run
  an authoritative pre-invocation remeasurement, transactionally recheck
  currentness and consume the invocation/resource rights, persist the rotated
  invocation authority through protected restart-safe custody, call
  the protected adapter with the exact store-returned snapshot, persist
  provider evidence, independently persist the observed-effect relation, and
  complete or require reconciliation; and
- `reconcile`: call only the adapter's evidence-only reconciliation method.

The orchestrator requires an atomic, ownership-fenced, exclusive store, an
authoritative `InvocationRemeasurerV2`, and protected
`InvocationAuthorityCustodyV2`. Production construction requires both store
and custody to be durable; checked-in memory implementations are accepted only
with explicit `testOnly: true`.

### 2.4 Protected adapter

The adapter contract fixes `custody: protected` and
`credentialsExposed: false`. Invocation receives only immutable IDs and
digests plus the invocation token. The provider credential and provider API
implementation remain inside the protected boundary.

Provider evidence verification and observed-effect relation are separate
interfaces. The first authenticates and binds the provider observation. The
second establishes `same_effect`, `no_effect`, or `indeterminate`. Neither
interface may silently trust the adapter's return type.

### 2.5 Unified Admission Store

`packages/gate/src/admission-store.ts` defines the canonical store consumed
directly by the orchestrator:

- immutable, content-addressed `AdmissionSnapshot`;
- separate CAS-owned `AdmissionRecord`;
- one-time execution right;
- tenant-operation uniqueness;
- shared resource reservations;
- separate append-only predecessor-digest journal;
- same-operation, identity-preserving atomic supersession;
- invocation/reconciliation-token rotation for crash recovery;
- separate provider and effect outcomes; and
- fresh remedy references.

The memory store serializes operations through one in-process queue. That is
linearizable for one JavaScript process and useful for hostile scheduling
tests. It is explicitly non-durable.

`packages/gate/src/admission-store-postgres.ts` and
`packages/gate/sql/gate-qualification-v2.sql` implement the public PostgreSQL
reference. The adapter is explicitly `durable`, `local_atomic`,
`singleTenant`, and `deploymentBound`; it validates exact snapshots, records,
and journals, retries only serialization/deadlock SQLSTATEs, and resolves a
lost `beginInvocation` acknowledgement only by exact invocation-token
readback.

The SQL uses a permanent singleton `(deployment_id, tenant_id)` binding,
permanent operation/resource fences, explicit row locks, immutable
snapshot/journal triggers, consumed-right guards, revoked public table
privileges, and `SECURITY DEFINER` RPCs. It intentionally has no
tenant-principal map, presenter-selected tenant session setting, or
multi-tenant RLS claim. It is installable reference SQL, not an entry in a
managed deployment migration ledger.

## 3. Semantic state mapping

The runtime persists several axes rather than one collapsed terminal label:

| Axis | Values | Meaning |
| --- | --- | --- |
| Admission state | `RESERVED`, `RELEASED`, `EXPIRED`, `SUPERSEDED`, `INVOKING`, `INDETERMINATE`, `COMMITTED`, `PROVEN_NOT_COMMITTED` | Lifecycle and current provider-outcome state. |
| Execution right | `RESERVED`, `RELEASED`, `CONSUMED` | Whether one-time provider-entry authority remains. |
| Provider attempt | `NOT_ENTERED`, `INVOKING`, `INDETERMINATE`, `COMMITTED`, `PROVEN_NOT_COMMITTED` | What is known about entry/commitment. |
| Provider outcome | `COMMITTED`, `PROVEN_NOT_COMMITTED`, `INDETERMINATE` | Authenticated provider evidence. |
| Effect relation | `OBSERVED_AS_REQUESTED`, `DIVERGED`, `INDETERMINATE` | Independently authenticated relation to the requested effect. |

`COMMITTED` is not an alias for executed-as-requested:
`COMMITTED + DIVERGED` is intentionally accepted and covered by runtime tests
and the formal reachability witness. The orchestrator's returned
`committed`/`not_committed` status follows the provider axis and carries the
effect relation separately. No state with a consumed execution right is
retryable.

## 4. Data and digest design

### 4.1 Qualification graph

All signed references use the digest of canonical decoded payload bytes.
Signature envelopes may change only if the same payload remains accepted under
the relying party's trust policy. Campaign, test-result, evidence, statement,
and status keys are role-specific; a deployment should not reuse one key across
all roles.

### 4.2 Admission snapshot

The snapshot normalizer:

- accepts only plain JSON;
- rejects dangerous object keys, accessors, cycles, invalid numbers, invalid
  instants, duplicates, and excessive depth/size;
- orders typed inputs and resources deterministically;
- computes the minimum expiry;
- enforces the closed typed input/resource roles and deadline ceilings; and
- domain-separates the snapshot digest.

The required singleton input roles are `candidate_manifest`,
`runtime_measurement`, `qualification_statement`, `qualification_status`,
`aeb`, `aec`, `local_policy`, and `authorization`; `test_result` and
`agent_evaluation_evidence` are bounded repeatable roles. The store treats the
normalized values as immutable digests; producers and their native verifiers
remain responsible for semantic truth.

### 4.3 Admission record and journal

The record head includes revision, semantic state, execution right, owner
digest, resources, provider/effect outcomes, supersession relation, invocation
time, predecessor record digest, and record digest. The journal sequence equals
the record revision and its head must name the current record digest.

Production adapters must return and validate the exact persisted snapshot,
record, and journal acknowledgement. A row count or generic success boolean is
not enough to establish a committed transition.

## 5. Transaction boundaries

### 5.1 Reserve

One transaction must:

1. assert the fixed deployment and tenant binding;
2. lock the tenant serialization root;
3. refuse permanent tenant-operation reuse;
4. validate the immutable snapshot and initial record;
5. validate remedy relation, if present;
6. refuse conflicting live resources;
7. insert snapshot, record, journal head, and resources; and
8. return exact persisted objects.

### 5.2 `beginInvocation`

Currentness is part of the store transaction. The memory reference calls its
configured currentness oracle inside the serialized operation and refuses when
none is supplied. PostgreSQL locks and compares the deployment binding,
candidate/runtime head, qualification-status head, protected-request head,
AEB/AEC/local-policy/authorization heads, trust/configuration epochs, and
external leases under a maximum observation age before the CAS. Gate first
recomposes those legs from an authoritative remeasurement source. The same
store transaction consumes the execution right and every resource right before
the adapter is called.

An implementation should expose an explicit provider-entry marker that moves
`INVOKING` to `INDETERMINATE` at the boundary. Until that runtime hook is
present, any exception after successful `beginInvocation` must be treated as
reconciliation-required even when the process believes provider entry did not
occur.

### 5.3 Terminalization

Provider outcome and effect relation are separate CAS transitions and separate
journal events. A determinate value on either axis requires its own evidence
digest. The effect relation is bound to accepted provider evidence by the
runtime verifier/relator boundary, but the store does not collapse one axis
into the other; `COMMITTED + DIVERGED` remains representable.

Terminal record states are immutable. Resource rows may be released for an
authenticated no-effect failure or marked committed for execution, but the
operation's execution right remains consumed.

### 5.4 Supersession

Supersession must lock and transition predecessor and successor together.
Shared resource ownership changes inside the same transaction. The predecessor
must be `RESERVED`; a consumed predecessor is never superseded. The successor
gets a new admission ID but preserves tenant, operation, CAID, action digest,
effect-request digest, provider binding, adapter digest, and idempotency key.
The permanent operation head moves to the successor without an unlocked
resource interval.

### 5.5 Recovery and reconciliation

Recovery requires the existing opaque owner capability, rotates the
invocation capability to a fresh reconciliation token, replaces the stored
token digest, and promotes a stranded `INVOKING` record to `INDETERMINATE`.
The old invocation token is refused; the owner token is not rotated. Recovery
never restores execution authority. Reconciliation uses stored immutable
bindings and calls only the evidence-only adapter method.

## 6. Deployment guarantee classes

### 6.1 `local_atomic`

For a production claim, every Gate replica capable of the same consequence
must use one durable admission transaction domain. That domain must cover the
operation key, all named resource keys, admission head, and journal append.
Database failover must preserve linearizability and durability; declaring
flags such as `atomic: true` is not evidence by itself.

### 6.2 `federated`

Federation does not merge independent stores into one transaction. Each domain
can provide signed evidence of its local reservation or decision, but the final
provider effect must still have one consequence owner and one `local_atomic`
fence. There is currently no federated coordinator, distributed commit
protocol, cross-domain recovery implementation, or global exactly-once proof
for Qualification v2.

Implementers must not market several independently retryable gateways as a
unified Admission Store. On partial federation failure, hold the final local
admission closed. Any compensating action is a new remedy.

## 7. Migration architecture

### 7.1 Shadow

Current shadow mode is decision comparison only. Its constructor rejects a
store, protected adapter, provider-evidence verifier, and effect relator, so it
cannot reserve, reconcile, or actuate. It does not detect cross-version
resource races, prove store parity, or exercise provider reconciliation.
Telemetry should record candidate, policy, decision, bounded reason, and
legacy/v2 match without exposing prompts, credentials, or sensitive evidence.

### 7.2 Shared-fence prerequisite

Legacy and v2 paths must share the final tenant-operation/resource fence before
v2 enforce traffic begins. Existing tests show the narrow v2 store can reserve
under a legacy actuation owner, but that is reference behavior, not a
production migration.

Open legacy records require explicit treatment:

- uninvoked reservations may be drained or atomically imported;
- invoked or ambiguous records must import as consumed/indeterminate;
- terminal records remain immutable;
- no migration may recreate a previously used operation as fresh.

### 7.3 Cutover and rollback

Cutover occurs at the consequence owner, not merely at an upstream proxy.
Health checks must cover durable store access, exact readback, status
freshness, adapter custody, and reconciliation readiness.

Rollback may route only work that has not consumed v2 authority. Consumed v2
records continue under v2 reconciliation even if new traffic returns to the
legacy path.

## 8. Implementation mapping

| Surface | Current repository mapping | Honest status |
| --- | --- | --- |
| Pure Qualification verifier and schemas | `packages/verify/src/gate-qualification.ts`; `packages/verify/gate-qualification.test.ts` | Implemented, package-exported, storage/network independent, and covered by focused hostile tests. A `QUALIFIED` result is not authorization. |
| Promptfoo evaluation-only adapter | `packages/verify/src/gate-qualification-promptfoo.ts`; `packages/verify/gate-qualification-promptfoo.test.ts` | Reference adapter and hostile tests present; not an authorization or production-evaluator claim. |
| Pure composition and v2 orchestration | `packages/gate/src/gate-qualification-v2.ts`; `packages/gate/gate-qualification-v2.test.ts` | Implemented and package-exported over the canonical `AdmissionStore`, with non-actuating shadow, enforce, ambiguous-begin recovery, independent provider/effect persistence, and evidence-only reconciliation tests. |
| Unified immutable Admission Store | `packages/gate/src/admission-store.ts`; `packages/gate/admission-store.test.ts` | In-memory reference and hostile scheduling tests present; non-durable. |
| PostgreSQL `local_atomic` reference | `packages/gate/src/admission-store-postgres.ts`; `packages/gate/sql/gate-qualification-v2.sql`; `packages/gate/admission-store-postgres.test.ts` | Adapter, SQL, static contract tests, and an environment-gated real-PostgreSQL concurrency/recovery suite are present. Public SQL is deployment-bound single tenant, not a managed migration or operated-production claim. |
| Unified-store/orchestrator bridge | canonical types above | Implemented directly; no narrower v2 store remains in the runtime path. |
| Explicit provider-entry transition | formal model only | Not implemented as a distinct runtime transition. Runtime conservatively treats every exception after successful `beginInvocation` as reconciliation-required. |
| Separate provider/effect terminalization | canonical store and orchestrator | Implemented as separate CAS transitions, journal events, verifier/relator interfaces, and tests, including `COMMITTED + DIVERGED`. |
| Offline CLI | `packages/qualify/cli.mjs`; `packages/qualify/cli.test.mjs` | Implemented thin offline evaluator with strict JSON, 8 MiB input bound, exact two-line output, and exit 0 only for `QUALIFIED`; never authorizes or mutates. |
| Portable vector corpus | `conformance/vectors/gate-qualification.v2.json`; TypeScript adapter/test | Checked-in closed reference vectors exercise qualification, binding, concurrency, crash, supersession, provider, and retry boundaries; a strict coverage test is included. Same-team reference evidence, not independent interoperability or mechanized refinement. |
| Durable managed deployment and recovery role | none established by these files | Pending external deployment work and evidence. |
| Federated admission coordination | none | Pending; no distributed atomicity claim. |
| Bounded lifecycle model | `formal/ep_gate_qualification_v2.tla`, `.cfg`, paired unsafe module, authenticated checker, and result files | Safe finite model reports 4,048 generated / 160 distinct states at depth 14 with 19 invariants and 10 properties; unsafe control reports a five-state late-supersession counterexample. Not an implementation refinement. |

## 9. Release order

The repository release chain is dependency ordered:

1. publish and verify the exact registry bytes for
   `@emilia-protocol/verify@3.19.0`;
2. only after that pinned tarball is available, release
   `@emilia-protocol/gate@0.22.1` and/or `ep-qualify@0.1.0`.

Gate and `ep-qualify` are downstream siblings and may release independently
after Verify. The release registry pins Verify's exact tarball digest for both.
Versions, changelogs, workflows, or locally passing package tests do not prove
that any npm package has been published.

## 10. Formal-assurance boundary

The checked result covers three qualification records, one tenant, two
operations, three CAIDs, two canonical actions, three canonical requests, two
authorizations, seven admissions, and twelve evidence values. The safe run
exhausted 4,048 generated / 160 distinct states to complete depth 14 with zero
queued states; all 19 state invariants and 10 transition properties held. It
also reached `COMMITTED + DIVERGED`.

The paired unsafe module permits post-entry supersession and produced the
required five-state counterexample to `SupersessionOnlyWhileReserved` after
165 generated / 15 distinct states.

It abstracts signatures, clocks, provider truth, storage durability,
linearizability, arbitrary concurrency, and TypeScript/SQL refinement. The
vector adapter is likewise a selected same-team reference mapping, not a
mechanized refinement proof. Implementers may cite the formal result only as
bounded finite-control evidence with those limits.

## 11. Public/reference and managed/private split

Public/reference:

- artifact shapes and pure verification;
- Promptfoo evidence adapter;
- exported Gate composition and canonical-store orchestration;
- test-only memory Admission Store;
- deployment-bound single-tenant PostgreSQL adapter and installable SQL;
- offline CLI, reference-vector corpus, tests, release guards, and bounded
  formal evidence.

Managed/private:

- tenant assignments and policy;
- production provider adapters and credentials;
- KMS/HSM custody and status-authority operations;
- database provisioning, migrations, backups, failover, and recovery roles;
- managed tenant-principal mapping and runtime-role grants;
- protected-path inventory, telemetry, alerts, runbooks, and service levels;
- customer-specific deployment and reconciliation evidence.

Private services may implement the public contract but must not become a hidden
dependency of public verification. The public source does not establish
managed-production operation, package publication, provider truth, federated
atomicity, or certification. This architecture creates no new IETF draft and
claims no IETF review, adoption, or endorsement.
