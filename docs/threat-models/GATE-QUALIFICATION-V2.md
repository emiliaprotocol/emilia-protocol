<!-- SPDX-License-Identifier: Apache-2.0 -->
# Gate Qualification v2 Threat Model

**Status:** threat model for the implemented public reference; managed
deployment controls, package publication, and provider truth require separate
evidence, and no certification is claimed

## 1. Security objective

Prevent a candidate, requester, evaluator, Gate replica, migration path, or
provider-response failure from turning evaluation evidence into unbounded
execution authority, changing the admitted action, invoking twice, rewriting
an uncertain effect as uninvoked, or erasing the original through supersession
or remedy.

The protected asset is not a score. It is the one-time right to cross the
provider or system-of-record mutation boundary for one exact action and its
bounded resources.

## 2. In scope

- candidate and campaign artifact integrity;
- evaluator and status-authority trust separation;
- assignment, policy, protected-request, and candidate-currentness binding;
- candidate measurement and influence cutoff;
- pure decision integrity;
- Admission Store tenant, operation, resource, owner, revision, and journal
  fences;
- provider-credential custody;
- crash, timeout, response-loss, and reconciliation behavior;
- supersession, remedy, migration, rollback, and cross-version replay;
- `local_atomic` and federated claim boundaries.

## 3. Out of scope and non-claims

This repository does not establish:

- that tests measure the right real-world property;
- model safety, legal compliance, business wisdom, or human comprehension;
- civil identity beyond the verified native evidence profile;
- correctness or honesty of an external provider;
- production key custody, database operation, backup, failover, monitoring, or
  protected-path completeness;
- global atomicity or exactly-once execution across independent federation
  domains;
- independent implementation or deployment;
- an audit opinion, certification, or IETF endorsement.

The bounded TLA+ result is a finite same-team control abstraction. It is not a
mechanized refinement to TypeScript, SQL, a provider, or a deployment.

## 4. Trust boundaries

### TB-1: Candidate and requester

May control code, prompts, tools, retrieval, memory, user input, request
presentation, and supplied evidence. They must not select trust roots, policy,
effect keys, owner tokens, provider credentials, or reconciliation truth.

### TB-2: Evaluation infrastructure

Produces campaigns and results but does not authorize execution. Harness,
environment, evaluator configuration, challenge campaign, assignment, and
candidate are independently pinned by the relying party.

### TB-3: Qualification and status authorities

Sign the Qualification Statement and its current status. Their keys and
thresholds are role-specific. A status observation is a relying-party input,
not self-asserted freshness.

### TB-4: Gate decision domain

Owns AEB/AEC composition, local policy, protected-request construction,
runtime measurement, and the immediate pre-invocation recheck. It must remain
separate from requester-controlled code.

### TB-5: Admission state domain

Owns operation uniqueness, resource reservation, CAS state, owner capabilities,
and journal history. Every active replica for the consequence must share this
domain for a fleet-wide claim.

### TB-6: Protected adapter and provider

Owns provider credentials and mutation implementation. Gate supplies only
frozen bindings. Provider observations are untrusted until authenticated and
related to the exact admitted effect.

### TB-7: Recovery and remedy operators

May reconcile or compensate under separately authorized roles. They must not
restore consumed authority or rewrite prior evidence.

## 5. Threats and required controls

| ID | Threat | Required control | Residual limitation |
| --- | --- | --- | --- |
| QV2-T01 | Candidate swaps code, prompt, tool, dependency, permissions, retrieval configuration, builder, or model after evaluation. | Exact Candidate Manifest, Runtime Candidate Measurement, minimum pinning strength, static canonical equality, freshness, and begin-invocation remeasurement when the candidate remains in path. | A mutable or externally hosted model may remain unpinnable; the safe result is refusal, not inferred identity. |
| QV2-T02 | Candidate influences the protected request after measurement. | Define and enforce `candidate_influence_cutoff`; bind dynamic retrieval, memory, user input, and protected request; freeze adapter input; require transactional currentness before invocation. | Supplying an authoritative currentness oracle or deployment table and complete process isolation remain deployment work. |
| QV2-T03 | Evaluator selectively omits failures or adds/reorders favorable results. | Hidden commitments, scenario-selection commitment, complete slot coverage, contiguous attempts, exact terminal counts/root, single-use test-result references, and no unreferenced results. | The profile proves campaign closure under committed scenarios, not that scenario selection is scientifically sufficient. |
| QV2-T04 | A failure, abort, expiry, or provider error is laundered into a pass. | Closed status vocabulary, cross-check source status against response/error/grading/measurements, and retain terminal evidence digest. | Source-system semantics still require a reviewed adapter profile. |
| QV2-T05 | Mutable aliases (`latest`, branch names, rolling model tags) are presented as immutable pins. | Reject mutable aliases; require exact semantic versions and digest-bound immutable references. | Some providers expose no immutable artifact; qualification must reflect weaker pinning. |
| QV2-T06 | Signature is valid but signer is not accepted for the artifact role. | Separate VERIFIED from ACCEPTED; role-specific key maps, accepted key IDs, and thresholds. | Key governance and compromise response are managed controls. |
| QV2-T07 | Old, revoked, suspended, expired, or equivocated qualification is replayed. | Signed status chain, exact predecessor and sequence, observed head, authority ID, sequence floor, freshness, `next_update`, `valid_until`, and equivocation refusal. | One observation is current-as-observed, not a global-consistency proof. |
| QV2-T08 | Qualification is treated as authorization. | Pure three-way decision; explicit AEB, AEC, and local-policy legs; evaluation adapters set `authorizes: false`. | Misuse outside Gate cannot be prevented by the evidence format alone. |
| QV2-T09 | Caller substitutes CAID, action, provider account, target, prompt, model, tool, or operation after decision. | Exact binding on every decision leg, immutable snapshot, pre-invocation recheck, frozen protected invocation, and binding verification on provider evidence. | Complete mediation requires all actual mutation paths to use the protected adapter. |
| QV2-T10 | Caller supplies a benign effect key while invoking a dangerous operation. | Derive tenant-operation key internally; never accept a presenter-selected replay key. | Operation construction must include every consequence-relevant dimension or reserve additional resource keys. |
| QV2-T11 | Two replicas or v1/v2 paths invoke the same effect. | One shared durable `local_atomic` Admission Store and final consequence-owner fence. | The memory store is single-process only. The PostgreSQL adapter/SQL are implemented public references, but no shared managed-production deployment is established. |
| QV2-T12 | Resource oversubscription across different operations. | Atomically reserve tenant-scoped resource keys with the admission; consume before provider entry; transfer only in atomic supersession. | Resources omitted from the snapshot are outside the fence. |
| QV2-T13 | Stale writer or token thief changes admission state. | Revision CAS plus opaque owner capability; store only owner digest; recovery requires that owner and rotates the invocation capability to a fresh reconciliation token. | The owner token is not rotated by recovery. Owner/reconciliation-token custody and recovery authorization are deployment responsibilities. |
| QV2-T14 | Store claims success but record, resources, or journal did not commit together. | One transaction, exact persisted-object readback, record/journal head consistency, immutable snapshot/journal, and invariant checks. | SQL presence alone is not operational durability evidence. |
| QV2-T15 | Process crashes immediately before or after provider entry and retries. | `beginInvocation` consumes authority before adapter call; any post-begin ambiguity is reconciliation-required; no blind retry. | This intentionally creates false-positive uncertainty when the crash was before provider entry. Safety takes precedence over availability. |
| QV2-T16 | Provider response is forged, stale, or bound to another attempt. | Authenticate evidence and bind tenant, admission, attempt, operation, CAID, action, provider account, outcome, and time. | Provider evidence cannot establish facts the provider itself does not expose. |
| QV2-T17 | Provider says committed, but a different effect occurred. | Persist provider `COMMITTED` independently from effect `DIVERGED`; require a determinate relation and observed-effect digest before representing the relation as `OBSERVED_AS_REQUESTED`. | Physical-world truth may remain outside cryptographic evidence. |
| QV2-T18 | Non-commit response is mistaken for proof of no effect. | Require authenticated `PROVEN_NOT_COMMITTED` on the provider axis and independently authenticated effect-relation evidence; never infer one axis from the other. | Eventual provider consistency can delay terminalization. |
| QV2-T19 | Reconciliation accidentally invokes the provider again. | Separate `reconcile()` adapter method with `reconciliationOnly: true`; no code path to `invoke()`. | Adapter implementation and provider client permissions still require review. |
| QV2-T20 | A terminal store write acknowledgement is lost and caller reports a result or retries. | Return reconciliation-required and retain consumed authority; reconcile exact evidence and record head. | Availability depends on durable store recovery. |
| QV2-T21 | Supersession releases already-consumed authority. | Permit supersession only from `RESERVED`; atomically mark predecessor `SUPERSEDED` and create successor; paired TLA+ negative control demonstrates the forbidden late transition. | Runtime-to-model refinement is not proven. |
| QV2-T22 | Supersession creates an unlocked resource interval, two successors, or a changed effect under an old operation. | One serialized transaction, revision/owner fence, a new admission with the same operation/CAID/action/effect-request/provider/adapter/idempotency identity, permanent operation head, and atomic resource transfer. | Supersession is a store operation; the high-level `execute()` path intentionally refuses a caller-supplied superseding snapshot. |
| QV2-T23 | Remedy rewrites or erases the original effect. | Fresh admission, operation, CAID, action, evidence, and authorization; immutable original record and journal. | Remedy effectiveness and legal enforceability are not protocol claims. |
| QV2-T24 | Shadow mode accidentally actuates or is cited as enforcement proof. | Shadow performs decision comparison only and never reserves, rechecks, or calls an adapter. | It does not test store races, durability, provider custody, or reconciliation. |
| QV2-T25 | Cutover creates two active replay domains. | Share the final Admission Store before enforcement; drain/import legacy records; classify ambiguity as consumed/indeterminate; cut over at the consequence owner. | Production migration tooling and evidence are pending. |
| QV2-T26 | Rollback replays a v2 in-flight action through v1. | Roll back only pre-`beginInvocation` traffic; keep consumed v2 records under v2 reconciliation and visible to the shared fence. | Operational routing must honor the shared state. |
| QV2-T27 | A caller uses the public PostgreSQL reference for the wrong tenant or represents it as managed multi-tenancy. | Permanent singleton deployment/tenant binding, adapter-side tenant assertion, binding checks in every RPC, revoked public table/function access, dedicated runtime `EXECUTE` grants, and no presenter-selected tenant session setting. | The reference deliberately has no managed tenant-principal map or RLS isolation model; it is not a deployment migration or operated service. |
| QV2-T28 | Federated parties claim global atomicity from local receipts. | State the guarantee class; require one final `local_atomic` consequence owner; treat remote state as evidence only. | No distributed commit, global freshness, or federated exactly-once implementation exists. |
| QV2-T29 | Journal or snapshot history is edited to hide a transition. | Content-addressed immutable snapshots, append-only predecessor-digest journal, terminal immutability, and exact head verification. | A database owner or infrastructure compromise may require external anchoring and incident evidence. |
| QV2-T30 | Public reference code is represented as a managed production control. | Explicit implementation-status mapping and public/managed boundary; require deployment-specific evidence. | Users can still deploy the reference code unsafely outside the claim. |
| QV2-T31 | Downstream packages are released against unavailable or substituted verifier bytes, or local metadata is cited as proof of publication. | Release Verify 3.16.0 first; require Gate 0.18.1 and `ep-qualify` 0.1.0 to verify the exact pinned registry tarball before release. | Release workflows and local package versions do not establish that registry publication occurred. |

## 6. State-machine safety properties

A conforming implementation should continuously check:

1. at most one live admission per tenant and operation;
2. no conflicting live resource owner;
3. `RESERVED` implies unconsumed authority and reserved resources;
4. `INVOKING`, `INDETERMINATE`, `COMMITTED`, and
   `PROVEN_NOT_COMMITTED` imply consumed authority;
5. consumed authority never becomes reserved or released;
6. provider entry is never represented as retryable;
7. terminal state is immutable;
8. accepted provider/effect evidence is immutable and exactly bound;
9. supersession begins only from `RESERVED`;
10. supersession changes admission identity while preserving the same canonical
    operation, CAID, action, effect request, provider, adapter, and idempotency
    identity;
11. every remedy names a different operation, CAID, action, and snapshot;
12. record revision equals journal-head sequence; and
13. journal predecessor and record-head digests verify.

The checked-in finite model covers the corresponding control-flow subset. The
managed deployment must additionally prove storage, clock, key, provider,
network, and protected-path assumptions.

## 7. Failure policy

| Failure point | Required behavior |
| --- | --- |
| Before reserve | Refuse; no provider call. |
| Ambiguous reserve acknowledgement | Refuse; read exact store state before any retry. |
| Recheck or remeasurement failure | Refuse and release only if the store proves authority is still unconsumed. |
| Ambiguous `beginInvocation` acknowledgement | Refuse provider entry; reconcile store state. |
| Any exception after successful `beginInvocation` | Preserve consumed authority; require reconciliation. |
| Invalid or unbound provider evidence | Remain indeterminate; never infer success or failure. |
| Terminal store write unconfirmed | Return reconciliation-required; never retry the effect. |
| Reconciliation unavailable | Remain indeterminate and alert an authorized operator. |
| Remedy unavailable | Preserve original history; do not relabel the original. |

## 8. Migration abuse cases

Before cutover, red-team at least:

- concurrent v1/v2 requests for the same tenant-operation;
- different operations sharing one resource;
- stale legacy reservation import;
- consumed legacy record mislabeled reserved;
- crash between routing cutover and store write;
- rollback after successful `beginInvocation`;
- failover with lost terminal acknowledgement;
- stale qualification status at recheck;
- candidate mutation after influence cutoff;
- provider response bound to another attempt;
- recovery owner theft; and
- federated remote success with local timeout.

Passing shadow comparison is not sufficient. Enforce cutover requires the
durable shared store, production adapter, migration, exact readback,
reconciliation path, and protected-path inventory.

## 9. Implemented reference status and remaining limits

- The pure verifier and Promptfoo adapter are implemented, package-exported,
  and covered by focused hostile tests.
- `GateQualificationV2` directly consumes the canonical immutable
  `AdmissionSnapshot`/CAS record/journal store contract. Shadow mode is
  structurally non-actuating; enforcement and evidence-only reconciliation are
  implemented.
- The memory Admission Store is a non-durable, one-process, test-only
  reference.
- The PostgreSQL adapter, deployment-bound single-tenant SQL, static contract
  tests, and environment-gated real-PostgreSQL concurrency/recovery suite are
  present. The SQL is not a managed deployment migration, and a skipped
  environment-gated integration run is not production evidence.
- Provider outcome and effect relation use separate runtime interfaces, CAS
  transitions, journal events, and tests. `COMMITTED + DIVERGED` is a valid
  represented result, not a contradiction that may be erased.
- Recovery rotates the invocation/reconciliation capability and invalidates
  the old token. The public runtime now requires a protected, restart-safe
  `InvocationAuthorityCustodyV2` contract and tests process replacement; the
  provided in-memory implementation remains explicitly test-only. KMS/HSM
  policy and recovery-role authorization remain deployment evidence.
- Runtime has no explicit provider-entry transition matching the formal
  `EnterProvider` action. Conservative reconciliation covers any exception
  after successful `beginInvocation`.
- The checked-in closed vector corpus and TypeScript adapter are same-team
  reference evidence. They do not prove independent interoperability, arbitrary
  concurrency, or mechanized implementation refinement.
- The bounded TLC result covers 4,048 generated / 160 distinct safe states, 19
  invariants, 10 properties, a `COMMITTED + DIVERGED` witness, and a five-state
  unsafe late-supersession counterexample. It abstracts cryptography, provider
  truth, clocks, storage, deployment, and arbitrary concurrency.
- The release chain orders Verify 3.19.0 before Gate 0.22.1 and `ep-qualify`
  0.1.0, but the checkout does not establish that any package is live.
- No federated coordinator, managed-production deployment, independent
  implementation, or production recovery evidence is established here.

These limits prevent claims of certification, managed-production readiness,
deployed exactly-once behavior, federated atomicity, arbitrary-concurrency
proof, or mechanized implementation refinement.

## 10. Public/reference and managed/private boundary

Public/reference material defines inspectable formats, deterministic
verification, refusal semantics, state invariants, exported reference
implementations, the single-tenant PostgreSQL adapter/SQL, offline CLI,
vectors, tests, release guards, and bounded formal evidence.

Managed/private operation supplies real tenant policy, keys, provider
credentials, protected adapters, durable database deployment, status
distribution, tenant-principal mapping, migrations and runtime grants, path
inventory, monitoring, reconciliation staff and runbooks, backups, failover,
incident response, and customer-specific evidence. Those controls require
deployment evidence and cannot be inferred from repository code, SQL, tests,
package metadata, or formal output.

This threat model and profile create no new IETF Internet-Draft. They do not
claim IETF review, adoption, or endorsement, and they are not a certification.
