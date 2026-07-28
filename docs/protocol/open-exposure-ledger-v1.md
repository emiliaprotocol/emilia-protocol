# Open Exposure Ledger v1

Status: experimental Gate implementation profile.

## 1. Purpose and boundary

The Open Exposure Ledger reserves a fixed minor-unit risk amount before a
protected executor enters a consequential effect boundary. It answers a narrow
operational question:

> How much configured exposure is still in custody for this tenant, program,
> counterparty, action class, currency, and fixed window?

It is not a payment ledger, general ledger, insurance policy, authorization
source, or proof of loss. A reservation does not establish legal
enforceability, payment, coverage, causation, solvency, collectability, or the
truth of an underlying commercial claim. A stored digest proves only that the
ledger record is bound to the identified bytes under the stated digest
algorithm. The ledger does not infer what those bytes prove.

Native signed artifacts retain their native claim boundaries. An integration
MUST verify any required signature, issuer, trust configuration, action
binding, freshness, and substantive evidence rules before invoking this
ledger. The reference stores authenticate the calling authority and preserve
the supplied evidence digest; they do not make an otherwise invalid artifact
valid.

## 2. Data model

Amounts are positive signed 64-bit integers in a named three-letter currency.
Floating-point values are forbidden. Amounts in different currencies or
different windows are never added.

Each reservation binds:

- tenant, exposure, and idempotent operation-token digest;
- program identifier and exact `program_version`, `program_source_digest`, and
  `program_digest`;
- exact CAID, `action_digest`, `admission_snapshot_digest`,
  `authorization_digest`, and canonical `authorization_expires_at`;
- counterparty and action class;
- amount, currency, fixed window, reservation time, invocation deadline, and
  reconciliation deadline;
- distinct origin, executor, and reconciliation authority identifiers;
- one reservation-evidence digest; and
- the four ceiling digests applied by the reservation transaction.

These execution and authorization pins are immutable. They are included in the
reservation digest, current-record digest, and every history-entry digest, and
the executor MUST present an exact copy before invocation can begin. The CAID
and signed-artifact digests identify supplied bytes and claims only; their
presence does not create authorization or widen any artifact's claim scope.

`invoke_by` MUST be no later than both `window_end` and
`authorization_expires_at`. An authorization expiry does not release an
existing reservation; it only prevents new effect entry.

Each fixed tenant/currency/window configuration MUST contain exactly one
matching ceiling at each scope:

1. `TENANT` with scope value `*`;
2. `PROGRAM` with the reservation's program identifier;
3. `COUNTERPARTY` with the reservation's counterparty identifier; and
4. `ACTION_CLASS` with the reservation's action class.

Ceilings are create-only. A changed ceiling is a new configuration for a new
identifier or window; an existing ceiling is not rewritten while reservations
refer to it.

## 3. Lifecycle and open exposure

The lifecycle is:

```text
RESERVED -> INVOKING -> INDETERMINATE -> CLOSED_COMMITTED
                    \                    -> CLOSED_PROVEN_NOT_COMMITTED
                     -> CLOSED_COMMITTED
                     -> CLOSED_PROVEN_NOT_COMMITTED
RESERVED --------------------------------> CLOSED_PROVEN_NOT_COMMITTED
```

`RESERVED`, `INVOKING`, and `INDETERMINATE` are open and count at their full
reserved amount against every applicable ceiling. In particular:

- `INVOKING` means custody crossed the invocation linearization point. It does
  not prove provider receipt or effect.
- `INDETERMINATE` means the effect cannot safely be classified. It remains open
  and MUST NOT be retried blindly.
- `CLOSED_COMMITTED` records an authenticated reconciler's `COMMITTED`
  closeout bound to an evidence digest.
- `CLOSED_PROVEN_NOT_COMMITTED` records an authenticated reconciler's
  `PROVEN_NOT_COMMITTED` closeout bound to an evidence digest.

The two closed labels are ledger outcomes under the configured reconciliation
procedure. The ledger does not independently establish payment, external
provider truth, business effect, causation, or legal consequences.

There is deliberately no release operation. A stale reservation, failed
request construction, timeout, or missing provider response does not reduce
open exposure. Only the separately authenticated reconciliation authority can
close it. A remedy, reversal, refund, or replacement is a new authorized action
and does not rewrite this history.

## 4. Atomic reservation

`reserve` is the only operation that adds open exposure. It MUST complete
before effect entry.

In one linearizable critical section or PostgreSQL transaction, the store:

1. authenticates the tenant-mapped origin authority;
2. enforces distinct origin, executor, and reconciliation authority IDs;
3. resolves exactly four immutable ceilings;
4. locks the ceiling rows in `(scope, scope_value)` order;
5. sums all rows in `RESERVED`, `INVOKING`, or `INDETERMINATE` for each scope;
6. refuses if `current_open + requested > limit`; and
7. inserts the reservation and initial history entry before committing.

The implementation compares `requested > limit - current_open` after checking
that current open exposure is not already above the limit. This avoids integer
overflow. Open sums are derived from rows rather than a decrementable counter,
so duplicate closeout cannot underflow a balance.

All database transactions are limited to local validation, row locking,
aggregation, and writes. Network calls, provider calls, and artifact
verification occur outside the transaction.

`beginInvocation` is the effect-entry linearization point. The first accepted
`RESERVED` to `INVOKING` transition returns one unpredictable invocation permit
and stores only its domain-separated, reservation-bound digest in the record
and history. Possession of that permit authorizes only this single configured
effect entry; it is not evidence of provider receipt, commitment, payment, or
external authorization.

The in-memory store obtains invocation time from its injected monotonic clock.
The PostgreSQL store uses `transaction_timestamp()` inside the row-locking
transaction. Caller-supplied invocation time is forbidden. A start after
`invoke_by` or `authorization_expires_at` returns `invocation_expired` without
issuing a permit.

## 5. Idempotency and retry rules

Operation and reconciliation tokens are high-entropy caller-generated tokens.
Only their SHA-256 domain-separated digests enter PostgreSQL payloads and
records.

- Reusing an operation token with the exact reservation semantics returns the
  original reservation as an idempotent replay.
- Reusing it with changed semantics returns `operation_token_conflict`.
- Exactly one racing `beginInvocation` call may transition `RESERVED` to
  `INVOKING` and receive the raw invocation permit.
- Every replay once the row is `INVOKING` or `INDETERMINATE` returns the
  non-authorizing `reconciliation_required` result. The raw permit is never
  returned again.
- Any mismatch in the immutable execution or authorization pins returns
  `immutable_binding_conflict` before effect entry.
- Reusing a reconciliation token with the exact reconciliation request returns
  the original response.
- Reusing it with any changed exposure, outcome, evidence, or observation time
  returns `reconciliation_token_conflict`.

An ambiguous acknowledgement MUST be recovered through the independent
reconciliation path or a READER observation; replaying `beginInvocation` is
never an authority-recovery mechanism. An ambiguous provider effect MUST NOT be
retried.

## 6. Authority separation

The roles are `POLICY_ADMIN`, `ORIGIN`, `EXECUTOR`, `RECONCILER`, and `READER`.
They are not interchangeable:

- `POLICY_ADMIN` creates immutable ceilings.
- `ORIGIN` reserves exposure and must match `originAuthorityId`.
- `EXECUTOR` moves its authority-bound record to `INVOKING` or
  `INDETERMINATE` and must match `executorAuthorityId`; it receives no
  tenant-wide read RPC.
- `RECONCILER` records indeterminate or terminal reconciliation and must match
  `reconciliationAuthorityId`.
- `READER` alone performs tenant-wide reads, history, aging, deadline, and sum
  queries.

The PostgreSQL store authenticates `SESSION_USER` against a private
tenant/authority mapping and a dedicated `NOLOGIN`, `NOBYPASSRLS` custody role.
One database principal cannot be mapped to multiple origin/executor/reconciler
roles for the same tenant. Generic `PUBLIC`, `anon`, `authenticated`, and
`service_role` principals receive no ledger table or RPC authority.

Deployment provisioning MUST preserve the same separation when granting custom
role membership and tenant mappings. A superuser or migration owner is an
administrative bootstrap principal, not a runtime custody principal.

## 7. Reconciliation and immutable history

`reconcile` accepts `COMMITTED`, `PROVEN_NOT_COMMITTED`, or `INDETERMINATE`.
`INDETERMINATE` appends reconciliation evidence but leaves the full amount
open. A later reconciliation token may provide a terminal outcome.

Every accepted transition appends a tenant/exposure sequence entry containing
the event, all immutable execution and authorization pins, invocation-permit
digest when issued, record digest, evidence digest, timestamp, and
predecessor-entry digest. History rows cannot be updated or deleted. Current
records preserve a revision number and predecessor-record digest; terminal
records cannot change.

History is tamper-evident custody evidence under this implementation. It is not
by itself proof that a provider committed an effect or that an observed effect
had a particular legal or financial meaning.

## 8. Operational queries

`sumOpen` returns an exact fixed-window total plus deterministic, bytewise-key
ordered breakdowns by program, counterparty, action class, and status.

`listAging` returns open rows ordered by `(reserved_at, exposure_id)` once their
reservation age reaches the requested threshold.

`listDeadlines` uses `invoke_by` for `RESERVED` rows and `reconcile_by` for
`INVOKING` or `INDETERMINATE` rows, ordered by `(deadline, exposure_id)`.

All broad queries are tenant scoped, authenticated, and restricted to the
configured `READER` authority. Custody roles receive only their mutation RPCs.
Queries report ledger state, not external effect truth.

## 9. Reference stores

`createMemoryOpenExposureLedger` is a linearizable in-process reference store
for conformance, race, and hostile-state tests. It is explicitly non-durable
and test-only. Callers may inject an absolute UTC monotonic clock; the default
uses Node's monotonic clock source, and any observed regression fails closed.

`createOpenExposurePostgresLedger` is deployment- and tenant-bound. Each
mutation is one call to a private PostgreSQL function. The migration applies
RLS and `FORCE ROW LEVEL SECURITY` to every private table, revokes all direct
table access from runtime roles, grants only role-specific RPC execution, uses
composite and partial indexes for open aggregates and operational scans, and
keeps transactions short.
