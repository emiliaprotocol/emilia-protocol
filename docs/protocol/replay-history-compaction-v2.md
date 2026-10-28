# Anchored exact-membership compaction, local v2 follow-up

This follow-up to the native replay-history profile adds one missing capability:
physical reclamation of raw authoritative history after an exact membership snapshot
has been independently anchored. It is a separate fresh-only implementation and
schema, not an in-place upgrade/import of a v1 or legacy operational database.

## Source and provider-path integration

`createPostgresCompactingReplayHistoryAuthority` implements the same trusted
`ReplayHistoryAuthority` interface for the actual native consequence-boundary path.
Bootstrap uses the existing unpredictable fresh grant-ID prefix and genesis. Existing
grants outside that prefix refuse; neither an operator boolean nor a signature over
an arbitrary list can turn incomplete legacy rows into a complete source history.

Before compaction, the implementation locks the authority head and verifies the live
independent witness, complete contiguous raw chain, and any previously anchored exact
snapshot plus its complete raw suffix. Missing facts, inconsistent roots or frontiers,
duplicate identities and unavailable witnesses refuse. The source is this authority's
known-complete fresh history, never a claim inferred from surviving operational rows.

The snapshot is a sorted, duplicate-free exact set of `(native replay identity,
original full receipt digest)` pairs. SHA-256 commitments use separate versioned domains
for membership and compaction. The compaction commitment binds authority ID, fresh
prefix, consumed-through frontier, independent checkpoint sequence, previous root and
membership root. Coverage and witness sequences are separate: a compaction advances
the latter without consuming a new grant.

Native replay remains fenced after raw rows are deleted. For recovery, Gate supplies
its original FULL receipt retained in durable attempt custody. The authority validates
all receipt fields and its structural hash, then requires that EXACT receipt digest in
the independently anchored membership set. A new self-hashed receipt, a digest alone,
or a different action/native identity does not authenticate the original receipt.
Missing original receipts fail closed; no full-receipt reconstruction is claimed.
The older uncompressed authority ignores the backward-compatible optional lookup
argument and retains its original behavior.

## Locked cutover and reclamation

1. Lock and verify the complete current source and live witness.
2. Insert an immutable snapshot and move the head in one synchronous PostgreSQL
   transaction. Head triggers require exactly one versioned successor and preserve
   the fresh namespace; ordinary writers cannot mutate retained entries/snapshots.
3. Commit PostgreSQL, then synchronously advance the independent witness by exact
   compare-and-swap. No raw row is reclaimed on a missing/invalid/lost anchor answer.
4. Re-read the live witness and require the exact acknowledged snapshot frontier.
5. Through a separately provisioned compaction connection, call the operator-only
   prune function. It locks the current head and may delete only raw rows covered by
   its installed snapshot and snapshots superseded by that snapshot. It cannot
   remove the current snapshot, newer raw facts, truncate history or reset an epoch.
6. Commit reclamation synchronously. A subsequent restart validates the anchored
   snapshot and exact suffix before evaluating membership or non-membership.

The prune function is SECURITY DEFINER with installation-time search path and PUBLIC
execution revoked. Grant EXECUTE only to a trusted compactor role; runtime authority
credentials must not own tables, alter triggers, set roles to the owner, or execute
pruning. The implementation's `compact()` requires explicit `compaction_pool`, pins
both connections and witness callbacks, and checks the witness before invoking the
prune capability. The function itself does not authenticate the external filesystem:
external acknowledgement is a trusted-service obligation, enforced by this adapter.
An authority owner/superuser can disable guards and remains outside the model.

A crash before snapshot COMMIT rolls back the candidate. A crash/lost acknowledgement
after PostgreSQL COMMIT but before witness persistence preserves raw rows and leaves
an uncertain cross-store gap; it never means UNUSED. If the witness persisted the
snapshot but raw pruning did not commit, an explicit repeat verifies that installed
snapshot and reclaims only already-covered rows. A lost pruning acknowledgement may
leave reclamation complete; a repeat is idempotent. No automatic retry hides an unknown
provider or consume outcome.

## Bounded adversarial evidence

One disposable real-PostgreSQL fixture exercises raw reclamation, repeated compaction
and removal of superseded snapshots, replay refusal after reclamation, original full
receipt recovery on the actual native Gate path, rejection of a valid-looking forged
self-hashed receipt, and concurrent compaction/provider replay with zero extra invokes.

Injected failures cover snapshot write before COMMIT, lost snapshot COMMIT response,
anchor failure before persistence, lost anchor acknowledgement after persistence,
unavailable witness before pruning, failure after DELETE but before pruning COMMIT,
and lost pruning COMMIT acknowledgement. Every pre-anchor failure leaves raw rows
intact. Missing current snapshot after reclamation refuses both previously consumed
and genuinely new identities. Ordinary mutation and wrong-root pruning refuse.
Tests use real PostgreSQL plus real fsync filesystem persistence but privileged local
setup accounts; they do not establish production role/administrator separation.

## Remaining scope

Independent witness operation/retention, operator separation, transport authentication,
complete mediation and the original fresh-prefix issuance assumptions still apply.
Simultaneous rollback of authority and every independent witness remains unsupported.

This is exact-set compaction, not compact Merkle point/non-membership proofs. Snapshot
verification remains O(total consumed identities); total history remains bounded by
`max_entries` (10,000 default, 1,000,000 maximum). Compaction reduces raw row and index
retention; it does not remove that limit or claim an unbounded/constant-time service.
The full original receipt must remain in external attempt/evidence custody for
recovery. Legacy completeness cannot be created retroactively; verified legacy import,
namespace retirement and v1-to-v2 migration are not implemented. Neither #902 nor
#905 is closed by this local follow-up or by a developer's two local storage paths.
