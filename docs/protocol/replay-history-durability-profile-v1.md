# Independently retained native replay history, opt-in profile

This private working change addresses #902/#905 on the native consequence-boundary
provider path. It implements an atomic live replay authority and a separately
retained monotonic checkpoint witness. It does not establish independent operation
by running two stores on one developer machine. No public guarantee changes for
unconfigured paths. Default legacy native IDs retain existing behavior; the newly
reserved fresh-profile ID form requires the profile and cannot silently downgrade.

## Implemented path and ordering

`createNativeConsequenceBoundary` accepts optional
`native_authorization.replay_history: ReplayHistoryAuthority`. A supplied malformed
profile refuses construction. Authority ID and consume callback pin at construction
and the authority ID enters the authorization-program digest. Authenticated
reconciliation additionally requires its stored receipt, configured authority ID,
exact historically verified native grant ID/action, and matching live authority
`lookup`. Lookup runs only after custody recovery authorization and historical
binding validation. Missing receipts, hashes absent from live authority history,
unavailable history and profile removal refuse recovery. A receipt hash alone is
structural integrity, never authenticity.

The native handoff and exact action must verify and local policy must permit
before the authority is called. The request uses the VERIFIED native replay
identity and action digest, never a separately supplied presenter identity.
`consume` must return the exact versioned, hash-bound receipt or `null` (already
consumed). Exceptions, invalid receipts and unavailable history refuse provider
entry with `native_replay_history_uncertain`; retry remains prohibited.

Accepted external consumption precedes attempt/local fence reservation. The receipt
is part of the native attempt binding sent to the configured durable attempt store
and provider context. Local failure, lost acknowledgement, expiry/revocation after
consume and terminal provider FAILED never refund the external native burn.
Existing local operation/action/native custody, INVOKING owner confirmation,
provider outcome verification, and final native-status refresh remain in force.

## Three durability domains

1. Gate operational PostgreSQL: reconstructable local fences and attempt evidence.
2. Replay-authority PostgreSQL: exact consumed membership and complete retained
   hash-chained consumption log; row lock serializes the stream.
3. Checkpoint witness: independently retained append-only sequence/root checkpoints
   outside the rollback/deletion powers of both databases.

`createPostgresReplayHistoryAuthority` implements the live authority using an
operator-supplied PostgreSQL pool. It explicitly requires a checkpoint store.
One transaction locks its provisioned head, compares the live witness's head,
reconstructs and verifies every retained fact, checks exact membership, appends a
new burn and advances its hash-chain root. `synchronous_commit=on` is required.
Missing head, coverage gaps, root/chain mismatch, duplicate native identities,
unsafe numeric frontiers and bounded capacity exhaustion fail closed.

Only after acknowledged PostgreSQL COMMIT does it synchronously advance the
separate checkpoint witness by exact compare-and-swap. It returns no accepted
receipt until the witness acknowledges the exact new sequence/root. A crash or
lost acknowledgement between stores may sacrifice availability: the identity is
burned and a later head mismatch refuses further admission. Recovery requires
operator-authorized reconstruction; there is no automatic head reset or refund.
This conservative profile explicitly anchors before provider entry. Its checkpoint
is not substituted for the atomic consume transition.

`createFileReplayHistoryCheckpoint` is a concrete witness adapter for an
independently retained filesystem. It locks live reads and CAS, appends exclusively
with `link` (never overwrites), fsyncs file bytes and the directory, and checks
contiguous sequence files on every read. Missing/corrupt files, a missing directory,
compare-exchange conflicts and stale locks refuse. Stale locks require operator
investigation; the implementation never auto-breaks them. `provision...` is an
explicit one-time operation that refuses existing directories. Neither adapter
implements deletion, compaction, epoch reset or automatic bootstrap. PostgreSQL
triggers reject entry UPDATE/DELETE/TRUNCATE, head DELETE/TRUNCATE, and head updates
that do not advance exactly one retained successor or that change the fresh-prefix
binding. Ordinary writers cannot invalidate history after the chain read and race
provider entry. Service credentials must lack table ownership, ALTER/TRIGGER and
superuser powers. Authority administrators who disable retention triggers remain
trusted/excluded. The filesystem adapter supplies an append-only API, not WORM
retention against its owner/admin.

## Deployment and trust requirements

A second pool/schema/database name on one administrative cluster is NOT an
independent durability domain. The pool must authenticate a separately administered
PostgreSQL authority; remote pools need pinned TLS/server authentication and
least-privilege service credentials. The checkpoint filesystem must be retained
outside both databases' rollback and administrative control. This can be a separate
retention service mounted with appropriate durability/locking semantics; the
filesystem adapter requires coherent exclusive directory creation, exclusive link
and fsync support. Do not assume those semantics on an arbitrary network mount.
Production retention/WORM policy, operator separation, backups and recovery drills
remain deployment requirements. They cannot be inferred from configuration labels.

The pool and checkpoint store are trusted service adapters, not untrusted caller
claims. A callback returning fabricated success defeats the trust model. The
concrete adapters use live serialized state and make no timestamp/freshness claim
based on a caller-provided boolean or clock. The receipt digest provides binding,
not authenticity against a malicious authority; authority identity is pinned by
the trusted authenticated adapter/channel. There is no SCITT service, external
signature receipt format, or independent operator attestation in this change.

### Enforced fresh-only cutover

This profile cannot enable an empty ledger for arbitrary pre-existing native grants.
`replayHistoryBootstrap(authorityId)` generates an unpredictable 256-bit native
`authorization_id` prefix with CSPRNG output and accepts no caller-specified prefix.
It returns one-time INSERT parameters, `fresh_authorization_prefix` and `genesis`.
The prefix persists in the head and binds into genesis; monotone-head rules forbid
changing it. The live authority refuses native grant IDs outside that prefix before
interpreting membership or appending consumption.

The native issuer must issue genuinely new stable grant IDs under the new prefix.
The trusted gateway must verify and preserve the issuer's actual stable native ID;
it must never relabel an old grant by prepending a prefix. That is the existing
native-verification trust boundary, not a caller-supplied freshness flag. Prior IDs
cannot already match an undisclosed random 256-bit prefix except with negligible
collision probability. A regression executes an old grant before bootstrap, loses
operational custody, enables the new profile, and proves the old ID cannot invoke.

Gate boundaries without the profile refuse the reserved `ep-fresh-<64 hex>:` ID
form. This prevents execution during the bootstrap-to-activation window and after
profile removal. All covered Gate binaries must be upgraded before publishing the
new prefix or issuing its grants; old binaries and unmediated provider paths are
outside complete mediation. A separate regression proves an unconfigured boundary
cannot execute a newly prefixed grant before profile activation.

Native systems unable to issue fresh IDs in this format cannot use this fresh-only
profile. Verified complete legacy import is not implemented; bootstrap is not an
import. Supply the returned genesis to one-time witness provisioning. A witness for
a different prefix cannot validate the authority head.

The stream is a fixed fresh native-authority subset deployment. Namespace/epoch
rotation requires draining or preserving the old namespace mapping and native
identity aliases before retirement; this code does not authorize a reset or
provide a rotation coordinator. The same authority ID must remain bound across
Gate restarts and operational restores. Removing the opt-in profile removes its
protection and must be controlled by deployment policy. Default paths do not gain
this guarantee.

If all independent stores and witnesses can be restored together to the same older
state, never-consumed and erased-consumed histories are indistinguishable. That
failure violates the independence/retention assumption and is explicitly unsupported.
No local hash, extra schema or signature can recover the erased information.

The implementation deliberately retains full exact history, bounded by 10,000
entries by default (maximum configurable 1,000,000). It does not implement compacted
membership/non-membership proofs or reclamation. Capacity exhaustion denies further
admission rather than deleting replay facts. Safe production compaction and epoch
retirement remain open acceptance work for #902, not implicitly complete.

## Focused verification

Run existing native/consequence-boundary and witness tests:

    node --test packages/gate/consequence-boundary.test.js packages/gate/replay-history-checkpoint.test.js

The PostgreSQL case is gated by explicit `EP_REPLAY_TEST_PGHOST` and
`EP_REPLAY_TEST_PGPORT`. Use only a disposable cluster: it creates/drops random test
schemas and simulates destructive authority rollback inside those schemas. Local
operational custody in that case uses the existing suite's deterministic doubles;
real PostgreSQL backs the authoritative burn and a separate real fsync filesystem
backs its witness. Provider callbacks are spies on the actual native-boundary path.

The focused corpus covers fresh-only cutover of an already executed old grant,
concurrent same-identity attempts, valid new identity,
complete operational loss, local failure after external consume, lost acknowledgement,
stale native status during consume, FAILED outcome retaining the burn, missing
membership facts, root tampering, authority-DB rollback with witness current,
witness failure after authority COMMIT, synchronized entry mutation after history
read, authenticated receipt recovery and lookup at full capacity without admitting
new burns. Every refusal case checks zero added
provider invocations. Separate witness cases cover restart/new handles, CAS races,
missing history, corruption, no reset and stale-lock refusal.

A disposable PostgreSQL stop/restart check also confirmed that an acknowledged
burn remained consumed with the filesystem checkpoint retained. This is local crash
persistence evidence, not independent deployment or power-loss/replication evidence.

## Issue acceptance still open

#902: verified legacy-history import, safe compaction/reclamation, bounded proof format and governed namespace
rotation/draining are not implemented; the profile instead forbids reclamation and
fails closed at capacity. Full model-to-runtime conformance is not claimed.

#905: the concrete live authority and checkpoint boundary are implemented and
integrated on the opt-in native provider path. Independent operator deployment,
retention/administrative separation, remote authentication configuration and
external recovery/rollback drills remain unperformed. Local tests do not close those
external acceptance criteria. Composed AEC paths and all adapters are not implicitly
covered by the native profile. Neither issue should be closed solely from this patch.
