# Replay-history recovery boundary (experimental)

Follow-on implementation: the opt-in native provider path, durable authority and
separate checkpoint witness are documented in
`docs/protocol/replay-history-durability-profile-v1.md`. The files in THIS
experimental directory remain standalone; the historical integration plan below
is superseded by that document where it describes completed implementation.

A bounded executable implementation step for issues #902 and #905. This module
is not exported by Gate and is not connected to a provider path. Neither issue
is resolved by this component. Run the focused corpus with:

    node --test packages/gate/experimental/replay-history/recovery.test.mjs

`evaluateReplayRecovery` commits to a sorted, exact, duplicate-free full set of
native consumed identities. It checks namespace/epoch, complete-set root,
frontier, previous checkpoint binding and exact equality with the independently
read latest anchor head. It returns COMPLETE or UNCERTAIN; COMPLETE ABSENT is
never a dispatch permit. It copies inputs before asynchronous reads.

`consumeRecoveredIdentity` calls the live authority only after COMPLETE ABSENT,
passes the expected current head for atomic compare-and-consume, and requires a
receipt bound to the native identity, exact action, namespace/epoch, predecessor
and next sequence. Conflicts refuse; malformed receipts and lost acknowledgement
remain uncertain. There is no retry or refund. Concurrent tests demonstrate the
required atomic service contract with a test double, not a durable service.

## Trusted adapters still required

The relying party must inject `readVerifiedLatest`. This is a trusted verifier,
not a presenter-supplied object loader. It must authenticate the external service
and its newest receipt under pinned keys; validate previous-checkpoint continuity,
coverage, freshness and epoch continuity; reject gaps, equivocation and unreadable
anchors; and run outside the operational store's deletion/restore authority.
The module compares commitments but does not implement signature verification,
transparency consistency proofs, freshness challenges, or an anchor service.
An attacker-controlled callback defeats its assumptions. Tests use test doubles.

The injected `atomicConsume` must be a live durable linearizable replay authority.
It must atomically compare the expected head, burn the exact native replay identity
and exact action, advance sequence, and emit the receipt. It cannot be implemented
as a lookup followed by an insert or a caller-provided success flag. Receipt field
checks here detect malformed/substituted responses; they cannot manufacture the
service's durability or atomicity. A checkpoint timestamp does not prove that a
consume preceded dispatch. Synchronous anchoring before entry is a separate profile.

## Integration work and exclusions

Implement and independently operate the authenticated anchor reader and atomic
consume authority; persist receipts; integrate the wrapper before existing local
reservation and provider entry on a covered executor path. Local failure after
external consume must leave the native identity burned. Bind the existing native
replay derivation rather than accepting presenter-created identities. Test that
provider invocation is zero on every refusal and uncertain outcome. These steps
are not implemented here; the wrapper itself does not evaluate authorization.

No compaction writer or garbage collector is implemented. Full-set reconstruction
is deliberately simple and not a compact membership proof. Checkpoints commit to
a previous digest, but chain correctness is the trusted reader's responsibility.
Old epochs cannot silently rotate into a new expected namespace; retirement and
draining need deployment policy. Resource limits and production transport hardening
remain deployment work.

If the primary store and all purportedly independent anchors are restored together
to the same older state, the consumed history is indistinguishable from never-used
history. This violates the external durability assumption and cannot be detected
from these surviving bytes. No same-database mirror, local boolean or hash fixes
that information loss. Anchor freshness after the read likewise requires atomic
head comparison by the live consumption authority; this wrapper does not reuse a
recovery decision as a timeless admission token.

## Concrete native provider-path integration plan

Inspection at base c7408b6e7923095cd359ef976666ce21ba178177:

- `packages/gate/src/consequence-boundary.ts` derives the native replay key from
  the verified handoff, constructs the action/operation binding, durably reserves
  an attempt, and reserves operation/native/action fences. It then revalidates
  native status, confirms INVOKING custody, revalidates status again and invokes
  the provider. The derived native identity is the integration input, not an
  identity supplied separately by a presenter.
- `packages/gate/src/aeb-consumption-store.ts` implements `reserve` with one
  PostgreSQL transaction inserting the operation and all replay keys. This closes
  concurrent local races, but its rows and local witness checkpoint can be restored
  together. It is not the missing independent replay-history authority.

The missing component is a relying-party-pinned, independently administered live
replay authority, with durable exact-identity membership, atomic head comparison
and consume, retained epoch history, authenticated latest-head reads, validated
continuity, and receipt persistence. Its restore/deletion powers must be separate
from those of Gate's operational PostgreSQL. Its monotonic state must survive the
primary rollback scenario in an independently operated deployment test. An
Ed25519 signature on a caller-supplied head or timestamp would not supply that
property. No cryptographic reader is added without that service protocol.

Implement integration only after that authority exists:

1. Add an explicit optional strong-profile configuration to the native boundary;
   preserve existing default semantics and scope their durability claim honestly.
   Selecting the profile with missing/invalid adapters must refuse configuration,
   never silently downgrade. Pin service identity, namespace/epoch and native
   authority mapping at boundary construction.
2. After verified handoff and exact local authorization, use the verified native
   replay identity and exact action digest to request live atomic durable consume.
   On backup recovery require full anchored reconstruction first. Compare the
   recovered head atomically at the authority so a concurrently advanced frontier
   cannot use stale ABSENT evidence. The service must fence the same identity
   across concurrent Gate instances and scope aliases.
3. Persist the service receipt in the durable attempt record before local fences
   and provider entry. If local reservation fails after consume, retain the burn;
   pre-entry cleanup may release local operational/action fences but cannot refund
   the external native identity. Unknown service outcome refuses entry and requires
   authenticated lookup/reconciliation, never blind repeat consume or dispatch.
4. Preserve INVOKING ownership confirmation and final native-status refresh before
   provider invocation. A long external service call may stale authorization; the
   existing final refresh must still run after every potentially blocking step.
5. Reconciliation and terminal FAILED handling retain the external burn. Compaction
   may delete raw history only after verified independently anchored reconstruction
   is complete; absence of checkpoint/continuity makes the strong profile uncertain.

Focused integration acceptance must use the actual native-boundary provider spy:
zero calls for uncertain/unavailable/malformed external state, stale authority,
local failure after consume, lost service acknowledgement, primary rollback and
namespace discontinuity; exactly one call across concurrent same-identity requests;
no refund on FAILED; and a valid fresh identity still executes. Run these against
an actual separate authority deployment as well as unit doubles. Simultaneous
rollback of every independent anchor is an explicit unsupported durability failure,
not an input corpus capable of proving detection from indistinguishable bytes.

These steps are a concrete plan, not implemented wiring. A standalone generic
consumption-store decorator is unsafe here: operation, action and native fences
have different release lifecycles, and burning all of them as native authority
would change existing semantics. The current prototype remains experimental.
