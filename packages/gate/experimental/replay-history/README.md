# Replay-history recovery boundary (experimental)

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
