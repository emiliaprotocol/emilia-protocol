# Hostile review of AE-CHALLENGE-06 and the private -07 candidate

Date: 2026-08-10

Internal record only. This is not independent review and is not an upload
artifact.

## Repaired protocol defects

1. Separate capacity and nonce operations allowed duplicate reservation or
   nonce burn. The candidate defines one owner-side transition.
2. A statefully issued challenge could deadlock at its own cap if its existing
   debit was counted again. The debit now transfers and only the positive
   incremental delta is added.
3. Replay scope omitted authenticated issuer identity. The security key is now
   the stable authenticated issuer identity plus nonce; `challenge_id` remains
   correlation only.
4. Replay, collision, and expiry precedence was ambiguous. The candidate now
   defines one total order, including expired open-body collisions.
5. Delimiter-joined replay tuples could collide. The finite model uses a
   structured tuple.
6. Recovery fencing was asserted while the reservation record omitted its
   owner token. The model now carries and checks that token.
7. The nonce wire syntax could not enforce the stated 128-bit floor. It is now
   at least 16 random octets encoded as 22 to 128 unpadded base64url
   characters.
8. The document called a refusal envelope an HTTP binding while leaving the
   corrected request and authenticated return path undefined. It is now an
   HTTP challenge-response carrier, and `present_as` profiles own the return
   path.
9. Problem Details `title` and `status` were treated as mandatory machine
   identifiers. The type URI is now primary; title can be localized and status
   can be omitted.
10. The 401/403 boundary and 409/429/503 mappings were incomplete. Their use is
    now constrained to the actual HTTP condition.
11. Retry-After conversion omitted the delay-seconds clock basis. It is now
    relative to response receipt and combined with `not_before` by taking the
    later instant.
12. An informative DMSC section used normative conformance language. It is now
    explicitly illustrative.
13. Unresolved carrier choices appeared as v1 interoperability questions. They
    are now future profiles outside the v1 core and HTTP carrier.
14. `critical` did not say whether it named nested fields. It now names only
    top-level core members; nested core objects are closed.
15. Policy-oracle, confidentiality, digest-dictionary, pre-owner resource, and
    final-action TOCTOU boundaries are now explicit.
16. The state namespace was changed in place during hardening. Issuer-scoped
    replay now uses v3, with a separate v2-to-v3 drain or atomic migration.
17. Concurrent stateful issuers could both pass a non-atomic last-slot check.
    Issuance now atomically joins every cap check and debit with replay-key and
    complete-body registration before exposure.
18. Remaining-only follow-ups could splice ambient evidence from a consumed
    challenge. The core now repeats all requirements unless an explicit
    authenticated continuation profile binds the predecessor evidence and
    evaluation state.
19. A digest could be compared without authenticating the action profile that
    gave it meaning, and a profile could omit a material effect field. The
    security binding is now the profile-and-digest pair and exact profiles must
    cover every material field.
20. Mutable audience aliases could change meaning between issuance and return.
    Namespace, comparison, alias version, and stable principal are now pinned
    for the challenge lifetime.
21. The HTTP carrier conflicted with HEAD and mapped every owner failure to
    503. HEAD is excluded, while 502, 503, and 504 retain their distinct HTTP
    meanings without carrying evidence details.
22. Production trusted a callback name plus caller-declared capability
    booleans. It now accepts only the owner object created by the supported
    factory, and a copied object cannot inherit that identity.
23. The old store interface could not represent reservation finalization,
    acknowledgement loss, or fenced recovery. The owner now returns an opaque
    generation-bound reservation, atomically finalizes terminal or follow-up
    state, and invalidates a stale worker after authorized recovery.
24. A worker could ask the owner to finalize a narrowed or substituted
    follow-up. The owner now compares the action, action profile, policy,
    complete requirement set, audience, and presentation method before it
    accepts follow-up state.
25. Owner expiry relied on worker time and the generated fixtures used strings
    that did not satisfy the canonical nonce grammar. PostgreSQL transaction
    time now decides owner expiry and the fixtures generate canonical random-
    byte encodings.
26. The lifecycle model represented durability but not the concrete
    authoritative-owner boundary. It now varies that property explicitly and
    the runtime bridge refuses an unbranded production store.
27. Issuance used the challenge audience as though it were an authenticated
    presenter, while claim used the actual presenter. A scoped capacity policy
    could therefore lock one bucket set while updating another. Owner record v2
    now stores the authenticated presenter, issuance debit, and bucket limits,
    locks their union, and preserves the original scope through finalization.
28. Production evidence freshness used caller-supplied `as_of`. A caller could
    move evaluation backward and freshen stale evidence. The successful owner
    claim now returns authoritative transaction time, and production policy
    replay uses that time instead.
29. The runtime emitted relative evidence and presentation identifiers while
    the draft required absolute URIs. The reference now emits exact absolute
    identifiers and keeps the internal policy token in `requirement_id`.
30. The public owner accepted only a version, identifier, and nonce before
    allocating state. It now rejects malformed digests, relative security
    identifiers, duplicate requirements, unknown nested members, bad retry
    windows, non-canonical data, and over-limit bodies before capacity changes.
31. The pre-owner budget did not explicitly cover an initial evidence
    evaluation used to decide whether to issue a challenge. The text now does,
    and requires a known-exhausted replay-state bound to win before optional
    native verification starts.
32. Model-to-Matter constructed native verifiers around caller time before the
    owner claim. A caller could therefore keep native evidence current while
    the generic replay record claimed owner time. Production verifier factories
    now run only after the owner returns its authoritative evaluation instant.
33. Capacity arithmetic read inherited JavaScript object properties. A valid
    constructor-pinned bucket named `constructor` or `toString` could therefore
    fail or corrupt arithmetic. Every vector lookup now uses own properties,
    and malformed non-record vectors from storage fail closed.
34. The object-level reference helpers cannot detect duplicate JSON members
    after a generic framework parser has collapsed them. The draft now states
    the raw-carrier boundary explicitly: bounded parsing and duplicate-member
    rejection happen before those helpers. This is a deployment obligation,
    not a property claimed by the object-level tests.
35. The PostgreSQL adapter compared database row order with JavaScript locale
    order. A collation difference could fail a valid capacity transaction. The
    adapter now uses deterministic bytewise client ordering for writes and
    validates locked rows as an exact key-to-limit set, independent of return
    order.
36. Caller-selected follow-up state could be rejected only after the owner had
    claimed the nonce, and a malformed follow-up could strand its reservation.
    Production caller nonces are now refused before claim. Follow-up
    construction failure terminalizes the existing reservation without issuing
    replacement state; an uncertain finalization remains unavailable.
37. A valid but insufficient presentation could force an unbounded sequence of
    fresh challenges. The core now requires a finite reissue budget bound to the
    issuer, presenter or audience, exact action, and policy; a fresh nonce does
    not reset it. A focused test exercises an action-scoped budget.
38. `retry_timing` was correctly non-critical but could still be mistaken for
    enforceable protocol state. An issuer relying on enforced pacing must now
    enforce it through carrier overload handling, admission control, rate
    limiting, or refusal.

## Runtime defects caught and bounded

- Generated standalone JavaScript was stale while Vitest redirected imports to
  TypeScript. The standalone runtimes are regenerated and a direct standalone
  synchronization gate is required.
- Caller-supplied production nonces are refused; production nonces are minted
  internally.
- Effective `NODE_ENV=production` now applies even when the caller omits the
  explicit option.
- Production evaluation requires a challenge audience and separately supplied
  authenticated presenter. The deprecated audience assertion is insufficient.
- Per-call action digesters were removed from the security decision.
- Multiple advertised presentation profiles no longer fail merely because the
  supported profile is not the sole array member.
- A backend timeout after a possibly committed claim returns typed
  unavailability with `state_changed: unknown`, invokes no evidence verifier,
  and emits no follow-up.
- Follow-ups refuse reuse of the prior identifier or a changed action profile,
  and recheck the current action after evidence evaluation before registration.

## Deliberately unclaimed and remaining review boundaries

The repaired stateful reference is same-team executable evidence. Its
PostgreSQL adapter has transaction-contract tests, not a live database
isolation audit or a production role and privilege review. The finite
claim-and-capacity harness checks 114 small scenarios and unsafe mutations; it
does not claim exhaustive verification, arbitrary-shard conservation, crash
refinement, or database correctness. The older lifecycle checker is also a
bounded abstraction, and its owner field is tied to runtime tests rather than
trusted self-declaration.

No independent implementation, external interoperability result, deployed
capacity or reissue policy, expiry collector, authenticated alias resolver,
safe quota-transfer system, or pre-owner abuse-control deployment is claimed. The
reference implements the stateful path. The self-describing alternative is a
protocol option, not a reference-runtime claim.

No known local build, package, state-machine, or publication-format blocker
remains in the frozen bytes. Independent security review and implementation
reproduction would materially strengthen the evidence and should precede any
claim of operational maturity. The candidate remains unpublished only because
filing requires an explicit decision, not because the earlier callback and
formal-claim defects are still open.
