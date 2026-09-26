<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to `@emilia-protocol/gate` are documented here.
This package follows [Semantic Versioning](https://semver.org/).

## 0.28.0 (2026-09-25)

### Security

- Stripe refunds now require a bounded `operation_id` in the approved action.
  The caller must assign it from a durable business record and retain it across
  retries; Gate checks its shape and action binding, not its provenance. The
  adapter derives the same Stripe idempotency key from that ID even when a
  fresh receipt is presented, while distinct partial refunds retain distinct
  keys. Older callers and receipts without the ID fail closed until migrated.
- Mock-provider tests close the lost-response/fresh-receipt duplicate-effect
  case while Stripe still retains the key. The adapter may make a second
  provider call on retry, and Stripe's key cache is finite. An uncertain refund
  must not be retried blindly or given a new ID; reconcile it against
  authenticated provider records first. This release does not add durable
  refund recovery or establish live Stripe/PostgreSQL behavior.

## 0.27.0 (2026-09-25)

### Security

- Both consequence boundaries now hold a durable same-action fence:
  `createNativeConsequenceBoundary()` and the composed
  `createConsequenceBoundary()`. Each attempt reserves a holder row that
  carries a fence keyed by relying party, provider coordinates as configured
  (tenant, provider, provider account, environment), and canonical action
  digest. While an attempt for that action is reserved, invoking, or
  indeterminate, a new attempt is refused before provider entry as
  `native_action_in_flight`, even with fresh authority and a fresh operation
  ID. Before this change the composed boundary had no fence, so fresh evidence
  presented while a first attempt was `INDETERMINATE` reached the provider a
  second time. After an authenticated EXECUTED result the fence stays closed
  (`native_action_already_executed`). Only a FAILED result the boundary
  accepts, direct or reconciled (affirmed for the attempt by
  `provider_outcomes.verify`, which both boundaries now require; see the
  terminal-evidence entry below), or a pre-entry stop proven by
  the explicit not-entered marker in the boundary's own durable attempt
  record opens it. On the composed boundary its
  existing refusals take precedence over the fence refusal. Both boundaries
  derive the same fence key from the relying party ID, so they fence each
  other when they share a store. New exports:
  `nativeConsequenceBoundaryActionFenceKey()`,
  `nativeConsequenceBoundaryActionFenceHolderKey()` (which takes `provider`,
  `boundary_id`, and `attempt_id`),
  `nativeConsequenceBoundaryAttemptReservationKeys()` (which also takes
  `boundary_id`), and `consequenceBoundaryActionFenceHolderKey()` (which
  takes `{ reservation_key, boundary_id, attempt_id }`).
- An attempt that stopped before provider entry (a crash while `RESERVED`, a
  lost acknowledgement on the move to `INVOKING`, a store error during a
  pre-entry release, or a crash after the fence holder was reserved but before
  the attempt was recorded) previously held the fence forever, refusing every
  later attempt at that action. The native boundary now writes the attempt
  record, and calls `create_id`, before any reservation, and both boundaries
  write it before the fence holder, so the last case can no longer arise.
  Pre-entry recovery is a separate mode of `reconcile()`, `mode:
  'pre_entry'`; terminal reconciliation is `mode: 'terminal'`, the default,
  and returns `INDETERMINATE` with `pre_entry_recovery_required` for a record
  that never reached `INVOKING`. Neither mode falls through into the other.
  Pre-entry recovery takes a `recovery_authorization` that the attempt
  store's `recover()` accepts for the attempt and the provider's answer: a
  "not found" lookup result as FAILED (presented as evidence of kind
  `pre_entry_lookup`, and affirmed by `provider_outcomes.verify` called with
  `purpose: 'pre_entry_lookup'`), or INDETERMINATE when the provider has no
  lookup. Recovery treats the attempt
  as not entered only when its own `RESERVED` to `RELEASED` transition, which
  writes the not-entered marker, is confirmed by a durable read (on a
  composed attempt store without `state()`, answered with exactly `true`),
  or when the record is already `RELEASED` with that marker. That transition
  is the
  linearization point: the live run's move to `INVOKING` then fails, and the
  run does not call the provider and releases whatever it reserved
  (`attempt_released_by_recovery`); a composed run whose attempt store has
  no `state()` cannot tell that transition from its own lost write, so it
  holds everything as `attempt_start_unconfirmed` instead. If the
  record is already `INVOKING` or later, recovery returns `INDETERMINATE`
  with `recovery_lost_to_live_attempt`, releases nothing, and never uses its
  lookup as a terminal outcome. Only after a confirmed not-entered transition
  does Gate release the attempt's reservations, confirm each release, and
  return `REFUSED` with `attempt_never_entered_provider`;
  an unconfirmed release stays `INDETERMINATE`
  (`native_pre_entry_release_unconfirmed`). A claim of EXECUTED is refused as
  `reconciliation_outcome_conflict` and releases nothing. On the composed
  boundary recovery releases only the fence holder and never touches the
  evaluation reservation, which a live run hands back itself and which stays
  reserved after a crash, so a retry needs a fresh evaluation. Without
  `attempts.store.state()`, only recovery's own transition answered with
  exactly `true` proves the stop, and a stop or lost race that recovery
  cannot prove that way keeps the action fenced.
- Both boundaries release or commit the fence holder and every other
  reservation of an attempt only after the attempt record's terminal or
  not-entered transition has succeeded and been confirmed. Terminal
  reconciliation freezes an `INVOKING` record as `INDETERMINATE` first and
  writes the terminal record before it consumes reservations or opens the
  fence; if the terminal record cannot be written, everything stays held.
  In 0.26.0 the composed `reconcile()` committed the evaluation reservation
  before its terminal attempt transition and without freezing an `INVOKING`
  record.
- A lost acknowledgement no longer releases anything on its own. If the
  move from `RESERVED` to `INVOKING` throws or answers anything but `true`,
  the run reads the durable record. `INVOKING` for this attempt means the
  write landed, and the run proceeds as the record's owner. `RESERVED` is
  first closed as not entered through the same atomic transition, then
  released (`attempt_start_conflict`). `RELEASED` with the not-entered marker
  for this attempt means a pre-entry recovery linearized first, and the run
  hands back what it holds (`attempt_released_by_recovery`). Anything else,
  including a `RELEASED` record without the marker, keeps everything held as
  `INDETERMINATE` with `attempt_start_unconfirmed`. A composed attempt store
  without `state()` cannot be read, so the run sends no not-entered write,
  holds everything, and returns `INDETERMINATE` with
  `attempt_start_unconfirmed` without calling the provider. A pre-entry stop that
  cannot confirm its own not-entered transition returns `INDETERMINATE` with
  `native_pre_entry_release_unconfirmed` on the native boundary and
  `attempt_release_unconfirmed` on the composed boundary. A native stop
  whose first reservation was refused holds no row, so it returns `REFUSED`
  with that refusal's reason even when the transition was not confirmed.
  In 0.26.0 the composed boundary released the
  evaluation reservation after such an error while the durable record could
  say `INVOKING`.
- A store answer counts as success only when it is exactly `true` or a
  durable read confirms the write. Where a store has a durable read, Gate
  decides attempt transitions and consumption-store commits, releases, and
  closes by that read alone; a recovery claim needs exactly `true`. In
  0.26.0 the composed boundary accepted any truthy answer, so a
  store that answered `{ ok: false }` to the move to
  `INVOKING` let the provider be called while the record stayed `RESERVED`.
  On the native boundary, a reserve call that throws, or answers anything
  other than exactly `true` or `'RESERVED'` or a defined conflict (`false`,
  `'CONSUMPTION_CONFLICT'`, or `'NATIVE_REPLAY_CONFLICT'`), has an unknown
  effect: the run reads that row, and unless the read shows `CONSUMED` or
  `RELEASED_NOT_ENTERED` it closes the attempt as not entered, hands its
  rows back, and returns `INDETERMINATE` with
  `consumption_reservation_unconfirmed`, never a clean refusal.
- The composed boundary's evaluation reservation is keyed by the evaluation,
  which successive attempts can present. Gate now commits it for an attempt
  only while that attempt's own fence holder is still held, which marks it
  as the reservation's owner (otherwise `evaluation_reservation_not_owned`
  unless it is already consumed), and pre-entry recovery never touches it, so
  recovering one attempt can no longer commit a later attempt's live
  reservation for the same evaluation.
  When the release of that reservation fails before provider entry, the run
  now returns `INDETERMINATE` with `evaluation_release_unconfirmed` rather
  than a clean refusal.
- Recovery claims are bound to one attempt. Before `authorizeRecoveryClaim`
  runs, `claimReservation()` refuses a claim made without a scope
  (`recovery_claim_scope_required`), a scoped claim whose key is not the row
  that its `scope` names for that attempt (new exports
  `consequenceBoundaryRecoveryClaimKey()` and
  `consequenceBoundaryRecoveryClaimMarkerKey()`), and a claim on the
  composed evaluation reservation, which several attempts share, unless the
  scope's attempt still holds its fence-holder row.
  The scope names the boundary kind (`scope.boundary`, `'native'` or
  `'composed'`) and the boundary (`scope.boundaryId`, the boundary's
  required `boundary_id`) as well as the attempt ID. A scope derives only
  the rows of its own boundary kind and boundary ID, every attempt-keyed
  reservation includes both, and `authorizeRecoveryClaim` receives
  `attemptIdentity` (`native:<boundaryId>:<attemptId>` or
  `composed:<boundaryId>:<attemptId>`, from the new export
  `consequenceBoundaryRecoveryAttemptIdentity()`), so two boundaries that
  share one store, of different kinds or of the same kind, can no longer
  claim each other's rows even when their attempt IDs are identical. The
  action fence key does not include the boundary ID, so every boundary at
  one provider still fences the same action. `scope.operationId` is
  caller-asserted: the store does not check it against the claimed row, and
  an authorizer must not rely on it. A malformed scope is a
  refusal (`recovery_claim_scope_invalid`), not a thrown error. The
  PostgreSQL store's new `claimReservationResult()` returns the refusal
  reason (`AebRecoveryClaimRefusal`): `recovery_claim_scope_required`,
  `recovery_claim_scope_invalid`, `recovery_claim_key_mismatch`,
  `recovery_claim_owner_marker_absent`, and `recovery_claim_already_owned`
  are decided before the authorizer runs, then `recovery_claim_unauthorized`
  and `recovery_claim_row_not_reserved`; a database error still rejects.
  A credential bound to one attempt can therefore no longer claim another
  attempt's live holder.
- A call now releases or closes only reservations it created. The native
  boundary writes three reservations per attempt (operation identity, native
  authority, action-fence holder), each keyed by its `boundary_id` and
  attempt ID, which no other attempt can produce; the composed boundary
  keys its fence holder the
  same way. In 0.26.0, when a native reserve write failed, the error path
  released the operation reservation for the caller-supplied operation ID
  without proof that this call had created it. With a store that fences
  release per store instance, such as the PostgreSQL store that can now back
  the native boundary, that release could delete another in-flight attempt's
  reservation and replay fence in the same process, leaving that action
  locked and that attempt's grant admissible for a second action. A failed
  reserve now marks the attempt `RELEASED`, releases only this attempt's rows,
  and returns `INDETERMINATE` `consumption_reservation_unconfirmed`, because
  the failed write may still land, or `INDETERMINATE`
  `native_pre_entry_release_unconfirmed` when a release cannot be confirmed.
- One grant accepted under two pinned `system` or `profile` labels, or under
  two spellings of one issuer that declare the same namespace, is now spent
  once. Gate reserves the label-free `replay_identity_key` that
  `@emilia-protocol/verify` derives locally from the pinned authority
  namespace (the issuer by default) and the native authorization ID. Beside
  it, it reserves the 4.1.0 `replay_key` for every `system` and `profile`
  label, with its issuer spelling, that the pin set accepts under the
  grant's authority namespace, not only for the presented label, so a grant
  that 0.26.0 consumed under one label is refused under any other label
  still pinned in that namespace. The provider idempotency key is derived
  from the identity and no longer depends on the labels or, when the pin
  declares an `authority_namespace`, on the issuer string.
- `reconcile()` never reconciles an attempt that did not enter the provider to
  EXECUTED or FAILED: terminal mode returns `INDETERMINATE` with
  `pre_entry_recovery_required`, and pre-entry mode can only release it as
  not entered (`attempt_never_entered_provider`). It refuses an outcome that
  conflicts with an existing terminal record as
  `reconciliation_outcome_conflict` without touching any reservation.
  Pre-entry refusals release reservations only after the attempt itself is
  durably `RELEASED`.
- Hostile in-process input is refused instead of throwing: a Proxy anywhere in
  `run()` or `reconcile()` input, getters, extra keys, and an own `__proto__`
  member. On the composed boundary this now also covers throwing getters on
  `artifacts`, `current_statuses`, `additional_replay_keys`, and `outcome`,
  and revoked Proxies. A synchronous attempt store that returns plain
  booleans is supported, not refused: Gate awaits its answers and applies
  the same rules. An unexpected exception is returned as `boundary_internal_error`
  and never thrown: from `run()` it is `REFUSED` before an attempt exists and
  otherwise `INDETERMINATE`, with `invoked: true` once the provider may have
  been entered, and every reservation stays held; from `reconcile()` it is
  `REFUSED`. In 0.26.0 the composed boundary threw on these inputs, and a
  synchronous attempt store made `run()` throw after the provider call.
  Attempt-store answers are copied once as plain data. A
  `pins.relying_party_id` outside the Gate identifier grammar is refused at
  construction, and durable keys are derived before `local_authorize` runs, so
  an unkeyable binding is a refusal (`native_consequence_binding_invalid`)
  with no side effect.

- "Not entered" is now recorded, never inferred. Every not-entered
  transition, a run's own pre-entry stop and pre-entry recovery's
  linearizing transition, writes the move to `RELEASED` with the evidence
  `{ kind: 'not_entered', attempt_id }` (new export
  `CONSEQUENCE_BOUNDARY_NOT_ENTERED`, type
  `ConsequenceBoundaryNotEnteredMarker`), and pre-entry recovery and the
  `pre_entry_recovery_required` routing of terminal reconciliation rely
  only on that marker. A `RELEASED` or `COMMITTED` record that carries
  neither the marker nor provider evidence, including one from an attempt
  store whose `state()` drops the stored evidence, is unproven: both
  reconciliation modes return `INDETERMINATE` with `attempt_record_unproven`
  and release nothing, so an attempt that entered the provider can never be
  recovered as a pre-entry stop and its one-time authority released
  unconsumed. An attempt store declares `notEnteredMarker: true` when it
  persists that evidence with the transition and returns it from `state()`.
- Terminal evidence is verified for the attempt, the purpose of the check,
  and the kind of evidence presented. `provider_outcomes.verify` now
  receives the attempt's `provider_idempotency_key` and a `purpose`, and
  the only answer Gate accepts is `{ verified: true, purpose, attempt_id,
  provider_idempotency_key }` restating what it was asked
  (`ConsequenceBoundaryProviderOutcomeAffirmation`). Any other answer,
  including a bare `true`, means "not verified" (`INDETERMINATE`
  `provider_outcome_authentication_failed`). The composed
  `createConsequenceBoundary()` now requires `provider_outcomes` as the
  native boundary does, and throws at construction without it
  (`consequence_boundary_configuration_invalid:
  provider_outcome_verifier_required`). On both boundaries an attempt
  that reached `INVOKING` closes as EXECUTED or FAILED only on an
  affirmation of `provider_outcome` bound to that attempt and its provider
  idempotency key, including the result of the run's own provider call, so
  a provider adapter's unverified FAILED, such as a timeout mapped to
  FAILED, never releases the fence. Evidence presented to `reconcile()`
  carries its kind in Gate's input (`evidence_kind`: `'provider_outcome'`
  or `'pre_entry_lookup'`): terminal reconciliation refuses a
  `pre_entry_lookup` and pre-entry recovery refuses a `provider_outcome`
  before the verifier runs (`evidence_kind_mismatch`; an EXECUTED or FAILED
  outcome without a kind is `evidence_kind_required`), so a
  "not found" lookup presented with its own kind can no longer become a
  terminal result, even under a verifier that only restates the context.
  Gate cannot detect mislabelled evidence or a verifier that affirms a
  purpose it did not evaluate: a lookup presented as `provider_outcome` to
  a verifier that restates the context, or always answers
  `provider_outcome`, still becomes a terminal FAILED while the provider
  call may be in flight. In 0.26.0 the composed boundary never verified
  provider evidence, and its `reconcile()` accepted a FAILED from any
  caller whose recovery authorization the attempt store accepted.
- Liveness repairs. On the composed boundary, every refusal in `run()` that
  happens before the attempt record exists (an unkeyable fence binding, an
  envelope refusal, attempt-ID allocation, and an attempt-store reserve that
  refuses or throws) now returns `INDETERMINATE` with
  `evaluation_release_unconfirmed` when the release of the evaluation
  reservation fails or cannot be confirmed, instead of a clean refusal, and
  a reservation of the evaluation whose outcome `authorizeAebExecutionDurable()`
  cannot confirm is `INDETERMINATE` with `consumption_reservation_unconfirmed`.
  Gate has no recovery for an evaluation reservation left `RESERVED` with no
  attempt record, and none is safe to add without a new durable marker:
  nothing durable tells a crashed run apart from a live run that has not yet
  written its attempt record, and releasing the reservation would let that
  live run enter the provider after a second run of the same evaluation had
  already entered and FAILED, spending one evaluation twice. That evaluation
  and its native mandate stay fenced, and a retry needs a fresh evaluation
  over fresh native authority.
  A run that has sent any write that could record its attempt as not
  entered, including a write whose acknowledgement was lost, never calls
  the provider afterwards, whatever a later read shows, because that write
  can still take effect after the read and would then make an entered
  attempt look never entered. When the record cannot be read after the
  move to `INVOKING`, the run reads it again up to three times and proceeds
  as the owner if a read shows `INVOKING`; if it stays unreadable, the run
  sends no not-entered write, holds every reservation, does not call the
  provider, and returns `INDETERMINATE` `attempt_start_unconfirmed` with
  `invoked: false`. If the start write did not land, pre-entry recovery
  closes the still-`RESERVED` record. If it landed, the record says
  `INVOKING` although the provider was never called, and it is closable
  only by terminal reconciliation with provider evidence that forecloses any execution, now or later, under the attempt's provider idempotency key,
  such as an authenticated cancellation of that key, which is the
  verifier's decision to affirm as `provider_outcome`; otherwise the action
  stays fenced, by design.
  A point-in-time "not found", even from an authenticated provider lookup,
  does not foreclose execution: a run that is still alive can deliver its
  call after the lookup. Terminal reconciliation now verifies the
  presented outcome before it freezes the record, so an outcome the
  verifier rejects leaves the
  record unchanged and a later reconciliation with verified evidence can
  still close it. When a recovery claim fails, recovery reads the row again
  and counts a row that is already `AVAILABLE` (or already closed to the
  target state) as done, so it no longer reports
  `native_pre_entry_release_unconfirmed` for rows that the live run's own
  hand-back already removed, and it claims again, at most three times, a
  row that another recovery took over before its write.

### Fixed

- `createPostgresAebDurableConsumptionStore()` now provides the durable
  `state()` read the native boundary requires, through a new executor-only
  security-definer function `ep_aeb_private.operation_state`. After a restart,
  `reconcile()` claims the attempt's reservations through
  `claimReservation(key, authorization, scope)` with the caller's
  `recovery_authorization` when the store declares
  `recoveryClaimSupported: true`. Each claim carries an `AebRecoveryClaimScope`
  (`{ boundary, boundaryId, attemptId, operationId, recoveryOperationKey,
  reservation }`),
  which the store validates without running getters and passes to
  `authorizeRecoveryClaim` as `claim.scope`, with `claim.attemptIdentity`. One authorization bound to the
  attempt covers every reservation it holds, so restart reconciliation to
  FAILED or EXECUTED completes in one call on both boundaries.

### Compatibility

- The composed boundary now snapshots the provider result together with
  its evidence, as the native boundary already did, so what was verified
  is what is returned. The result must be in the strict canonical JSON
  domain: plain objects and arrays, strings, booleans, null, and numbers
  that are safe integers. A fractional number, a `Date` or other class
  instance, `undefined`, a bigint, a function, or a cyclic value makes
  `run()` return `INDETERMINATE` `provider_outcome_invalid` after the
  provider call, so the action then needs reconciliation. Encode amounts
  as integers or strings in the invoke adapter's result.
- A mixed fleet is unsafe. A 0.26.0 boundary, native or composed, has no
  same-action fence and does not reserve the label-free identity key, so
  while 0.26.0 and this release serve one consumption store, an action in
  flight on either version can be executed again through a fresh permit on
  the other, and a grant consumed by this release can be admitted again by
  0.26.0 under another pinned label. Do not roll an upgrade across 0.26.0
  and this release. Upgrade in this order. First stop every gate 0.26.0
  boundary that uses the store and drain or reconcile its in-flight
  attempts on 0.26.0, with the provider-outcome verifier that 0.26.0
  already uses: a 0.26.0 native boundary counts only a verifier answer of
  exactly `true`, so a verifier that returns the new affirmation fails
  every 0.26.0 run and reconciliation and the drain cannot finish. A
  0.26.0 instance that restarts during the drain no longer owns the
  reservations its earlier process made, so it closes them only through
  the store's recovery claim (`claimReservation` with a recovery
  authorization), as in 0.26.0. Finish
  on 0.26.0 any pre-entry stop whose rows it did not release as well,
  because 0.26.0 wrote those records `RELEASED` without the not-entered
  marker and this release reports them `attempt_record_unproven`. Only then
  deploy the new verifier, the upgraded attempt stores, and this release
  together; never deploy the new verifier while any 0.26.0 boundary still
  serves. The executed-action fence is not retroactive: 0.26.0 wrote no
  fence row for the actions it completed, so this release admits fresh
  authority for an action that 0.26.0 already executed, and only actions
  executed after the upgrade are refused as
  `native_action_already_executed`. After the upgrade, Gate fences the
  verify 4.1.0 `replay_key` for every `system` and `profile` label, with its issuer
  spelling, that the pin set accepts under the grant's authority namespace,
  so a grant that 0.26.0 consumed under one label is refused as
  `native_replay_conflict` under any label still pinned in that namespace.
  A 0.26.0 attempt has no fence row, so fresh authority for an action that
  0.26.0 left in flight would not be refused; that is why its attempts must
  be resolved first. Keep every label and issuer spelling that 0.26.0
  accepted pinned until the grants consumed under it have expired or been
  revoked: removing one drops its 4.1.0 key from the fence.
- Changing a pin's `authority_namespace`, or the issuer spelling of a pin that
  uses the default namespace, changes the replay identity of every grant under
  it. The 4.1.0 keys do not depend on the namespace, so the same grant is
  still refused when a label and issuer spelling whose 4.1.0 key was
  reserved at consumption is still pinned in its namespace; presented only
  under labels and spellings outside that set, it could be admitted again.
  Drain in-flight attempts and let consumed grants expire before rotating.
  Pins whose issuers are different spellings of one issuer must now all
  declare the same namespace, or construction is refused.
- Existing databases need the `operation_state` function:
  `supabase/migrations/20260925010000_aeb_operation_state.sql` (it mirrors
  `AEB_CONSUMPTION_DDL`).
- `authorizeRecoveryClaim` is called once per reservation an attempt holds
  (operation, native authority, and action-fence holder on the native
  boundary) and receives the validated `scope` and `attemptIdentity`
  (`native:<boundaryId>:<attemptId>` or `composed:<boundaryId>:<attemptId>`).
  Bind the recovery credential to exactly one attempt: `attemptIdentity`,
  together with the relying party and tenant it was issued for, never
  `scope.attemptId` alone, and never `scope.operationId`, which the store
  does not check against the claimed row. `claimReservation()` now
  requires a scope and refuses a claim without one
  (`recovery_claim_scope_required`); a scope that lacks `boundary` or
  `boundaryId` is malformed (`recovery_claim_scope_invalid`); a
  caller that claimed rows directly must pass the attempt's scope. Do not
  bind it to one exact row key, or restart reconciliation cannot finish in
  one call. Never bind it to
  `scope.recoveryOperationKey` or an operation ID: every attempt that reuses
  one operation ID for the same action shares those values, so such a
  credential would authorize claims across attempts. A custom
  `attempts.create_id` must return a unique ID for every attempt of one
  boundary.
- Both boundaries require a `boundary_id`: 1 to 128 letters, digits, `_`,
  `.`, or `-`, starting with a letter or digit, with no `:`. Anything else
  is refused at construction (`boundary_id_invalid`). Keep it unchanged
  while the boundary's attempts may still need reconciliation. Replicas that
  serve one attempt store must use the same value, because the attempt
  record does not carry it; boundaries with different attempt stores that
  share one consumption store use different values. It is part of the
  attempt identity and of every attempt-keyed reservation key, so
  attempt-keyed rows and recovery credentials from a build without it are
  not derivable: drain first, as above, and issue recovery credentials for
  the new identity.
- Native runs now write the attempt record, and call `create_id`, before any
  reservation. A run refused after its record is written leaves that record
  `RELEASED`.
- `reconcile()` takes an optional `mode` (`'terminal'`, the default, or
  `'pre_entry'`). A caller that used `reconcile()` to release a pre-entry
  stop must now pass `mode: 'pre_entry'`.
- `provider_outcomes.verify` receives a `purpose` (`'provider_outcome'` or
  `'pre_entry_lookup'`) and must answer `{ verified: true, purpose,
  attempt_id, provider_idempotency_key }` for the purpose, attempt, and key
  it checked. A verifier that answers a bare `true` no longer verifies
  anything: update it to restate what it checked, and to affirm a "not
  found" lookup only for `pre_entry_lookup`. `createConsequenceBoundary()`
  now requires the same option and refuses construction without it
  (`provider_outcome_verifier_required`); its `run()` verifies its own
  provider result. Callers of `reconcile()` present evidence with its kind
  (`evidence_kind`: `'provider_outcome'` or `'pre_entry_lookup'`).
- A native attempt store must declare `notEnteredMarker: true`, or
  `createNativeConsequenceBoundary()` refuses it at construction: it persists
  the evidence Gate writes with each transition, including the not-entered
  marker, atomically with the transition and returns it from `state()`. A
  composed attempt store without that declaration is used as in 0.26.0,
  with transitions counted only on an answer of exactly `true`. Without its
  `state()`, a start answer other than exactly `true` now holds every
  reservation as `INDETERMINATE` `attempt_start_unconfirmed` without
  calling the provider; pre-entry recovery closes that attempt only when
  its own move from `RESERVED` is answered with exactly `true`, and
  otherwise the action stays fenced. A store
  that drops stored evidence cannot prove a pre-entry stop, so such an
  attempt stays fenced as `attempt_record_unproven`.
- `createNativeConsequenceBoundary()` refuses a pin set that
  `verifyAebNativeAuthorizationPins()` rejects, throwing
  `native_consequence_boundary_configuration_invalid: <native_pins_* reason>`
  at construction.
- `createConsequenceBoundary()` writes one fence-holder row per attempt and
  one marker row per executed action to its consumption store, and refuses
  `action_fence_binding_invalid` when `aeb.config.relying_party_id` cannot key
  the fence. Pre-entry recovery on this boundary works without
  `attempts.store.state()`, but then only its own transition answered with
  exactly `true` proves the stop.
- Gate now imports `verifyAebNativeAuthorizationPins()` from
  `@emilia-protocol/verify`, which verify 4.1.0 does not export, and relies on
  that release's one-namespace-per-issuer pin rule. This release pins
  `@emilia-protocol/verify` exactly at 5.0.0, and release order is a hard
  dependency: publish `@emilia-protocol/verify` 5.0.0 first, then publish
  this Gate. A Gate published while it still pins 4.1.0 fails to
  load its root entry, `@emilia-protocol/gate`, and every subpath that
  imports `@emilia-protocol/verify/aeb`, not only `./aeb`: in a packed check
  against the published 4.1.0, `.`, `./aeb`, `./consequence-boundary`, and
  `./aeb-consumption-store` each failed with a missing export
  (`verifyAebNativeAuthorizationPins`). That breaks every Gate consumer,
  including receipt-guard users of the root entry. The workspace link hides
  this in CI.
- TypeScript: `ConsequenceBoundaryReconcileInput.outcome` and
  `NativeConsequenceBoundaryReconcileInput.outcome` now take
  `ConsequenceBoundaryPresentedOutcome` (an EXECUTED or FAILED outcome that
  carries `evidence_kind`) instead of `ConsequenceBoundaryEffectOutcome`, a
  compile-time break for callers of `reconcile()`. New exported types:
  `ConsequenceBoundaryEvidenceKind` and `ConsequenceBoundaryPresentedOutcome`.
  Both boundary configurations require `boundary_id`, and the boundary
  objects both constructors return expose it.
- Version type: the changes above refuse pin sets, attempt stores, inputs,
  verifier answers, and recovery claims that 0.26.0 accepted, require a
  provider-outcome verifier and a `boundary_id` on both boundaries, and
  change how `reconcile()` releases a pre-entry stop, so this is a breaking
  release. Semantic Versioning 2.0.0 allows anything to change in a 0.y.z
  version; this release follows the npm caret convention, under which
  `^0.26.0` admits only 0.26.x, and ships the breaking change as the next
  minor version, 0.27.0. It pins `@emilia-protocol/verify` exactly at
  5.0.0.
- `createNativeConsequenceBoundary()` now also refuses a pin set that declares
  two different `authority_namespace` values for one exact issuer
  (`native_pins_issuer_namespace_conflict`), and treats more issuer spellings
  as aliases (URI scheme case, trailing dots on a URL host, an http or https
  URL written without `//`, URN namespace-identifier case, DID method-name
  case, `did:web` host case and trailing dots, and SPIFFE trust-domain case
  and trailing dots), through
  `verifyAebNativeAuthorizationPins()`. Normalization cannot find every
  alias: two issuer strings that denote one authority but do not normalize
  equal need one explicitly shared namespace.
- The fence, and every other key built from them, compares the canonical
  action digest and the provider coordinates exactly as configured. Gate
  implements no material-field inventory and no equivalence between spellings
  (amount formats, case, whitespace, Unicode normalization); callers must
  canonicalize the action and configure identical coordinates on every
  boundary instance that reaches one provider account. Identical intentional
  repeats must differ in the canonical action, for example through an
  instance field.
- Each executed native action leaves one permanent marker row in the
  consumption store, used only to choose the `native_action_already_executed`
  reason.

## 0.26.0 (2026-09-24)

### Added

- Add the stable `./aeb` facade for native authorization handoff and
  consequence admission. Gate verifies a pinned gateway statement bound to the
  stated native authorization identity and exact action, applies local policy,
  durably reserves its replay unit before provider entry, and preserves
  uncertain provider outcomes for authenticated reconciliation.
- Snapshot the configured trust, policy, provider, recovery, clock, identifier,
  and durable-store callables when the boundary is constructed. The provider
  result is cloned and frozen before verification, so later caller or provider
  mutation cannot change what runs or what Gate returns under recorded program
  digests.

The direct handoff is a repository implementation profile for the direct
native path of AEB-06. AEB-06 was posted as an individual Internet-Draft at
2026-09-25T02:15:03Z, before this release was published, and is not adopted by
any working group; the text shipped in this release still described it as
staged. AEB-06 makes CAID and AEC conditional but does not specify the gateway
handoff. Source labels do not establish native-protocol conformance or
independent interoperability.

### Known issues (found after release)

- `createNativeConsequenceBoundary()` does not fence the action itself. While
  a first attempt is `INDETERMINATE`, a second attempt at the identical action
  that carries a fresh native `authorization_id` and a fresh operation ID is
  admitted and reaches the provider a second time.
- The native replay unit includes the handoff's `system` and `profile` labels.
  When a relying party pins one gateway and issuer under two labels, the same
  native grant presented under each label is admitted twice.
- The shipped PostgreSQL AEB store does not expose `state()`, so it cannot back
  `createNativeConsequenceBoundary()`; construction fails with
  `native_consequence_boundary_configuration_invalid`.
- The composed `createConsequenceBoundary()` does not fence the action either.
  Fresh evidence with a new operation ID, presented while a first attempt is
  `INDETERMINATE`, reaches the provider a second time.
- When a native reserve write fails, the error path releases the operation
  reservation for the caller-supplied operation ID without proof that the
  call created it.

All of these are repaired in 0.27.0 above.

## 0.25.0 (2026-09-13)

### Added

- Add `./action-risk-control-schedule`
  (`EP-ACTION-RISK-CONTROL-SCHEDULE-v1`), a relying-party-scoped,
  hybrid-signed statement of the technical controls required for one action
  class, with a signed qualification status and an evaluation that returns
  `ELIGIBLE`, `NOT_ELIGIBLE`, or `INDETERMINATE`. The schedule is evidence
  input only. It never authorizes an action, creates policy or coverage, sets a
  premium, allocates liability, or proves a provider effect.
- Add `./provider-outcome-binding` (`EP-PROVIDER-OUTCOME-BINDING-v1`). It
  verifies a complete `EP-OUTCOME-OBSERVATION-v2` under the relying party's
  source pins and requires the signed observation to commit the digest of one
  closed `EP-PROVIDER-OUTCOME-CONTEXT-v1`. Outcomes are `COMMITTED`,
  `PROVEN_NOT_COMMITTED`, or `INDETERMINATE`; the binding is not provider
  truth or proof of an external effect.
- Add `./action-evidence-packet` (`EP-ACTION-EVIDENCE-PACKET-v1`), a
  content-addressed join of native artifacts for one exact Gate action through
  relying-party-supplied native verifier adapters. Results are
  `TECHNICALLY_COMPLETE`, `INCOMPLETE`, `CONFLICTED`, or `INDETERMINATE`. The
  packet never decides coverage, causation, liability, a claim, or payment.

### Changed

- Depend on `@emilia-protocol/verify` 4.0.0.
- The underwriter control attestation's boundary `status` string changed from
  "carries no coverage effect until adopted by the carrier" to "has no coverage
  effect; acceptance as technical evidence would not create or decide
  coverage", so newly built attestations differ in that field from 0.24.0
  output.

## 0.24.0 (2026-09-05)

### Security

- Bind the canonical observed action for a legacy
  `EP-ACTION-RISK-MANIFEST-v0.1` entry that is `receipt_required` but declares
  no `execution_binding.required_fields`. Such an entry previously left the
  receipt bound to the action TYPE alone even though the executor had supplied
  system-of-record fields, so a receipt signed for a $1.00 payout to one
  account authorized a $999,999.99 payout to another. `validateActionRiskManifest`
  now refuses that manifest at author time; this is the enforcement-time floor
  for a manifest loaded without re-validation. A receipt carrying no signed
  `canonical_action` fails closed instead of authorizing an unconstrained
  mutation.

- Validate and bound provider-entry guard evidence as a plain finite-canonical
  JSON object before any provider effect, preserve accepted or refusing guard
  evidence through capability results and internal Gate records, and propagate
  only valid HTTP error statuses. Compatibility note: guard evidence containing
  Dates, Maps, accessors, symbols, cycles, non-finite numbers, excessive depth,
  node count, or string data now refuses before provider entry. Finite decimal
  measurements remain supported. Ordinary Gate refusal objects retain the
  existing evidence-record fields except that raw `guard_evidence` is now
  redacted from public refusal and `guard()` error surfaces; the full record
  remains available through the internal evidence log and direct `run()` result.

- Restrict the Action Escrow human-facing milestone, amount, currency, payee,
  and destination fields to printable ASCII before building the exact approval
  envelope, preventing Unicode-confusable substitutions in authority text.
  Compatibility note: existing templates containing non-ASCII values now
  refuse instead of being normalized. Deployments must map those values to
  stable ASCII identifiers and issue a fresh binding and approvals.
- Make a deployment-level `requiredAdmissibilityProfile` authoritative. A
  request or selector may repeat its configured identifier and digest, but
  cannot replace either before the trusted verifier runs or a receipt is
  reserved.
- Add the experimental Claim Assurance bridge as non-authorizing,
  exact-action evidence. Gate recomputes the Claim Case under the operator's
  pinned profile and verifier callbacks, validates the closed result against
  the executor-observed action, and preserves the typed block separately from
  Gate's reliance interpretation.
- Invalid or authority-claiming Claim Assurance results fail closed and are not
  re-emitted as valid typed evidence in reliance packets.

## 0.23.20 (2026-08-21)

- Add provider-neutral memory projection records for SHEESH/SOMA and Zep,
  binding pinned source and projection bytes to one exact action while keeping
  verified context separate from authorization.
- Refuse provider/profile substitution, stale verification state, projection
  drift, and replay with seven bounded positive and hostile cases.

## 0.23.19 (2026-08-21)

- Make the installed `ep-protect` executable resolve npm's bin symlink before
  deciding whether it is the process entry point. Version 0.23.18 could exit
  successfully without activating or writing an artifact when invoked through
  the normal npm-installed command.
- Add a subprocess regression that invokes the executable through an
  npm-shaped symlink and requires an activation artifact to be written.

## 0.23.18 (2026-08-21)

- Reissue the customer-owned consequence-protection release after npm 12
  changed `npm pack --json` from an array to a keyed object. The release
  verifier now accepts both documented report shapes without weakening any
  packed-artifact or consumer check.

## 0.23.17 (2026-08-21)

- Reissue the customer-owned consequence-protection release from the exact
  protected `main` commit after the immutable `0.23.16` tag correctly remained
  bound to an earlier commit whose publication preflight failed under npm 12's
  remote-dependency policy.
- Add a sealed protected-action registry and `gate.runRegistered()`. Reviewed
  handlers are installed only during trusted startup, the pinned manifest
  selects the handler, and frozen validated parameters enter the existing
  reserve/provider-entry/commit path. The existing `run(fn)` API is unchanged.
- Coverage reconciliation schema family v2 (`EP-COVERAGE-SOURCE-INVENTORY-v2`,
  `EP-COVERAGE-POPULATION-v2`, `EP-COVERAGE-RECONCILIATION-REPORT-v2`,
  `EP-COVERAGE-RECONCILIATION-ATTESTATION-v2`); v1 artifacts fail closed under
  v2 verifiers and there is no compatibility alias.
  - Rename the `receipt_without_effect` bin to `receipted_without_observation`:
    the join only shows a receipt with no matching record in the supplied
    source population, never that no effect occurred.
  - Require a `classification_rule_id` on every `excluded` and `exception`
    record, resolved against the compiled-in versioned registry
    `EP-COVERAGE-CLASSIFICATION-RULES-v1`; the field rides inside the record
    and is covered by the signed population root. A missing or unresolvable
    rule id demotes the record to the new system-side `system_indeterminate`
    bin instead of widening an exclusion.
  - Assert, in the runner before any report is emitted, that bin counts sum
    back to the signed record counts of both populations
    (`assertCoveragePopulationConservation`), refusing with
    `population_conservation_violation:system` or
    `population_conservation_violation:receipt` on violation.

## 0.23.15 (2026-08-15)

First published in 0.23.15. This section was previously labelled Unreleased.

### Added

- Add the transport- and evidence-format-neutral `./consequence-boundary`
  facade. It re-verifies a signed AEB join for one frozen action, applies local
  policy, atomically fences native replay units, records provider-attempt
  custody, and reports only `EXECUTED`, authoritative `FAILED`, or
  `INDETERMINATE` after provider entry.
- Add `./bounded-execution-acceptance`, a relying-party-signed acceptance
  profile and portable evidence pack over signed bounded-execution reports.
  Evaluation preserves unresolved work as `INDETERMINATE` and deliberately
  makes no legal-compliance, external-effect, safety, or complete-mediation
  claim.

### Security

- Scope legacy receipt consumption by the canonical signed
  `[tenant_id, receipt_id]` pair. Every reserve, consume, commit, and release
  transition now uses the same recorded composite key, preventing one
  tenant's receipt identifier from colliding with another tenant in a shared
  store.
- Require an explicit relying-party verification mode when WebAuthn RP and
  origin pins are authoritative; omitted pins now fail closed instead of
  silently producing an integrity-only result.

### Compatibility

- Pre-composite stores contain bare `receipt_id` rows that the new composite
  keyspace does not consult. Before upgrading a deployment that cannot accept
  one additional admission during the configured `maxAgeSec` window, drain
  in-flight receipts or refuse admission for one complete `maxAgeSec`
  interval. Fresh stores are unaffected.

## 0.23.14 (2026-08-05)

- Carry `@emilia-protocol/require-receipt` 0.8.0 so Gate integrations can use
  the same executor-side exact-action binder as the public framework adapters.

## 0.23.13 (2026-08-04)

- Reissues the recoverable prepared-reservation release from the exact protected
  `main` commit after the immutable `0.23.12` tag was correctly refused by the
  publication gate when `main` advanced before dispatch.

## 0.23.12 (2026-08-04)

### Security

- Allow an orchestrator to durably custody the exact reservation owner token
  before Gate commits the atomic reservation, closing the process-death window
  between those two steps.
- Make deadline recovery program-aware so releasing an expired, provably
  unentered admission also releases its occurrence and reserved budgets.
- Keep post-provider-entry recovery evidence-gated; the deadline reaper does
  not retry or erase an entered effect.

## 0.23.11

- Publish the crash-safe bounded-program provider-entry path from 0.23.10 under
  a fresh immutable tag after the original protected tag stopped before npm
  publication.
- Regenerate package-bound formal, security-case, and proof evidence against
  the exact release bytes. There is no additional API change from 0.23.10.

## 0.23.10

- Add crash-safe, program-aware provider entry with a caller-prepared invocation token.
- Preserve bounded-program status, concurrency, occurrence, and budget checks on that path.

## 0.23.9 (2026-08-03)

### Security

- Fail closed when an allowance/profile verifier returns only `true` or
  `{ ok: true }`; it must now return an explicit canonical
  `action_fence_digest` derived from the profile-validated material action.
- Derive the built-in Gate Allowance fence from every validated action field
  except the wrapper-specific operation-ID field, so two operation IDs cannot
  execute one material action twice in the shared allowance namespace.

### Compatibility

- Custom allowance/profile verifiers must return
  `{ ok: true, action_fence_digest }`. This intentional security break does not
  change the capability database schema or the exact-digest and CAID scope
  semantics.

## 0.23.8 (2026-08-03)

### Security

- Fence live reservations by a stable material-action digest in addition to
  the exact request digest, so wrapper-specific operation IDs cannot authorize
  the same consequential action twice.
- Permanently quarantine legacy capability IDs whose historical rows do not
  carry authoritative semantic-fence evidence; reviewed recovery issues a new
  capability ID instead of inferring equivalence from old exact digests.
- Reject failed CAID resolver decisions, non-positive spend reservations, and
  mismatched action digests across pre-entry recovery and indeterminate
  reconciliation in both memory and PostgreSQL stores.
- Validate the complete PostgreSQL fence-index contract and enforce semantic
  readiness at the database boundary, including direct table writers.

## 0.23.7 (2026-08-02)

### Release

- Supersedes the unpublished `0.23.6` tag after the protected release gate
  required a source-bound LLM context refresh. Runtime, protocol, and draft
  behavior are unchanged from `0.23.6`.

## 0.23.6 (2026-08-02)

### Security

- Recheck each allowance's authoritative monotonic status head inside the same
  atomic transaction that reserves spend, closing the verify-then-revoke race.
- Persist invocation recovery authority before the durable `INVOKING`
  transition so a process crash cannot strand an unowned operation.
- Distinguish pre-provider reservations from entered effects, allowing only an
  expired, demonstrably unentered reservation to be released automatically;
  post-entry recovery remains evidence-gated and never blindly retries.

## 0.23.5 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.4` tag after protected `main` advanced for a
  standards-only idnits correction before registry publication. Security and
  runtime behavior are unchanged.

## 0.23.4 (2026-08-01)

### Security

- Refuse symbol-keyed members in Gate commit-binding inputs so every in-process
  member is either covered by the exact-action hash or rejected.
- Publish from the post-hardening protected-main baseline after the prior
  approval-wait release was correctly invalidated by a main-branch advance.

## 0.23.3 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.2` tag so Gate and its exact
  `@emilia-protocol/require-receipt` 0.7.2 dependency publish from the same
  protected-main baseline.

## 0.23.2 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.1` tag and pins
  `@emilia-protocol/require-receipt` 0.7.2, whose clean build now reproduces all
  package-declared dist assets from source.

## 0.23.1 (2026-08-01)

### Release

- Supersedes the unpublished `0.23.0` release tag on the corrected protected-
  main evidence baseline.
- Pins `@emilia-protocol/verify` 3.20.1 and
  `@emilia-protocol/require-receipt` 0.7.1 so the published Gate consumes the
  same hardened canonicalization, projection, and receipt behavior verified by
  this release's evidence chain.

## 0.23.0 (2026-08-01)

### Added

- `./coverage-reconciliation-runner`, which verifies independently signed,
  privacy-minimized source inventories, joins exact CAID/action-digest pairs,
  derives conserving counts, and emits a report-bound period attestation.
- `./bounded-execution-program`, a canonical signed finite action DAG with
  exact-action or pinned-profile nodes, typed terminal dependencies, retained-
  occurrence ceilings, multidimensional attempt budgets, suspension,
  revocation, and fresh signed supersession.
- `./bounded-execution-report`, a signed point-in-time, program-to-date record
  of Gate-observed occurrences and budget use with an explicit boundary around
  external effects and actions outside Gate.
- Program-aware in-memory and PostgreSQL AdmissionStore operations that bind
  each occurrence into the immutable admission snapshot and consume the
  one-time execution right in the same transaction as program state.
- The versioned PostgreSQL reference schema in
  `sql/gate-qualification-v2.sql`, deterministic reference vectors, runtime-
  refinement traces, and a bounded TLC model with two intentional negative
  controls.
- Signed Gate Allowances that permit exact, bounded repeated operations while
  retaining immutable provider-action binding, aggregate depletion, current
  status, and one-time operation fencing.
- Conserved-authority delegation across sibling fan-out: every child transfer
  is funded exactly once from its parent in one authoritative state domain,
  with aggregate sibling limits and explicit cross-domain non-guarantees.

### Security

- Source-system identities, mapping-profile digests, source operators, trust
  keys, and verification time are verifier-owned pins. Duplicate joins,
  cross-population CAID/digest conflicts, same-operator source populations, and
  report substitution fail closed. The artifact remains evidence about two
  supplied populations and does not prove either source was complete.
- Program-authorizer keys, roles, status, verification time, action-profile
  matchers, and current program status are store-owned policy. The signed
  program constrains separately authorized actions; it does not prove human
  ceremony, safe intent, provider or effect truth, complete mediation, or the
  absence of actions outside Gate.
- The ordinary and execution-program admission paths both retain monotonic
  authenticator-counter currentness checks immediately before provider entry.

## 0.22.2 (2026-07-31)

### Security

- Reproject the normalized payment action at admission from the exact
  server-owned AP2 payloads and source binding, then require every Gate, human,
  and AEB action digest to match it. A pinned verifier can no longer cause the
  live path to compare a claimed action with itself.
- Support an explicit zero-counter platform-passkey policy without a false
  monotonicity claim; strict counter advancement remains the default, and both
  modes retain exact assertion replay, AP2 token, provider-operation, and
  one-time admission controls.

### Packaging

- Include and export the PostgreSQL Gate Qualification v2 schema used by the
  durable AdmissionStore deployment.

## 0.22.1 (2026-07-31)

### Added

- FIDO/AP2 AdmissionStore builders that re-verify a signed,
  execution-authorizing two-leg AEB record against server-owned pinned
  configuration and authenticated status heads, remeasure the exact AP2 v0.2
  token strings and final provider-request bytes, and require a pinned provider
  adapter to find the exact PaymentMandate token in those frozen bytes.
- Domain-separated one-time resources for the CheckoutMandate token,
  PaymentMandate token, WebAuthn assertion, provider operation, and both
  authenticated status heads, plus a durable monotonic counter resource for
  the RP/credential pair. The signed full AEB evaluation record, including
  initiator, executor, evaluator, nonce, and requirement, is retained in the
  admission evidence.

### Security

- Request-side clocks, trust roots, status maps, actors, provider adapters, and
  provider bytes are not accepted. Gate Qualification v2 plus AdmissionStore
  `beginInvocation()` remain the sole authority-custody and one-time provider
  entry boundary; the bridge creates no parallel consumption store and makes
  no provider-outcome or observed-effect claim.
- Admission builders return recursively frozen clones after validating the
  complete Gate snapshot contract, preventing post-build nested mutation.
- Memory and PostgreSQL AdmissionStores require a trusted enrollment or
  recovery baseline, atomically compare and advance signed WebAuthn counters
  with successful reservation, and recheck their durable head before
  invocation. Missing enrollment, reuse, rollback, and artifact-selected
  baselines fail closed.

## 0.21.0 (2026-07-29)

### Added

- Signed action-refusal delivery from the live reliance boundary, with a
  durable PostgreSQL acceptance store for atomic replay refusal, tenant
  isolation, custody references, and delivery evidence.
- PEDIGREE composition that preserves native verification and keeps completion
  evidence structurally separate from pre-action authorization.
- A relying-party-pinned Trusted Context admission pack and optional
  ApertoMemory adapter for encrypted context evidence without allowing memory
  evidence to authorize an action by itself.

### Security

- Pins `@emilia-protocol/verify@3.18.2`, carrying the PSEA-02 adapter,
  independent industrial effect-evidence predicates, and the current
  PEDIGREE/AEB composition vectors into Gate.
- Refusals remain fail-closed, exact-action bound, and non-authorizing. Trusted
  context remains an optional evidence leg; Gate still owns the final local
  authorization and one-time consequence-admission decision.

## 0.20.1 (2026-07-29)

### Security

- Pins `@emilia-protocol/verify@3.17.1`, carrying the current-status
  compromise boundary and the corrected backdating semantics into every
  Gate installation. The independently published verifier tarball is
  byte-pinned in the governed release registry.

## 0.20.0 (2026-07-28)

### Added

- A separately signed Loss-Allocation Schedule pinned to an exact Reliance
  Program through a relying-party-owned Admissibility Profile.
- An Open Exposure Ledger with aggregate ceilings across tenant, program,
  counterparty, and action class; durable PostgreSQL custody; and mandatory
  independent reconciliation for indeterminate execution.
- Exact-action signed refusal statements with atomic replay acceptance and
  optional delivery, custody, and transparency evidence references.
- Period Coverage Reconciliation Attestations, governed-taxonomy Receipt Census
  aggregates with coarse primary suppression, and signed external Loss
  Experience Feeds with trusted correction lineage.
- A bounded composed lifecycle model and runtime-refinement trace covering
  admission, exposure reservation, invocation, uncertainty, reconciliation,
  refusal, and terminal-state preservation.

### Security

- Loss schedules, refusal statements, coverage attestations, and loss feeds
  remain separate from authorization and cannot create execution authority.
- Open exposure remains reserved through `INVOKING` and `INDETERMINATE`; there
  is no blind release or retry, and origin, executor, and reconciler authority
  must remain distinct.
- Coverage and census artifacts reconcile only supplied populations. They do
  not establish completeness, causation, insurance coverage, legal liability,
  adjudicated loss, solvency, or payment.

## 0.19.0 (2026-07-28)

### Added

- `./reliance-program`, a closed, relying-party-signed source policy and
  deterministic compiler to the existing
  `EP-GATE-TRUST-PROGRAM-PROFILE-v1` wire format.
- Admissibility Profile references as digest-pinned program fragments, with a
  relying-party-owned evaluator adapter that prevents presenters from choosing
  the acceptance bar.
- A public JSON Schema, compiler trace, and explicit consequence ownership by
  either a receipt program or Action Escrow.

### Security

- Gate now pins the independently published
  `@emilia-protocol/verify@3.17.0` registry tarball. Reliance Program decision
  citations therefore execute against the exact AEB/AEC verifier release whose
  bytes are recorded in the governed package registry.
- Compilation requires an Ed25519 signer whose pinned key is bound to the
  named relying party, recomputes every profile self-hash, and refuses unknown
  fields, substituted profiles, disconnected stages, action drift, and
  ambiguous consequence ownership.
- Compilation proves only that the signed source maps to the existing Trust
  Program. It does not assert evidence sufficiency, authorization, provider
  outcome, observed effect, or deployment completion.

## 0.18.2 (2026-07-27)

### Added

- `./referee`, a closed, non-authorizing `EP-REFEREE-RESULT-v1` self-test
  evaluator that preserves native verification, relying-party acceptance,
  exact-action matching, evidence satisfaction, provider outcome, and observed
  effect as separate dimensions.
- `./referee-runner`, a no-shell local subprocess transport with strict JSON,
  executable SHA-256 verification, bounded input/output and time, and
  fail-closed handling for malformed or ambiguous runner behavior.

### Security

- Referee results are fixed to `claim_scope: SELF_TEST` and
  `execution_authorizing: false`; they cannot authorize, reserve, invoke, or
  certify an action.
- The transport is not an operating-system sandbox and makes no claim to block
  runner network, filesystem, syscall, or descendant-process access.
- Retained the independently published
  `@emilia-protocol/verify@3.16.0` registry dependency. Referee does not depend
  on the new Verify AEB-1 reference runner, so Gate keeps its release graph
  honest instead of declaring an unnecessary coupled upgrade.

## 0.18.1 (2026-07-27)

### Fixed

- Repinned the release dependency to the exact published
  `@emilia-protocol/verify@3.16.0` registry tarball. No runtime or API behavior
  changed from 0.18.0; the protected 0.18.0 tag was never published.

## 0.18.0 (2026-07-26)

### Added

- `./gate-qualification-v2`, with pure qualification/AEB/AEC/local-policy
  composition plus shadow, enforcement, and evidence-only reconciliation
  orchestration around a protected adapter.
- `./admission-store`, a unified immutable admission snapshot, CAS-owned
  lifecycle, one-time execution right, operation/resource fencing,
  predecessor-digest journal, supersession, and remedy reference contract.
- `./admission-store-postgres`, a deployment-bound PostgreSQL RPC adapter for
  the unified store with single-tenant construction, exact output validation,
  bounded transaction retries, and ambiguous-begin readback handling.
- Root-package re-exports, generated declarations, compatibility entry points,
  and focused package tests for the qualification and admission modules.

### Security

- Qualification remains non-authorizing and cannot replace AEB, AEC, or the
  relying party's local authorization policy.
- Authority is consumed before provider entry; uncertain outcomes remain
  reconciliation-required and cannot be blindly retried.
- The checked-in memory store is an explicit test-only, non-durable reference.
  The orchestrator and PostgreSQL adapter consume the canonical unified
  `AdmissionStore` contract.
- Enforcement requires authoritative immediate remeasurement of the candidate,
  qualification status, AEB, AEC, local policy, and protected request before
  transactional consumption. It also requires protected restart-safe custody
  for owner and reconciliation capabilities; memory custody is test-only.
- Qualification decisions bind the exact protected-request digest and cannot
  be replayed across another otherwise-valid admission.
- The PostgreSQL adapter is a single-tenant public reference. Managed
  tenant-principal mapping, deployment migrations, federated atomicity, and
  managed service operation are not claimed.

## 0.17.0 (2026-07-26)

### Added

- `./autonomy-control-plane-profile`, a closed compiler from a human-signed
  root objective into one existing Gate Trust Program per exact child action.
- Typed containment for child actions, audiences, expiries, per-child and
  aggregate sibling budgets, exact code-diff bindings, independent
  proposer/evaluator/executor roles, pinned fitness evidence, bounded canary
  promotion, current suspension status, and separately authorized rollback.
- A bounded TLA+ model and deliberately unsafe self-expansion configuration;
  the safe model checks authority conservation while the negative control
  falsifies it when an agent can grant itself a new action and budget.

### Security

- Unknown profile fields, cyclic goal derivation, role collapse, stale or
  unpinned fitness/status evidence, promotion without canary evidence, and
  rollback under a reused CAID fail closed.
- The claim boundary explicitly excludes natural-language goal entailment,
  provider truth, test adequacy, clocks, storage, and deployment completion.

## 0.16.1 (2026-07-26)

### Fixed

- PostgreSQL 17 role-graph checks now distinguish provider-managed
  administrative grants from executable `INHERIT` or `SET` authority, while
  continuing to reject every usable owner/executor or privileged-role path.
- Forward migrations remove their own temporary owner grant without deleting
  a managed provider's non-usable administrative grant.
- The protected npm publisher uses an explicit local tarball file spec.

## 0.16.0 (2026-07-25)

### Added

- `./consequence-actuator`, a short-lived signed execution-envelope boundary
  for separately deployed credential-owning actuators, with immutable tenant,
  action, CAID, provider account, target, operation, attempt, idempotency,
  nonce, and expiry bindings.
- A PostgreSQL RPC-only permanent envelope store with tenant-principal
  isolation, forced RLS, no direct runtime or `service_role` table authority,
  and no release path after provider invocation.
- `./discovery-permit-resolver`, which retrieves pinned action-control
  discovery without redirect, network-boundary, freshness, or source drift.
- A split managed reference deployment where the decision service owns policy
  and envelope signing while the actuator alone owns provider credentials and
  signs exact execution observations.

### Security

- A provider timeout consumes the execution envelope as `INDETERMINATE`; blind
  replay is refused and only authenticated, attempt-bound evidence may
  reconcile the Proposal-to-Effect lifecycle.
- Production actuator construction requires an atomic, durable,
  ownership-fenced, permanently consuming store. Process-local storage is
  available only through an explicit test-only opt-in.
- The decision process has no provider credential or provider API
  implementation. Signed actuator observations are verified under a pinned key
  and exact execution tuple before use as lifecycle evidence.

## 0.15.2 (2026-07-23)

### Fixed

- Proposal-to-Effect recovery snapshots now preserve PostgreSQL microseconds
  for the exact lease compare-and-swap fence. The previous millisecond
  serialization could make a stale attempt conflict with its own stored lease
  and remain permanently unrecoverable.
- The managed consequence-control readiness gate verifies that the live
  `read_attempt` RPC carries the required microsecond-precision contract
  before admitting traffic.

## 0.15.1 (2026-07-23)

### Added

- A tenant-authenticated `hasReplayFence()` observation on the durable AEB
  consumption store. It reports an exact native replay unit as unavailable
  when either a reserved or permanently consumed fence exists.
- Durable accepted `EP-STATUS-v1` head custody, scoped by tenant, relying
  party, and complete status target, with database-side compare-and-advance.
- A tenant-authorized Proposal-to-Effect attempt lookup over the immutable
  provider tuple and request digest, so a lost indeterminate HTTP response can
  be rediscovered without invoking the effect again or rotating recovery
  ownership.

### Security

- Proposal-to-Effect status verification can now obtain exact, server-side
  replay state without granting direct table access. The observation is a
  preflight check; the immediately following atomic reservation remains the
  race-closing authority boundary.
- Proposal-to-Effect no longer accepts a caller-configurable previous-head
  resolver. Status candidates are verified against the relying party's stored
  predecessor and admitted only if that head still wins an atomic comparison.
- The production readiness contract proves distinct executor and recovery
  session identities, exclusive tenant capabilities, exact role/RPC grants,
  and the required replay, status-head, and attempt-store schema before
  admitting traffic.

## 0.15.0 (2026-07-22)

### Added

- `./proposal-to-effect`, an orchestration profile over CAID, the existing
  `EP-APPROVAL-v1` acquisition rail, signed AEB evaluation, Gate authorization,
  durable operation reservation, exact effect invocation, and authenticated
  reconciliation.
- An executable end-to-end example and profile vectors covering exact-action
  mutation, stale evidence, one-time replay, indeterminate effects, and
  post-effect commit failure.
- `./aeb-consumption-store`, a tenant- and relying-party-namespaced PostgreSQL
  store that atomically fences the AEB operation and all native replay units,
  with opaque owner tokens and authorized restart recovery.
- `./proposal-to-effect-status`, which verifies server-resolved
  `EP-STATUS-v1` heads and separately requires authenticated local consumption
  state before the atomic execution reservation.
- `./proposal-to-effect-postgres`, a private-schema PostgreSQL store for
  consequence attempts with HMAC-hidden owner capabilities, tenant/provider
  namespaces, owner-fenced transitions, immutable terminal states, exact
  provider-evidence reconciliation, database leases, disjoint executor and
  recovery roles, tenant-principal bindings, and stale-only restart recovery.
- Concrete Remedy Program evidence adapters for signed disputes,
  authorizations, provider outcomes, Action Escrow state, and late revocation.
- A heterogeneous remedy case-set coordinator that completes only after every
  exact child state and signed remedy receipt verifies.
- A PostgreSQL remedy case-set store with tenant RLS, immutable manifests,
  append-only state events, database-clock custody, and owner/revision CAS.

### Security

- A proposal is explicitly non-authoritative and carries no signature, permit,
  or presenter-controlled authorization decision.
- AEB and Gate make independent, fail-closed decisions over the same operation,
  initiator, CAID, normalized action, and relying-party pins.
- Once an effect may have executed, failed bookkeeping cannot release its AEB
  reservation. The operation remains frozen until authenticated provider
  evidence proves `COMMITTED` or `NOT_COMMITTED`.
- A committed effect consumes AEB replay authority before its consequence row
  becomes terminal. `repairAeb` converges legacy or crash-window terminal rows
  without invoking an effect, and opaque attempt-owner capabilities are kept
  out of enumerable results and errors.
- A recovered worker receives a rotated owner capability; the stale worker can
  no longer transition or reconcile the attempt. An in-flight attempt is
  conservatively recovered as `INDETERMINATE`, never retried as unexecuted.
- AEB production consumption state is RPC-only behind tenant-bound, no-bypass
  executor and recovery roles with physically separate pools. Supabase
  `service_role` and both runtime roles have no direct table authority;
  in-memory stores remain test-only.
- Remedy case-set state and append-only history are likewise RPC-only behind a
  tenant-bound no-bypass executor; generic service credentials cannot rewrite
  current or historical remedy state.

## 0.13.0 (2026-07-20)

### Added

- A receipt-program execution kernel that composes CAID matching, Gate
  authorization, bounded capability reservation, provider execution,
  execution evidence, and an operator-signed content-addressed certificate.
- Offline certificate verification under a separately pinned operator key,
  context, and evidence record, including CAID re-performance, exact schemas and
  instruction sequencing, result digest, action/operation binding, and Gate
  evidence-record references.
- A tenant-bound Trust Program kernel for staged, ordered or threshold
  authorization ceremonies, with durable Postgres state, revocation handling,
  exact predecessor/evidence bindings, and tenant-wide replay refusal.
- Explicit `executed`, `refused`, and `indeterminate` terminal states. Provider
  timeout and non-canonical provider output halt the operation without restoring
  replay authority.

### Security

- Production construction requires both a durable atomic evidence log and a
  durable capability store, an external KMS/HSM signer, pinned certificate
  context, pinned result projector, and finite provider deadline. Process-local
  state and keys are available only behind an explicit test/demo opt-in.
- CAID resolution, operation-id field selection, certificate signing and
  context, result projection, deadline, clock, and Gate trust are
  constructor-pinned; runtime requests cannot replace them.
- Provider code receives deep-frozen snapshots rather than Gate's live
  authorization objects. Complete certificates are appended to the atomic
  evidence log, and signer/persistence failures preserve Gate's terminal state
  without issuing contradictory proof.
- The certificate is an operator-signed integrity and binding artifact. It is
  not a zero-knowledge proof and does not attest that an external provider's
  statement is truthful.

## 0.12.0 (2026-07-18)

### Added

- A distinct contractor release-template profile that requires a signed
  `project_record_snapshot_digest` while preserving the closed legacy profile.
- A contractor evidence-package profile that carries and re-verifies the exact
  project-record sidecar bytes under a relying-party-owned verifier.
- A read-only Procore change-order source adapter with complete pagination and
  stable double-fetch snapshots.

### Security

- A project-system source record cannot become agreement acceptance or release
  authority. Replacing its committed snapshot changes the action digest and
  fails closed.
- Existing Action Escrow templates without a project source remain valid under
  their original closed profile; new contractor artifacts use an explicit
  version boundary and cannot be silently downgraded.
- Unmarked project-bound artifacts from the unreleased `0.11.1` preview remain
  readable only through the contractor package path, which requires the exact
  project-record sidecar and a relying-party-owned source verifier.

## 0.11.0 (2026-07-17)

### Added

- Action Escrow modules for exact document/action binding, evidence
  verification, a signed lifecycle state machine, durable Postgres state and
  journal storage, licensed-custodian adapters, portable assurance packages,
  and fail-closed release enforcement.
- Public package exports for `action-escrow`, `action-escrow-state`,
  `action-escrow-postgres`, `action-escrow-custodian`,
  `action-escrow-package`, and `action-escrow-verifiers`.

### Security

- Release requires exact profile, party, final-document, material-term,
  funding, milestone, action, and approval binding under relying-party-pinned
  policy.
- Release approvals are fresh and action-specific, release is consumed once,
  storage failure refuses, and an ambiguous provider effect enters
  reconciliation instead of being retried.
- Release approvals now use the canonical `EP-RESOLUTION-v1` binding-moment
  hash, relying-party-pinned option mapping, initiator, per-party nonce, and
  evaluation time. The reference scenario uses real WebAuthn-shaped P-256
  signatures rather than a resolution-like demo envelope.
- Runtime roles cannot also act as contract parties. Provider and effect
  references are fenced to prevent substitution across actions or sessions.

### Distribution

- Gate now depends on `@emilia-protocol/verify` 3.11.0 and
  `@emilia-protocol/require-receipt` 0.6.1. All shipped imports remain within
  declared package boundaries.

## 0.10.0 (2026-07-16)

### Added

- The EMILIA Gate consequence-control plane, including action coverage,
  settlement, metering, deployment-attestation, network-witness, SIEM, and
  control-plane modules.
- A BYOC GitHub repository-deletion service with complete mediation, strict
  receipt ingress, durable Postgres action/consumption/evidence state,
  authenticated evidence reads, bounded readiness, graceful shutdown, and
  fail-closed recovery of interrupted effects.
- Helm, Terraform, Docker Compose, and SQL deployment assets for the BYOC
  service. Production assets require explicit non-latest images, separate
  runtime and migration credentials, and operator-owned trust configuration.

### Security

- Pinned issuer, approver, policy, actuator, meter, attestation, and
  network-witness trust roots are kept outside presenter-controlled evidence.
- Signed negative human decisions remain durable evidence but cannot satisfy
  authorization, signer, assurance, authority, quorum, or action-material
  predicates.
- Mobile approval and denial evidence is bound to the exact action, profile,
  presentation, app, device enrollment, RP, origin, and single-use challenge.
- A same-sequence network-witness conflict permanently poisons that exact
  witness/capture-point stream. Higher sequence numbers cannot restore trust;
  recovery requires an explicitly provisioned replacement stream identity.
- Ambiguous external effects burn their receipt and become `indeterminate`;
  Gate never retries a consequential effect whose outcome is unknown.

### Distribution

- Gate now declares the exact `@emilia-protocol/require-receipt` and
  `@emilia-protocol/verify` release bytes it imports. The verifier floor is
  `3.10.1`, which includes the signed-denial authorization fix.
- The npm package now carries this changelog and the Apache-2.0 license text.

## 0.9.2 (2026-07-06)

### Added
`EP-EXTERNAL-VERIFICATION-STATEMENT-v1` (`./reports/external-verification`): the
artifact a non-EMILIA verifier signs after checking EP evidence. It records a
procedure, inputs, result, and limitations under the verifier's own Ed25519 key,
and is accepted only by a relying party pinning that key together with the
verifier identity out of band. It does not authorize an action or certify
correctness. A turnkey harness for issuing one over a conformance run lives in
`examples/external-verification/`.

### Fixed
`./reports/external-verification` imported `canonicalize` from outside the
package root, which made the published tarball unloadable
(`ERR_MODULE_NOT_FOUND`) for every consumer, including the package main entry.
It now imports the byte-identical in-package `canonicalize`. A new
`package-boundary` test fails closed if any shipped module ever again resolves a
relative import outside the package root.

### Security
Verification hardening (fail-closed): a pin must name the `verifier_id` it
vouches for, so a pinned key can never validate a different claimed identity
(`pin_missing_or_mismatched_verifier_id`); `key_id` is derived from the carried
public key and a mismatched envelope `key_id` is refused (`key_id_mismatch`),
since the envelope is outside the signed bytes. Default statement limitations now
disclose that a statement carries no expiry and no consumer binding, is
replayable verbatim, and that `generated_at` is signer-asserted, not verified.
