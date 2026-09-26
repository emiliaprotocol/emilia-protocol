# @emilia-protocol/gate — EMILIA Gate

**Consequence admission for autonomous work.** Apply a native authorization
decision to one exact provider attempt, then keep custody until the outcome is
known.

OAuth, AuthZEN, AP2, and local systems keep their native credentials, mappings,
and policy decisions. Gate verifies the configured AEB evidence for the final
operation, applies the relying party's local authorization rule, reserves every
native replay identity before provider entry, refuses a second attempt at the
same canonical action and configured provider while an earlier attempt is
unresolved, and refuses blind retry after an uncertain result.

On an exclusively mediated path, an agent without sufficient current authority
cannot reach the configured executor for money, code, permissions, data,
infrastructure, energy, or physical state. That authority can be native or can
include an EMILIA receipt when local policy requires fresh human approval.

Gate is not an identity provider, a replacement PDP, or proof of a provider's
physical effect. Its prevention claim covers only configured paths the
deployment completely mediates.

For the native-evidence path, import the stable facade:

```js
import { createNativeConsequenceBoundary } from '@emilia-protocol/gate/aeb';
```

Both boundaries, `createNativeConsequenceBoundary()` and the composed
`createConsequenceBoundary()`, hold a durable same-action fence keyed by the
relying party ID (`pins.relying_party_id` or `aeb.config.relying_party_id`),
the provider coordinates exactly as configured (tenant, provider, provider
account, environment), and `digestAebNativeAuthorizationAction(action)`.
While an attempt for that key is reserved, invoking, or uncertain, a new
attempt is refused before provider entry as `native_action_in_flight`, even
with fresh authority and a fresh operation ID. After an executed result it is
refused as `native_action_already_executed`. The fence opens only on a
terminal FAILED outcome the boundary accepts, from the provider call or from
authorized reconciliation, or on a pre-entry stop the boundary proves from
the explicit not-entered marker in its own durable attempt record. Both
boundaries derive the same fence key, so they fence each other when they
share a consumption store and relying party ID.

Provider results must be in the strict canonical JSON domain: plain objects
and arrays, strings, booleans, null, and numbers that are safe integers. Both
boundaries snapshot the result with its evidence so that what was verified is
what is returned. A fractional number, a `Date` or other class instance,
`undefined`, a bigint, a function, or a cyclic value makes `run()` return
`INDETERMINATE` with `provider_outcome_invalid` after the provider call, and
the action then needs reconciliation. Encode amounts as integers or strings
in the invoke adapter's result.

Terminal evidence is verified for the attempt, the purpose of the check,
and the kind of evidence presented. Both boundaries require the operator's
provider-outcome verifier, `provider_outcomes.verify`:
`createNativeConsequenceBoundary()` and the composed
`createConsequenceBoundary()` throw at construction without it
(`native_consequence_boundary_configuration_invalid:
provider_outcome_verifier_required` and
`consequence_boundary_configuration_invalid:
provider_outcome_verifier_required`). The verifier receives the attempt
binding, the outcome, the attempt's provider idempotency key, and a
`purpose`: `provider_outcome` for a terminal result, or `pre_entry_lookup`
for the lookup presented to pre-entry recovery. The only answer Gate
accepts is an affirmation that restates what it checked, `{ verified: true,
purpose, attempt_id, provider_idempotency_key }`, exactly as the context
gave them. Any other answer, including a bare `true`, means "not verified",
and the result is `INDETERMINATE` with
`provider_outcome_authentication_failed`. An entered attempt closes as
EXECUTED or FAILED only on an affirmation of `provider_outcome` for that
attempt and its provider idempotency key. That holds on both boundaries,
for the result of the run's own provider call as well as for
reconciliation, so a provider adapter's unverified FAILED never releases
the fence.

Evidence presented to `reconcile()` carries its kind in Gate's own input:
an EXECUTED or FAILED outcome carries `evidence_kind`, `'provider_outcome'`
for a terminal outcome or `'pre_entry_lookup'` for a pre-entry lookup, and
is refused without it (`evidence_kind_required`); an INDETERMINATE outcome
carries no evidence and no kind. Terminal reconciliation refuses evidence
of kind `pre_entry_lookup`, and pre-entry recovery refuses evidence of kind
`provider_outcome`, before either calls the verifier
(`evidence_kind_mismatch`). A "not found" lookup presented
with its own kind therefore never becomes a terminal FAILED, even under a
verifier that only restates the context it is given. Gate cannot detect
mislabelled evidence or a verifier that affirms a purpose it did not
evaluate: a lookup presented as `provider_outcome` to a verifier that
restates the context, or always answers `provider_outcome`, still becomes a
terminal FAILED while the provider call may be in flight. The operator must
label evidence by what it is, and the verifier must check the evidence
against the purpose it is asked about.

Each boundary writes its attempt record before any record that occupies the
action key; the native boundary writes it before any reservation at all. The
native boundary keys all three of its reservations (operation, native
authority, fence holder) by its `boundary_id` and the attempt ID. The
composed boundary keys its fence holder the same way, but its evaluation
reservation is keyed by the evaluation, and successive attempts can present the same evaluation; it
commits that reservation for an attempt only while that attempt's own fence
holder is still held, which marks it as the reservation's owner, and
releases it only in the run that created it, after that run's record is
confirmed not entered and its holder is released. A call therefore never
releases, closes, or commits a reservation that another attempt holds.

An attempt that stopped before provider entry (a crash while reserved, a lost
acknowledgement on the move to invoking, a store error during a pre-entry
release) still holds the fence. Both boundaries recover it under one
contract:

- **Explicit not-entered marker.** Whenever Gate closes an attempt as not
  entered, through a run's own pre-entry stop or through recovery's
  linearizing transition, it writes the move to RELEASED with the evidence
  `{ kind: 'not_entered', attempt_id }` (`CONSEQUENCE_BOUNDARY_NOT_ENTERED`
  is the `kind`). Only that marker proves a pre-entry stop. Gate never infers
  "not entered" from a RELEASED record that lacks provider evidence: a
  RELEASED or COMMITTED record that carries neither the marker nor provider
  evidence, including one from an attempt store whose `state()` drops the
  evidence it was given, is unproven, and both reconciliation modes return
  `INDETERMINATE` with `attempt_record_unproven` and release nothing. An
  attempt store declares `notEnteredMarker: true` when it persists that
  evidence atomically with the transition and returns it from `state()`.
  The native boundary requires the declaration; the composed boundary reads
  `state()` only from a store that makes it.
- **Pre-entry recovery is a separate mode.** Call `reconcile()` for the
  attempt with `mode: 'pre_entry'`, a `recovery_authorization` that the
  attempt store's `recover()` accepts for that attempt, and the provider's
  answer: a "not found" lookup result as FAILED, or INDETERMINATE when the
  provider has no lookup. A lookup result carries `evidence_kind:
  'pre_entry_lookup'` and must be affirmed by `provider_outcomes.verify` as
  `pre_entry_lookup`. The two modes never fall through into each other.
  Terminal reconciliation, `mode: 'terminal'` and the default,
  returns `INDETERMINATE` with `pre_entry_recovery_required` for a record
  that is still RESERVED or carries the not-entered marker, and changes
  nothing. An EXECUTED claim in pre-entry mode is refused as
  `reconciliation_outcome_conflict` and releases nothing.
- **Linearization.** Recovery treats the attempt as not entered only when
  its own atomic transition of the attempt record from RESERVED to RELEASED,
  which writes the marker, succeeds (confirmed by a durable read where the
  attempt store has one, and otherwise answered with exactly `true`), or when
  the record is already RELEASED with the marker. That transition is the
  linearization point: afterwards the live run's move to INVOKING fails and
  the run does not call the provider. A run still reserving when recovery
  closes its record releases what it reserved, does not call the provider,
  and returns `REFUSED` with `attempt_released_by_recovery`. On the composed
  boundary that needs `attempts.store.state()` and `notEnteredMarker: true`:
  without them the run cannot tell recovery's transition from its own lost
  write, so it holds everything as `INDETERMINATE` with
  `attempt_start_unconfirmed`. If the record is
  already INVOKING or later, recovery returns `INDETERMINATE` with
  `recovery_lost_to_live_attempt` and releases nothing; if its transition
  cannot be confirmed while the record is still RESERVED, it returns
  `INDETERMINATE` with `attempt_release_unconfirmed`. The lookup it was
  given is pre-entry evidence only and is never used as a terminal outcome
  for an attempt that entered; that attempt needs terminal reconciliation
  with a provider outcome observed after entry.
- **Release ordering.** Gate releases or commits the fence holder and the
  attempt's other reservations only after the attempt record's not-entered
  or terminal transition has succeeded and been confirmed. After a confirmed
  not-entered transition, recovery releases the attempt's reservations (on
  the composed boundary, its fence holder), confirms each release, and
  returns `REFUSED attempt_never_entered_provider`, or
  `INDETERMINATE native_pre_entry_release_unconfirmed` when a release cannot
  be confirmed; repeating the call is safe. When a claim fails, recovery
  reads the row again, and a row that is already AVAILABLE counts as
  released, so a recovery that races the live run's own hand-back does not
  report a release as unconfirmed for a row that is gone; a claim that
  another recovery overtook is made again, at most three times. Terminal
  reconciliation verifies the presented outcome for the attempt first, then
  freezes an INVOKING record as INDETERMINATE and writes the terminal
  record, and only then consumes the reservations and releases or keeps
  closed the fence. An outcome the verifier rejects leaves the record as it
  was, so the live run can still finish it and a later reconciliation with
  verified evidence can still close it. If the terminal record cannot be
  written, every reservation stays held.
- **Lost acknowledgement.** If the run's move from RESERVED to INVOKING
  throws or answers anything but `true`, the run releases nothing on that
  basis and reads the durable record. INVOKING for this attempt means the
  write landed, and the run proceeds as the record's owner. RESERVED means it
  had not landed when read: the run closes the record as not entered
  through the same atomic transition, then releases and returns `REFUSED`
  with `attempt_start_conflict`. If a delayed start write lands before that
  close, the close fails; the run still never calls the provider, because it
  has sent a not-entered write, keeps its reservations, and returns
  `INDETERMINATE` (`native_pre_entry_release_unconfirmed` on the native
  boundary, `attempt_release_unconfirmed` on the composed boundary). The
  record then says INVOKING although the provider was never called, and it
  is closable only as the next item describes. RELEASED with the not-entered marker for this
  attempt means a pre-entry recovery linearized first: the run releases what
  it holds and returns `attempt_released_by_recovery`. Any other answer,
  including a RELEASED record without the marker, holds everything and
  returns `INDETERMINATE` with `attempt_start_unconfirmed`.
- **No provider call after a not-entered write.** A run that has sent any
  write that could record its attempt as not entered, including a write
  whose acknowledgement was lost, never calls the provider afterwards,
  whatever a later read shows: the write can still take effect after that
  read, and the record would then say "not entered" for an attempt that
  entered.
  An unreadable record is read again, up to three times. If a read shows
  INVOKING, the run proceeds as the owner; it has sent no not-entered write.
  If the record stays unreadable, the run sends no not-entered write at all:
  it holds every reservation, does not call the provider, and returns
  `INDETERMINATE` with `attempt_start_unconfirmed` and `invoked: false`.
  If its start write did not land, the record is still RESERVED and
  pre-entry recovery closes it as usual. If the start write landed, the
  record says INVOKING although the provider was never called; pre-entry
  recovery then answers `recovery_lost_to_live_attempt`, and the record is
  closable only by terminal reconciliation with provider evidence that
  forecloses any execution, now or later, under the attempt's provider idempotency key, such as an authenticated cancellation of that key by the
  provider. Whether the presented evidence establishes that is the
  verifier's decision, affirmed as `provider_outcome`; a "not found" lookup
  presented as `pre_entry_lookup` is refused in terminal mode. Without such
  evidence the action stays fenced, by design.
  A point-in-time "not found", even from an authenticated provider lookup,
  does not foreclose execution: a run that is still alive can deliver its
  call after the lookup.
- **Pre-entry stops report their own code.** Every pre-entry stop releases
  nothing until the record's not-entered transition is confirmed. When it
  cannot be confirmed, the native run returns `INDETERMINATE` with
  `native_pre_entry_release_unconfirmed` and the composed run returns
  `INDETERMINATE` with `attempt_release_unconfirmed`. A native stop whose
  first reservation was refused holds no row, so it returns `REFUSED` with
  that refusal's reason even when the transition was not confirmed; nothing
  it wrote fences the action.
  A reserve call that throws, or answers anything other than exactly
  `true` or `'RESERVED'` or a defined conflict (`false`,
  `'CONSUMPTION_CONFLICT'`, or `'NATIVE_REPLAY_CONFLICT'`), has an unknown
  effect, not a refusal. The run reads that row: `CONSUMED` or
  `RELEASED_NOT_ENTERED` proves this call wrote nothing and gives the
  conflict refusal; anything else, `AVAILABLE` included, counts the row as
  held, and after the run closes the attempt as not entered and hands its
  rows back the result is `INDETERMINATE` with
  `consumption_reservation_unconfirmed`, never a clean refusal. A write that
  lands later is released by pre-entry recovery, because the record carries
  the not-entered marker.
- **Only `true` or a durable read counts.** Where a store has a durable
  read, Gate decides each attempt-store transition and each
  consumption-store commit, release, and close by that read, never by the
  store's answer. Without a read, only an answer of exactly `true` counts,
  and a recovery claim always needs exactly `true`. Any other value,
  including a truthy object such as `{ ok: false }`, is a failure.
- **Composed boundary.** Pre-entry recovery on `createConsequenceBoundary()`
  releases only the attempt's fence holder. It never touches the evaluation
  reservation: a live run hands that back itself, and after a crash it stays
  reserved. That reservation also keeps the native replay fences of the
  mandate the evaluation carries, so a retry needs a fresh native
  authorization, not only a fresh evaluation. With `attempts.store.state()`
  and `notEnteredMarker: true` the not-entered transition is confirmed by a
  durable read; without them, only recovery's own transition answered with
  exactly `true` proves the stop. Without them, a stop that the run already
  closed as not entered but whose holder release then failed, or a run that
  lost its start to recovery, cannot be proven by a later recovery either,
  so that action stays fenced; provide `state()` with
  `notEnteredMarker: true` to recover those cases. A composed run whose
  attempt store has no `state()` and whose start write is unconfirmed
  cannot read the record, so it sends no not-entered write, holds every
  reservation, and returns `INDETERMINATE` with `attempt_start_unconfirmed`
  without calling the provider. A
  0.26.0-style attempt store without `state()` still gets terminal
  reconciliation, which verifies the presented outcome: Gate
  freezes an INVOKING record before the terminal write, and a RESERVED
  record fails both, so nothing is released for an attempt that never
  reached INVOKING. When the release of the evaluation reservation fails or
  cannot be confirmed at any refusal in `run()`, including the refusals
  that happen before the attempt record exists (an unkeyable fence binding,
  an envelope refusal, attempt-ID allocation, and an attempt-store reserve
  that refuses or throws), the result is `INDETERMINATE` with
  `evaluation_release_unconfirmed`, not a clean refusal; a reservation of
  the evaluation whose outcome is unknown is `INDETERMINATE` with
  `consumption_reservation_unconfirmed`. Gate has no recovery path for an
  evaluation reservation left RESERVED with no attempt record, and none is
  safe without a new durable marker: nothing durable tells a crashed run
  apart from a live run that has not yet written its attempt record, and
  releasing the reservation would let that live run enter the provider
  after a second run of the same evaluation had already entered and
  FAILED, spending one evaluation twice. That evaluation and the native
  mandate it carries stay fenced, so a retry needs a fresh evaluation over a
  fresh native authorization.

The fence compares the canonical action digest and the provider coordinates
exactly as configured. Gate implements no material-field inventory and no
equivalence between spellings: `"500"` and `"500.00"`, `"USD"` and `"usd"`,
trailing whitespace, and NFC versus NFD strings are different actions, and two
boundaries configured with `account:one` and `Account:One` for one real
account do not share a fence. Canonicalize amounts, case, whitespace, and
Unicode normalization before building the action, put only material fields in
it, and configure identical coordinates on every boundary instance that can
reach one provider account. Intentional repeats must differ in the canonical
action, for example through an instance field fixed when the action is
authorized.

The native replay identity is derived from the relying-party-pinned authority
namespace and the native authorization ID. The namespace is the issuer unless
the pin declares `authority_namespace`, in which case the issuer string is not
an input. The `system` and `profile` labels are never inputs, so one grant
accepted under two pinned labels is spent once. Gate reserves the identity key
(`replay_identity_key` from `@emilia-protocol/verify`) and, beside it, the
verify 4.1.0 `replay_key` for every `system` and `profile` label, with its
issuer spelling, that the pin set accepts under the grant's authority
namespace, not only for the label the grant was presented under. A grant that
gate 0.26.0 consumed under one label is therefore refused under any other
label still pinned in that namespace after an upgrade. That legacy fence
covers only the labels and spellings pinned now: removing a label that 0.26.0
accepted lets a grant consumed under it be admitted under another label, so
keep every such label and spelling pinned until the grants consumed under it
have expired or been revoked.
One issuer has one namespace in a pin set. Pins whose issuer strings are
identical, or are spellings the verifier normalizes as equal (URI scheme case,
URL host case, trailing dots on the host, a default port, trailing slashes,
dot segments in the path, an http or https URL written without `//`, URN
namespace-identifier case, DID method-name case, `did:web` host case and
trailing dots, and SPIFFE trust-domain case and trailing dots),
must either all omit `authority_namespace` and use one identical issuer
string, or all declare the same `authority_namespace`. Normalization cannot
find every alias: two issuer strings that denote one authority but do not
normalize equal need one explicitly shared namespace. A pin set that declares
two different namespaces for one issuer, mixes declared and default namespaces
for it, or spells it two ways without one shared declared namespace is
refused: `createNativeConsequenceBoundary()` throws
`native_consequence_boundary_configuration_invalid: <native_pins_* reason>` at
construction. Changing a pin's namespace changes the replay identity. The
4.1.0 keys do not depend on the namespace, so the same grant is still refused
while a label and issuer spelling whose 4.1.0 key was reserved when it was
consumed stays pinned in its namespace, but not when it is presented only
under labels and spellings outside that set. Drain in-flight attempts and let
grants consumed under the old namespace expire first.

**Upgrading from gate 0.26.0.** A mixed fleet is unsafe. A 0.26.0 boundary,
native or composed, has no same-action fence and does not reserve the
label-free identity key, so while 0.26.0 and this release serve one
consumption store, an action in flight on either version can be executed
again through a fresh permit on the other, and a grant consumed by this
release can be admitted again by 0.26.0 under another pinned label. Upgrade
in this order, and never roll an upgrade across 0.26.0 and this release:

1. Stop every gate 0.26.0 boundary that uses the store, and drain or
   reconcile its in-flight attempts on 0.26.0, with the provider-outcome
   verifier that 0.26.0 already uses. A 0.26.0 native boundary counts only
   a verifier answer of exactly `true`, so a verifier that returns the new
   affirmation fails every 0.26.0 run and reconciliation, and the drain
   cannot finish. Finish on 0.26.0 any pre-entry stop whose rows it did not
   release as well: 0.26.0 wrote those records RELEASED without the
   not-entered marker, so this release reports them
   `attempt_record_unproven` and releases nothing for them.
2. Only then deploy the new provider-outcome verifier, the upgraded attempt
   stores, and this release together. Never deploy the new verifier while
   any 0.26.0 boundary still serves.

The executed-action fence is not retroactive. Gate 0.26.0 wrote no fence
row for the actions it completed, so this release admits fresh authority
for an action that 0.26.0 already executed; only actions executed after
the upgrade are refused as `native_action_already_executed`. Grants that
0.26.0 consumed stay refused as described above.

The native boundary needs a durable, ownership-fenced consumption store that
also exposes a durable `state()` read. The PostgreSQL store from
`createPostgresAebDurableConsumptionStore()` provides that read. Its commit
and release are fenced to the reserving store instance, so after a restart
`reconcile()` claims the attempt's reservations through `claimReservation()`
with the caller's `recovery_authorization`: the operation, native-authority,
and action-fence-holder rows on the native boundary, and the evaluation
reservation and the holder on the composed boundary.
Each claim carries a `scope` of `{ boundary, boundaryId, attemptId,
operationId, recoveryOperationKey, reservation }`, where `boundary` is
`'native'` or `'composed'` and `boundaryId` is the boundary's configured
`boundary_id`. A scope derives only the rows of its own boundary kind and
boundary ID, so two boundaries that share one store, of different kinds or
of the same kind, never name each other's rows, even when their attempt IDs
are identical. `authorizeRecoveryClaim` receives the validated scope and
`attemptIdentity`, which is `consequenceBoundaryRecoveryAttemptIdentity(scope)`:
`native:<boundaryId>:<attemptId>` or `composed:<boundaryId>:<attemptId>`. A
recovery credential is bound to exactly one attempt: bind it to
`attemptIdentity`, together with the tenant and relying party it was issued
for. Never bind it to `scope.attemptId` alone, which attempts of other
boundaries on one store can share, and never to
`scope.recoveryOperationKey` or to an operation ID: every attempt that
reuses one operation ID for the same action (native), or presents the same
evaluation (composed), shares that key, so a credential bound to it would
authorize claims across attempts. `scope.operationId` is caller-asserted:
the store checks that the scope's boundary kind, boundary ID, attempt ID,
recovery operation key, and reservation derive the claimed row, but it never
checks `operationId` against that row, so an authorizer must not rely on
it. Before the authorizer runs, the store
refuses a claim without a scope (`recovery_claim_scope_required`), a
malformed scope (`recovery_claim_scope_invalid`), a claim whose key is not
the row that the scope names for its attempt
(`consequenceBoundaryRecoveryClaimKey(scope)`; `recovery_claim_key_mismatch`),
and a claim on the composed evaluation reservation, which several attempts
share, unless the scope's attempt still holds its fence-holder row
(`recovery_claim_owner_marker_absent`), as well as a row this store
instance already owns (`recovery_claim_already_owned`); after the
authorizer, a refused credential is `recovery_claim_unauthorized` and a row
that is no longer RESERVED is `recovery_claim_row_not_reserved`.
`claimReservationResult()` returns the refusal reason; `claimReservation()`
returns only whether the claim succeeded. A database error rejects either
call, so a caller fails closed. Attempt IDs must be unique per attempt: a custom
`attempts.create_id` must never return an ID twice within one boundary.
Every boundary configures a required `boundary_id`: 1 to 128 letters,
digits, `_`, `.`, or `-`, starting with a letter or digit, with no `:`;
anything else is refused at construction (`boundary_id_invalid`). Replicas
that serve one attempt store must use the same `boundary_id`; boundaries with
different attempt stores that share one consumption store use different
values. The attempt record does not carry the boundary ID, so a replica
configured with a different one derives other reservation keys: its
pre-entry recovery of another replica's attempt can mark the record not
entered while the real rows stay RESERVED, and the action stays fenced until
recovery runs through a boundary with the original `boundary_id`. Keep it
unchanged for as long as the boundary's attempts may still need
reconciliation. The attempt
identity and every attempt-keyed reservation include it, so two such
boundaries cannot collide even when their attempt IDs are identical. The
action fence key does not include it, so every boundary at one provider
still fences the same action. One credential bound to the attempt covers every
reservation the attempt holds, so restart reconciliation completes in one
call. Gate 0.26.0 shipped the PostgreSQL store without `state()`; existing
databases need the `ep_aeb_private.operation_state` function from
`supabase/migrations/20260925010000_aeb_operation_state.sql`.

This direct path follows AEB-06, which was posted on 2026-09-24 as an
individual Internet-Draft and is not adopted by any working group. AEB-06 makes
CAID conditional on a cross-format join and AEC conditional on a multi-leg
evidence requirement. The signed gateway handoff and the same-action fence are
repository implementation profiles that AEB-06 does not specify; a staged -07
candidate that specifies the fence has not been submitted. The named
source labels and same-repository vectors do not establish native-protocol
conformance or independent interoperability.

See the [consequence-admission boundary](../../docs/protocol/consequence-admission.md)
for the division of responsibility between the native authorization system,
optional CAID/AEC composition, AEB custody, and provider outcome evidence.
The [direct native handoff profile](../../docs/protocol/aeb-native-authorization-handoff-v1.md)
defines the signed permit binding and operator-controlled status lookup.
`createConsequenceBoundary()` remains available for deployments that need the
composed CAID/AEC path; it also holds the same-action fence.

The original Receipt Required guard remains available for deployments whose
policy specifically requires an EMILIA approval receipt.

## Receipt guard

### Run it

```bash
node --test                       # Gate + red-team + EG-1 + MCP + adapter tests
node demo.mjs                     # end-to-end: passthrough -> 428 -> too-low -> drift -> allow -> replay -> tamper -> reliance packet
node eg1.mjs                      # EG-1 conformance: 8/8 -> "EG-1 Enforced"
node adapters/github-demo.mjs     # an agent tries to delete a prod repo (refused without a receipt)
node custody-demo.mjs             # rotate, revoke a compromised issuer key live, retention export
```

### Use it

```js
import { createTrustedActionFirewall } from '@emilia-protocol/gate';

const gate = createTrustedActionFirewall({
  trustedKeys: [ISSUER_PUBKEY_B64U], // pin the issuers you trust
  store: sharedConsumptionStore,      // durable + ownership-fenced + permanent
  maxAgeSec: 900,
});

// Facts from the system of record, not from attacker-controlled request input.
const observedAction = {
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_123',
  beneficiary_account_hash: 'sha256:...',
};

const out = await gate.run({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  receipt,
  observedAction,
}, async () => {
  // Only reached after receipt verification, assurance enforcement, field
  // binding, and one-time reservation.
  return releasePayment(observedAction);
});

if (!out.ok) throw out.body; // 428 Receipt Required
console.log(out.packet.verdict); // "rely"
```

### Activate a self-service protection plan

Build and download a plan at `https://www.emiliaprotocol.ai/protect`, then sign
that exact plan locally with a customer-owned Ed25519 key:

```bash
npx --package @emilia-protocol/gate@0.28.0 ep-protect activate plan.json \
  --private-key owner.pem \
  --tenant my-tenant \
  --gateway my-mcp-gateway \
  --authorizer my-owner \
  --key-id owner-key-1 \
  --out activation.json
```

The command refuses duplicate-member JSON, incomplete context, non-Ed25519
keys, and overwriting an existing output. The signed activation is gateway
configuration, not per-action authority and not proof that a connector is
installed. The customer-owned MCP composition is runnable at
`examples/customer-owned-mcp-gateway`.

### Seal reviewed handlers at trusted startup

`runRegistered()` removes the caller-supplied callback from the execution
request. The application registers reviewed handlers during trusted startup,
seals the registry, and Gate resolves the handler from its pinned manifest.
The selector must come from the local adapter or route, not from agent content.

```js
import {
  createGate,
  createProtectedActionRegistry,
} from '@emilia-protocol/gate';

const actions = createProtectedActionRegistry();
actions.register(
  'payment.release',
  (parameters) => typeof parameters?.payment_instruction_id === 'string',
  (parameters) => paymentProvider.release(parameters),
);
actions.seal();

const out = await gate.runRegistered({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  receipt,
  observedAction,
}, actions);
```

The registry is not a second policy engine. It does not select actions from
agent-provided names, transform parameters, or consume authority itself.
Validation and an immutable parameter snapshot occur before reservation. The
existing Gate path then reserves authority before provider entry, commits it
after a returned effect, and records an attempted-but-unknown effect as
`INDETERMINATE`. `run(fn)` remains available for existing integrations.

### Reserve aggregate consequence capacity

`@emilia-protocol/gate/consequence-envelope` adds an optional signed capacity
reservation before provider entry. One owning state domain atomically accounts
for a relying-party-defined conservative impact contribution. Capacity never
refills from a timer, and disconnected operation requires a preissued,
epoch-bound, nonrenewable slice already deducted from the parent.

The bundled memory store is explicitly test-only. Production callers must
supply a durable, owner-fenced, epoch-fenced local-atomic store. An uncertain
provider outcome keeps capacity unavailable until separately authenticated
reconciliation establishes commitment or non-commitment. Telemetry and anomaly
models cannot mint capacity, and no envelope record proves a physical effect.

## Customer-owned Reliance Programs

`@emilia-protocol/gate/reliance-program` turns a relying party's signed policy
source into the existing Gate Trust Program wire format. It does not add a
second authorization engine. An Admissibility Profile remains the acceptance
bar for one evidence role; a Reliance Program composes those hash-pinned bars
across stages and selects exactly one consequence owner.

```js
import {
  compileRelianceProgram,
  createAdmissibilityProfileTrustAdapter,
  signRelianceProgram,
} from '@emilia-protocol/gate/reliance-program';
import {
  createRelianceProgramCompilationRecord,
  renderRelianceProgramCompilationRecord,
} from '@emilia-protocol/gate/reliance-compilation-record';

const signed = signRelianceProgram(customerOwnedSource, rpPrivateKey);
const compiled = compileRelianceProgram(signed, {
  trustedKeys: {
    'rp-key-1': {
      relying_party_id: 'payer:example',
      public_key: rpPublicKey,
    },
  },
  profiles: relyingPartyPinnedAdmissibilityProfiles,
});

// Package the exact source-to-Gate mapping for institutional review. A
// reviewer recompiles independently and verifies this record against the
// reproduced compiler result. The record is not authority or execution proof.
const compilationRecord = createRelianceProgramCompilationRecord(compiled);
const reviewMarkdown = renderRelianceProgramCompilationRecord(compilationRecord);

// `compiled.program` is EP-GATE-TRUST-PROGRAM-PROFILE-v1.
// The adapter runs the already-shipped profile evaluator under a constructor-
// pinned profile; the presenter supplies evidence, never policy or trust roots.
const verifier = createAdmissibilityProfileTrustAdapter({
  profile: relyingPartyPinnedAdmissibilityProfiles[0],
  evaluate: evaluateAdmissibilityProfile,
  project: projectVerifiedPrincipalsAndTimes,
  now: () => new Date().toISOString(),
});
```

The signed source, its `source_digest`, the compiled `program_digest`, and the
compiler trace remain distinct. Compilation proves a deterministic policy
mapping; it does not prove that evidence is sufficient, authorize an action, or
claim an external effect occurred.

## Trusted Context Pack

`@emilia-protocol/gate/trusted-context` controls the boundary between
persistent agent memory and one consequential action. A provider verifies its
native memory semantics and emits a signed, digest-only projection. Gate binds
that projection to the exact proposed action under a relying-party policy;
`ep-memory-projection` may then satisfy one AEC evidence role. It never becomes
authorization by itself.

```js
import {
  createTrustedContextAecVerifier,
  createTrustedContextEvaluator,
  signTrustedContextBinding,
} from '@emilia-protocol/gate/trusted-context';
import {
  createApertoMemoryContextProvider,
} from '@emilia-protocol/gate/trusted-context/apertomemory';
```

The runtime artifact contains signed projection and action-binding records,
object/fragment digests, keyring and policy commitments, and exclusion counts.
It does not carry decrypted memory. Current implementation details and claim
boundaries are in `docs/protocol/trusted-context-pack-v1.md`.

## Gate Qualification v2

Gate Qualification v2 treats model or agent qualification as one input to a
consequence-owning Gate. Qualification never substitutes for AEB, AEC, or the
relying party's local authorization policy.

```js
import {
  GateQualificationV2,
  composeQualificationDecisionV2,
  createMemoryInvocationAuthorityCustodyV2,
} from '@emilia-protocol/gate/gate-qualification-v2';
import {
  createAdmissionSnapshot,
  createMemoryAdmissionStore,
} from '@emilia-protocol/gate/admission-store';
import {
  createAdmissionPostgresStore,
} from '@emilia-protocol/gate/admission-store-postgres';
```

`composeQualificationDecisionV2()` is pure and non-mutating. In enforcement
mode, `GateQualificationV2` requires matching qualification, AEB, AEC, and
local-policy legs. It requires an authoritative invocation remeasurement and
protected restart-safe capability custody, then atomically consumes authority
before entering a caller-supplied protected adapter. Provider commitment and observed effect remain separately
authenticated facts; an uncertain outcome stays reconciliation-required and
cannot be retried as fresh work.

`createMemoryAdmissionStore()` is a test-only, non-durable, single-process
reference for the unified immutable snapshot, CAS-owned lifecycle, operation
and resource fencing, journal, supersession, and remedy contracts.
It refuses `beginInvocation()` without an explicit currentness oracle;
`createMemoryInvocationAuthorityCustodyV2()` is likewise test-only and
non-durable.
`GateQualificationV2` consumes that canonical `AdmissionStore` contract and
requires both a durable production store and durable protected authority
custody unless explicitly constructed for tests.

`createAdmissionPostgresStore()` is a deployment-bound, locally atomic and
durable adapter to an externally installed PostgreSQL RPC contract. Each store
instance is bound to exactly one deployment and one tenant. This public
reference does not provide or claim managed tenant-principal mapping, a
deployment migration, cross-tenant operation, federated atomicity, or managed
service operation; callers remain responsible for database roles, RPC
installation, backups, monitoring, and recovery procedures.

For an execution-program admission, a durable orchestrator should create and
custody an owner capability first, then call
`reserveExecutionProgramAdmissionWithPreparedOwnerToken()`. Gate atomically
binds that exact capability to the reservation, closing the process-death
window between reservation and local custody. The ordinary `reserve()` API
still creates its owner token internally; if a worker using that path dies
before custody, the token may be unrecoverable. The store therefore exposes
`reapExpiredReservation({ tenant_id, admission_id, expected_revision })` and
the SQL contract exposes `ep_gate_admission_reap_expired`. That dedicated RPC
has no owner-token argument. It succeeds only after the immutable admission
deadline, only from `RESERVED / NOT_ENTERED`, and only at the exact revision
under the admission row lock. For an execution-program admission it also
atomically releases the occurrence and its reserved program budget. It releases
non-monotonic resource fences, retains the permanent operation head and
monotonic counter advance, and appends
`ABANDONED_BEFORE_INVOCATION` so an unused counter value is explainable.
Anything at `INVOKING` or later remains frozen for indeterminate recovery and
cannot be reaped. Grant EXECUTE on the recovery RPC only to a narrowly scoped
reaper role; ordinary runtime roles do not need it.

Bounded-program callers that must survive a process death at provider entry
SHOULD generate and durably custody an invocation token before consumption,
then call `beginExecutionProgramInvocationWithPreparedToken()`. The store
atomically binds that token digest while preserving the same current-status,
reachability, occurrence, concurrency, and budget checks as
`beginExecutionProgramInvocation()`. The plaintext token never enters the
database and remains the caller's reconciliation authority.

A `QUALIFIED` verifier result by itself is non-authorizing. It does not grant
permission, reserve or consume authority, invoke a provider, or establish
legality or business suitability.

`@emilia-protocol/gate/fido-ap2-bridge` supplies pure builders for the closed,
immediate AP2 v0.2 profile. The caller supplies evidence; a separate
server-owned controls object supplies the trusted clock, pinned AEB config,
authenticated status resolver, tenant/RP/audience/actors, exact canonical AP2
tokens, native-verifier-returned payloads, current WebAuthn counter head, final
provider-request bytes, and pinned provider adapter. Gate derives the checkout
hash algorithm from the exact issuer token and independently reprojects the
native payloads at admission; the claimed human-action object is not used as
its own expected value. The adapter
must prove that those exact bytes carry the exact PaymentMandate token. The
builders then retain the full signed AEB evaluation and derive replay,
provider-operation, status-head, and monotonic WebAuthn-counter resources.

The returned admission input is a recursively frozen clone. Immediate AP2
execution is represented by an omitted `execution_date`, as required by the
pinned v0.2 schema; schema-invalid `null` optionals fail closed upstream.

Request-side trust configuration, status maps, clocks, actor identities,
provider adapters, provider bytes, and reservation identifiers are not
accepted. The builders do not reserve state, hold provider credentials, invoke
a payment service, or reconcile an effect. The result must still pass Gate
Qualification v2 remeasurement and AdmissionStore `beginInvocation()` before
the protected adapter may enter the provider. The durable AdmissionStore is the
sole one-time authority-custody boundary.
Its memory and PostgreSQL implementations compare and advance the credential
counter atomically with successful `reserve()` and recheck the durable head at
`beginInvocation()`; duplicate or rolled-back counts fail closed. A trusted
enrollment or recovery path must provision the initial head first
(`initialMonotonicCounterHeads` for the test-only memory store, or the
operator-only `ep_gate_provision_monotonic_counter` SQL function). A request
cannot create or replace its own counter baseline, and release never lowers a
committed head.

The explicit `not-relied-upon` WebAuthn policy is
available for zero-counter platform passkeys: it makes no counter-based clone
detection claim and emits no monotonic-counter reservation, while retaining UP,
UV, exact-action, assertion-replay, native-token, and provider-operation
reservations plus one-time admission. The default strict policy remains
`above-enrollment-and-one-time`.

## Bounded execution programs

The cross-module runtime composition is documented in
[`Conserved Authority Runtime v1`](../../docs/protocol/conserved-authority-runtime-v1.md).
It combines exact authority, sibling allocation, bounded capabilities, signed
execution programs, credential-owning provider entry, and uncertainty without
claiming cross-domain conservation.

`@emilia-protocol/gate/bounded-execution-program` defines and verifies one
signed, closed DAG of bounded autonomous actions. Each node pins either an
exact CAID and action digest or a relying-party-pinned matching profile, one
Trust Program digest, terminal predecessor outcomes, an occurrence ceiling,
and charges against aggregate program budgets. The artifact also binds the
subject, objective, authorization-evidence and presentation byte commitments,
audience, validity window, and explicit supersession lineage.

```ts
import {
  signBoundedExecutionProgram,
  verifyBoundedExecutionProgram,
  type BoundedExecutionProgramInput,
} from '@emilia-protocol/gate/bounded-execution-program';
import {
  createMemoryAdmissionStore,
  type ExecutionProgramAdmissionStore,
  type ExecutionProgramRuntimeState,
} from '@emilia-protocol/gate/admission-store';
```

The program-aware `ExecutionProgramAdmissionStore` extends, rather than
replaces, the ordinary `AdmissionStore`. A standalone admission still owns one
immutable operation snapshot, its resource reservations, execution right, and
provider outcome. A program-linked admission must use the program-aware
reserve, begin, release, and expiry methods so DAG reachability, occurrence
limits, typed program budget charges, and the signed concurrent-effect ceiling
change in the same linearizable domain as the execution right. `INDETERMINATE`
continues to occupy a concurrency slot until reconciliation. The memory
implementation remains test-only and makes no durability or deployment claim.

Registration fences the program's exact `authorization_digest`, preventing an
ordinary admission under the same root authorization from bypassing the graph.
Each program reservation also derives an `execution_program` resource binding
over the tenant, program digest, node, occurrence, and admission expiry and
seals it into the immutable AdmissionSnapshot. Missing or substituted bindings
fail closed. An admission based on genuinely separate authorization remains an
independent decision.

The adjacent surfaces remain separate:

- The Autonomy Control Plane compiles a closed, human-rooted policy into a
  Trust Program for each exact child action; it is not the runtime DAG ledger.
- A Trust Program governs the staged, parallel, or quorum evidence ceremony
  for one action. A bounded execution node pins its digest but does not weaken
  or replace that action's evidence requirements.
- A bounded capability receipt carries scoped, budget-backed authority for an
  action occurrence and is reserved before provider entry. An execution
  program orders eligible occurrences and accounts aggregate program charges;
  it neither mints capability authority nor replaces any capability receipt
  that the relying party requires.
- Authority-allocation snapshots separately bind `max_active_children` for one
  parent and refuse a wider same-domain sibling set. This is a bounded
  allocation count, not proof that every registered child process is still
  alive. Money, action occurrences, compute, and other consumable dimensions
  remain typed budgets; concurrent effects remain a separate signed ceiling.
- Signature and schema verification establish only the program's typed
  bindings. They do not prove intent, goal safety, provider or effect truth,
  complete mediation, or that any node is authorized or executed.
- The Ed25519 program signature identifies the relying party's pinned
  program-authorizer. Human approval remains separately verified evidence—such
  as a WebAuthn/P-256 ceremony—bound by the program's authorization and
  presentation digests.
- A constructor-pinned program-status oracle is mandatory for program
  registration and is rechecked before reservation and provider entry. Stale,
  unavailable, or absent status fails closed. This package
  defines the checked observation shape, not a portable signed status artifact
  or the trustworthiness of the deployment's status source. Work already past
  provider entry is reconciled, not erased.

`@emilia-protocol/gate/bounded-execution-report` turns one verified program and
one transactionally consistent `readExecutionProgramReportSnapshot` result
into a canonical, signed point-in-time program-to-date report. The snapshot
contains the runtime state, every retained occurrence for the exact tenant and
program digest, and a deterministic SHA-256 marker, bounded by the signed
`max_total_occurrences`. The report separates terminal recorded outcomes,
unresolved post-entry attempts, pre-entry releases, and never-attempted node
capacity; binds aggregate budget use and supersession state; and can be
reverified offline under relying-party-pinned report keys. A `RELEASED`
occurrence remains in retained history and consumes program-wide retained
inventory, but does not occupy reusable per-node occurrence capacity.

The report covers Gate-recorded program occurrences only. It does not prove
external effect truth, event chronology, program safety, complete mediation,
or the absence of actions executed outside Gate. That population-completeness
claim requires a separately signed external Inventory Root and is intentionally
outside this package. The checked-in report vectors are same-team experimental
reference vectors, not independent or cross-language conformance evidence.

`@emilia-protocol/gate/bounded-execution-acceptance` adds the separate
relying-party question the program and report intentionally do not answer: do
the recorded outcomes satisfy this party's signed acceptance profile? The
profile pins the exact program digest, accepted runtime statuses, unresolved
and reserved occurrence ceilings, and required node outcomes. Its offline
verifier returns `RECORDED_PROCESS_ACCEPTED`,
`RECORDED_PROCESS_NOT_ACCEPTED`, or `INDETERMINATE` and can assemble the signed
profile, signed report, and deterministic evaluation into one portable
evidence pack. It does not emit a `compliant` boolean or claim legal
compliance, external effect truth, program safety, or complete mediation. See
[`EP-BOUNDED-EXECUTION-ACCEPTANCE-PROFILE-v1`](../../docs/protocol/bounded-execution-acceptance-v1.md).

### Install the Gate Qualification v2 SQL artifact

Pin the package artifact to `@emilia-protocol/gate@0.28.0` and verify the exact
shipped migration before applying it. The SHA-256 below identifies this source
artifact; it is not a statement that the migration is already deployed:

```bash
GATE_SQL_PATH=node_modules/@emilia-protocol/gate/sql/gate-qualification-v2.sql
test "$(node -p "require('./node_modules/@emilia-protocol/gate/package.json').version")" = "0.28.0"
printf '%s  %s\n' \
  'e9b55e29c90cf7061bd62a8afd7c97402927e1eeb87649d4a38952a4b08df6b3' \
  "$GATE_SQL_PATH" | shasum -a 256 -c -
```

Apply it with `ON_ERROR_STOP` as the database owner, or as a migration role
that can create `pgcrypto`, tables, triggers, and `SECURITY DEFINER` functions:

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$GATE_SQL_PATH"
```

The migration revokes `PUBLIC` execution from every Gate helper and RPC. Keep
those revocations in place. Use two independently credentialed service roles:

- `emilia_gate_runtime` owns ordinary admission lifecycle and read access. It
  MUST NOT execute RPCs that accept a verified program, profile `MATCH`, or
  status assertion.
- `emilia_gate_verifier_service` is an isolated verifier service. It verifies
  Ed25519 programs, action-profile evidence, and signed status under pinned
  trust roots before invoking the four assertion-bearing RPCs.

The SQL deliberately does not verify Ed25519 inside PostgreSQL. Structural
checks in those RPCs are defense in depth, not cryptographic authentication.
Configure the adapter with two database pools so `query` uses the runtime
credential and `executionProgramVerifierQuery` uses only the verifier-service
credential. Never point both options at the same pool or database role.

As the database owner, grant schema use to both roles, then grant the normal
lifecycle/read surface only to the runtime role (replace both example role
names with deployment-specific roles):

```sql
GRANT USAGE ON SCHEMA public TO emilia_gate_runtime, emilia_gate_verifier_service;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_reserve(text,text,jsonb,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_release(text,text,text,bigint,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_expire(text,text,text,bigint,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_supersede(text,text,text,bigint,text,jsonb,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_begin_invocation(text,text,text,bigint,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_recover_indeterminate(text,text,text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_record_provider_outcome(text,text,text,bigint,text,text,text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_record_effect_relation(text,text,text,bigint,text,text,text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_read(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_read_by_operation(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_read_snapshot(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_journal(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_admission_check_invariants(text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_release_admission(text,text,text,bigint,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_expire_admission(text,text,text,bigint,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_read(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_read_by_admission(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_read_report_snapshot(text,text,text) TO emilia_gate_runtime;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_read_occurrence(text,text,text,text) TO emilia_gate_runtime;
```

Grant only the assertion-bearing surface to the verifier service:

```sql
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_register(text,text,text,jsonb,jsonb,text) TO emilia_gate_verifier_service;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_reserve_admission(text,text,text,text,text,jsonb,jsonb,text,jsonb) TO emilia_gate_verifier_service;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_begin_invocation(text,text,text,bigint,text,text,jsonb) TO emilia_gate_verifier_service;
GRANT EXECUTE ON FUNCTION public.ep_gate_execution_program_supersede(text,text,text,jsonb,jsonb,text) TO emilia_gate_verifier_service;
```

```ts
const store = createAdmissionPostgresStore({
  query: runtimePoolQuery,
  executionProgramVerifierQuery: verifierServicePoolQuery,
  deploymentId,
  tenantId,
  executionProgramVerificationPolicy,
  executionProgramStatusOracle,
  executionProgramActionMatchVerifier,
});
```

Neither role needs table privileges or helper-function grants. Granting these
RPCs establishes database access only; it does not establish deployment,
complete mediation, external effect truth, or production evidence. A missing
status oracle fails closed as `program_status_indeterminate`; PostgreSQL uses
`clock_timestamp()` at mutation time for status expiry and maximum-age checks.

## Proposal to effect

`@emilia-protocol/gate/proposal-to-effect` closes the loop from an agent's
proposal to a controlled consequence without minting another authorization
format. The proposal is an unsigned, short-lived request; authority remains in
`EP-RECEIPT-v1` and the relying party's pinned AEB requirement.

```js
import { createProposalToEffect } from '@emilia-protocol/gate/proposal-to-effect';
import { createProposalToEffectPostgresStore } from '@emilia-protocol/gate/proposal-to-effect-postgres';

const controller = createProposalToEffect({
  gate,
  proposal_integrity: { hmac_sha256_key: serverHeld32ByteKey },
  consequence: {
    tenant_id: tenantId,
    provider_id: providerId,
    provider_account_id: providerAccountId,
    environment,
    executor_id: executorId,
    store: durableConsequenceAttemptStore,
  },
  profiles: {
    'payment-release': {
      id: 'payment-release',
      action_type: 'payment.release',
      selector: { protocol: 'mcp', tool: 'release_payment' },
      required_fields: [
        'action_type', 'amount_usd', 'currency',
        'payment_instruction_id', 'beneficiary_account_hash',
      ],
      authorization: {
        authorization_endpoint: 'https://authorize.example/v1/approvals',
        flow: 'EP-APPROVAL-v1',
      },
      aeb_requirement_ref: 'requirement:payment-release',
      ttl_sec: 300,
      canonicalize_action: deriveCanonicalPaymentActionAndCaid,
    },
  },
  aeb: {
    config: pinnedAebConfig,
    adapters: pinnedAebAdapters,
    store: durableOperationStore,
    resolve_artifacts,
    currentStatusResolver,
    statusVerifier,
    verify_provider_evidence,
  },
});

const proposal = controller.prepare({
  proposal_id, profile_id: 'payment-release', operation_id,
  initiator_id: authenticatedAgentId, action: paymentFromSystemOfRecord,
});

const result = await controller.execute(
  { proposal, receipt, evaluation: signedAebEvaluation },
  ({ action }) => paymentProvider.release(action),
);
```

The controller re-verifies the signed AEB evaluation, runs Gate policy,
reserves the operation before invoking the effect, and consumes it after
success. An uncertain provider result remains reserved; only authenticated
provider evidence bound to the same operation, CAID, and action digest can
reconcile it. Owner capabilities are not serialized in results or errors;
same-process services retrieve them with `getReconciliationHandle(object)`,
while restarted services use the PostgreSQL store's authorized recovery path.
Production PostgreSQL wiring uses different executor and recovery pools. Each
database login is explicitly bound to a tenant and receives only its matching
non-login group role; `service_role` receives neither RPC surface. Recovery is
possible only after the database lease is stale, rotates the owner capability,
and preserves `INDETERMINATE` whenever provider execution may have started.
`repairAeb()` converges a durable terminal attempt with a stranded AEB
reservation without invoking the effect again. See
[`docs/protocol/proposal-to-effect-profile-v1.md`](../../docs/protocol/proposal-to-effect-profile-v1.md)
and run `node examples/proposal-to-effect/demo.mjs` from the repository root.

The AEB consumption store has its own disjoint PostgreSQL credentials:
`createPostgresAebDurableConsumptionStore()` requires an `ep_aeb_executor`
pool and a physically distinct `ep_aeb_recovery` pool. Each login must be
listed for the tenant in `ep_aeb_private.tenant_principals`. Neither runtime
role receives table privileges; reserve, commit, release, recovery claim, and
the operation-state read are narrow security-definer functions, and the state
read is granted to `ep_aeb_executor` only. Supabase `service_role` receives no
table, schema, or function authority. Remedy case sets use the same custody
shape through a tenant-bound `ep_remedy_executor` login and
`ep_remedy_private.tenant_principals`.

## Recovery admission

The experimental `@emilia-protocol/gate/recovery-admission` developer surface binds a relying-party-derived
recovery class to one exact action, tenant, operation, provider account,
environment, adapter, resource set, and policy/trust epochs. The presenter
cannot choose or downgrade that class.

- `LOCAL_ATOMIC` is valid only when every protected mutation stays inside one
  executor-owned database transaction. The PostgreSQL reference scaffold uses a
  `SERIALIZABLE` transaction, validates the result, rechecks currentness before
  commit, consumes the exact ordinary Admission Store reservation before the
  transaction, and treats commit acknowledgement loss as `INDETERMINATE`.
- `RESERVED_COMPENSATION` proves only that a separately authorized remedy is
  currently reserved. The remedy bridge verifies the claimed Remedy Program
  receipt and reserves the fresh remedy through the existing Admission Store.
  It never invokes a provider or reopens the original authority. It is a
  building block; an original-action integration must re-evaluate reservation
  currentness immediately before provider entry.
- `IRREVERSIBLE` routes to the ordinary authority policy. It is not automatic
  retry authority.

Only a still-reserved, demonstrably pre-entry operation may be released. Once
provider entry may have occurred, a timeout or negative lookup cannot restore
authority. Compensation is a fresh action and never rewrites the original
record. The callback markers in the PostgreSQL scaffold document the adapter
contract; JavaScript cannot sandbox a dishonest callback, so enforceable
confinement remains a deployment property. Run
`npm run demo:recovery-admission` from the repository root for the local
transaction path. See
[`docs/protocol/recovery-admission-profile-v1.md`](../../docs/protocol/recovery-admission-profile-v1.md)
and
[`docs/threat-models/RECOVERY-ADMISSION-V1.md`](../../docs/threat-models/RECOVERY-ADMISSION-V1.md).

## Three-plane deployment

High-consequence infrastructure separates three jobs instead of asking one
vendor or appliance to prove its own work:

1. **Enforcement plane** — an executor-side Gate returns 428 and does not call
   the actuator until the pinned authorization profile is satisfied.
2. **Witness plane** — an independently pinned TAP, packet broker, or sensor
   signs privacy-minimized observations. Observation never establishes that an
   action was authorized, blocked, executed, or physically completed.
3. **Control plane** — a relying party pins the coverage inventory and
   settlement profile, joins signed evidence by exact action digest, reports
   `gated`, `witness_only`, `ungated`, `stale`, or `unknown`, and meters only
   protected actions.

```js
import { evaluateGateControlPlane } from '@emilia-protocol/gate/control-plane';

const report = await evaluateGateControlPlane({
  coverage: { deployments, probes, witnesses }, // presenter evidence only
  settlements: [{ bundle }],
}, {
  coverageInventory,       // relying-party pinned
  settlementProfile,       // relying-party pinned
  expectedProbeNonces,     // current RP challenges, keyed by surface
  attestationVerifiers,
  pinnedProbes,
  pinnedWitnesses,
  witnessSequenceStore,     // durable atomic stream checkpoint store
  verifyAuthorization,
  verifyExecution,
  verifyOutcome,
});
```

The reference demonstration is `node examples/gate-control-plane/demo.mjs`.
It shows a complete view becoming `witness_only` and settlement-ineligible when
the Gate is removed while the network witness remains healthy.
Witness-dependent production decisions fail closed unless `witnessSequenceStore`
is durable or the relying party supplies a previously accepted durable witness
result through the explicit trusted-acceptance option.

## Default action packs

`createTrustedActionFirewall()` ships with high-risk defaults. These are category-based, not just
amount-based:

- `payment.release` — money movement, `class_a`
- `payment.bank_details.change` — bank-detail / beneficiary change, `class_a`
- `deploy.production` — production deploy, `quorum`
- `permission.admin.change` — permission / admin change, `quorum`
- `data.export` — bulk sensitive-data export, `class_a`
- `record.delete` — destructive record deletion, `class_a`
- `regulated.decision.override` — regulated decision override, `quorum`

Each pack also defines `execution_binding.required_fields`. The executor must pass those observed
fields from the real system of record. If the signed claim and observed mutation differ, the gate
refuses with `execution_binding_failed` before consuming the receipt.

Execution-parameter binding is therefore a **Gate** comparison that holds **only when you supply a
system-of-record `observedAction`**: Gate can refuse when those observed parameters do not match what
was authorized, but it does not prove what a provider ultimately executed. If a required field is declared but no
`observedAction` is provided, the check fails closed (`execution_binding_failed`), never silently
passes. A bare `@emilia-protocol/require-receipt` gate binds the action type/target only; reach for
this package when parameter drift (amount, beneficiary, commit, role, …) must be caught.

Prefer `gate.run(...)` for mutations: it reserves the receipt, runs the side effect, commits
one-time consumption after success, and emits the execution receipt + reliance packet. Once the
executor is invoked, a thrown error is an **indeterminate effect**, not proof that nothing happened:
the approval is burned (or its no-TTL reservation remains frozen if the store is unavailable) so a
blind retry cannot duplicate the side effect. Retryable integrations should make the downstream
operation idempotent under `receipt_id` and reconcile the result. Use lower-level `gate.check(...)`
only when your framework has to separate authorization from execution.

Use your own manifest when you need custom policy:

```js
import { createGate } from '@emilia-protocol/gate';

const gate = createGate({ manifest, trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
```

## Framework adapters

```js
// 1) Express / Connect route wrapper. The handler is the effect callback;
// Gate owns reservation, execution, consumption, and evidence as one lifecycle.
app.post('/payments', gate.route(
  async (req, res) => res.json(await releasePayment(req.paymentFromSystemOfRecord)),
  {
    selector: { protocol: 'http', method: 'POST', path: '/payments' },
    observedAction: (req) => req.paymentFromSystemOfRecord,
  },
));

// 2) Wrap any function
const release = gate.guard(reallyRelease, {
  selector: () => ({ tool: 'release_payment', protocol: 'mcp' }),
  receipt: (_amount, r) => r,
  observedAction: (amount) => ({
    action_type: 'payment.release',
    amount_usd: amount,
    currency: 'USD',
    payment_instruction_id: 'pi_123',
    beneficiary_account_hash: 'sha256:...',
  }),
});
```

`gate.middleware()` is intentionally deprecated and always refuses: middleware
cannot prove that code after `next()` executed, so consuming a one-time receipt
there would create an authorization-without-effect ambiguity. Use
`gate.route()`, `gate.guard()`, or `gate.run()` for mutations.

## MCP drop-in

Agents live at the MCP tool-call boundary. One wrapper turns a dangerous tool into a
receipt-required one:

```js
import { createTrustedActionFirewall } from '@emilia-protocol/gate';
import { gateMcpTool } from '@emilia-protocol/gate/mcp';

const gate = createTrustedActionFirewall({ trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });

server.tool('release_payment', gateMcpTool(
  gate,
  { tool: 'release_payment', observedAction: (args) => paymentSystem.describe(args) },
  async (args) => paymentSystem.release(args),
));
// No valid receipt -> a structured MCP error ({ isError, _emilia.challenge }).
// On success -> the tool result with { _emilia: { execution, reliance } } attached.
```

## System-of-record adapters

Adoption happens where the mutation happens — *"install this before your agent can touch
production."* Each adapter guards the destructive operations of a real system so the mutation never
reaches it without a receipt bound to **this** resource (a receipt for resource A cannot authorize
mutating B). All share one fail-closed contract (`adapters/_kit.js`).

```js
import { createGate } from '@emilia-protocol/gate';
import { createGithubManifest, guardGithubMutation } from '@emilia-protocol/gate/adapters/github';

const gate = createGate({ manifest: createGithubManifest(), trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
await guardGithubMutation(gate, octokit, {
  op: 'repo.delete',                 // | 'permission.change' | 'branch_protection.remove'
  params: { owner: 'acme', repo: 'prod' },
  receipt,                           // throws EMILIA_RECEIPT_REQUIRED if absent/invalid/replayed/drifted
});
```

| Adapter | Import | Guarded ops (assurance) |
|---|---|---|
| **GitHub** | `@emilia-protocol/gate/adapters/github` | repo.delete `class_a`, permission.change `quorum`, branch_protection.remove `class_a` |
| **Stripe** | `@emilia-protocol/gate/adapters/stripe` | payout.create `class_a`, refund.create `class_a`, bank_account.change `quorum` |
| **Supabase / Postgres** | `@emilia-protocol/gate/adapters/supabase` | sql.destructive `class_a`, data.export `class_a`, rls.change `quorum` |
| **AWS (IAM + network)** | `@emilia-protocol/gate/adapters/aws` | iam.attach_policy `quorum`, iam.create_access_key `class_a`, iam.delete_user `class_a`, ec2.authorize_ingress `quorum` |
| **MongoDB** | `@emilia-protocol/gate/adapters/mongodb` | document.delete_many `class_a`, document.update_many `class_a`, collection.drop `quorum` |

```js
import { createStripeManifest, guardStripeMutation } from '@emilia-protocol/gate/adapters/stripe';
const gate = createGate({ manifest: createStripeManifest(), trustedKeys: [ISSUER_PUBKEY_B64U], store: sharedConsumptionStore });
await guardStripeMutation(gate, stripe, { op: 'payout.create', params: { amount: 40000, currency: 'usd', destination: 'acct_x' }, receipt });
// Supabase: guardSupabaseMutation(gate, db, { op: 'sql.destructive', params: { sql }, receipt })  // binds the exact statement
// AWS:      guardAwsMutation(gate, client, { op: 'iam.attach_policy', params: { user, policy_arn }, receipt })
```

Clients are injected (the real `@octokit/rest`, `stripe`, a `pg`/Supabase client, or the AWS SDK), so
the adapters are testable without credentials. Adding an adapter is ~40 lines: a frozen action pack
(selectors + tiers + `execution_binding.required_fields`) and an op map (`selector`, `observed(params)`,
`perform(client, params)`) passed to `createAdapter()`.

## Earn EG-1

**EG-1 conformance** answers the only question that matters for adoption: *does your integration
actually enforce the gate, or are you just claiming it?* An integration earns **EG-1 Enforced** only
if it demonstrably passes all eight checks:

1. missing receipt → 428
2. software receipt on a Class-A action → refused
3. observed execution drift → refused
4. valid Class-A / quorum receipt → runs
5. same receipt replay → refused
6. tampered receipt → refused
7. execution proof binds to the authorization decision
8. reliance packet returns verdict `rely`

```js
import { createTrustedActionFirewall, createEg1Harness, gateConformance } from '@emilia-protocol/gate';

const harness = createEg1Harness();
const gate = createTrustedActionFirewall({
  trustedKeys: [harness.publicKey],
  approverKeys: harness.approverKeys,
  rpId: harness.rpId,
  allowedOrigins: harness.allowedOrigins,
  allowEphemeralStore: true, // conformance fixture only
});
const report = await gateConformance({ gate, harness });
// report.passed === true; report.badge === 'EG-1 Enforced'
```

For a custom integration (an HTTP service, another language), provide your own `invoke` to
`runEg1({ invoke, harness })` — it drives the same eight scenarios. `node eg1.mjs` self-certifies the
reference gate and exits non-zero on any failure, so it drops straight into CI. This turns an open PR
into a crisp claim: *"this PR makes `delete_row` earn EG-1."*

## What it adds over a bare verifier

`@emilia-protocol/require-receipt` already does manifest matching, offline verification, and the 428
challenge. The Gate composes that and adds the lifecycle controls a firewall needs:

- **Assurance tiers** — `software` < `class_a` (device signoff) < `quorum` (m-of-n). A `critical`
  action can demand `class_a` or `quorum`; a lower-assurance receipt is refused (`assurance_too_low`).
  In the lightweight EP-RECEIPT-v1 gate, the tier is an issuer-attested claim
  inside a receipt signed by a pinned issuer key. For independent verification
  of every embedded device/quorum signature, use the EP §6.2 trust-receipt
  verifier in `@emilia-protocol/verify`.
- **One-time consumption** — a receipt authorizes one action, once. Replays are refused
  (`replay_refused`). Gate construction requires a durable, ownership-fenced, permanent store.
  The process-local store is available only through explicit `allowEphemeralStore:true` for tests
  and reference demos.
- **Evidence log** — the local logger hash-chains decisions and detects alteration when given its
  complete process history. It is not a fleet ledger: a sink cannot prevent restart-from-genesis or
  cross-replica forks. Safety-critical deployments use `createAtomicEvidenceLog()` over a durable
  backend whose compare-and-append transaction advances one shared head across replicas.
- **Execution-field binding** — for high-risk packs, the signed claim must match the executor's
  observed mutation fields (`amount_usd`, `commit_sha`, `principal_id`, `record_id`, etc.). This
  closes "approved harmless X, executed dangerous Y."
- **Reliance packet** — `gate.reliancePacket()` turns the decision, execution receipt, field binding,
  and evidence head into the compact artifact an auditor, insurer, or investigator can review.
- **Independent coverage evidence** — deployment attestation plus a separately pinned active probe
  can establish a declared surface as `gated`; a passive network witness alone is always
  `witness_only`. Inventory completeness remains an explicit relying-party assumption.

## Formal-to-runtime bridge

Every Gate has an explicit runtime lifecycle monitor. It mirrors the load-bearing
state ordering behind the formal model: authorization must precede the effect,
consumption is one-way, and execution evidence follows the effect attempt. A
divergence emits a bounded `SPEC_DIVERGENCE` event and moves the Gate into
fail-closed safe mode. In safe mode, pass-through is disabled and a receipt must
earn at least Class-A assurance before execution.

```js
import { createRuntimeMonitor, createTrustedActionFirewall } from '@emilia-protocol/gate';

const monitor = createRuntimeMonitor({
  onDivergence: (event) => siem.append(event),
  authorizeRecovery: (request) => operatorApproval.verify(request),
});
const gate = createTrustedActionFirewall({ runtimeMonitor: monitor, /* ... */ });
```

Recovery is explicit and operator-authorized; it never re-authorizes a prior
receipt. The repository's `check:runtime-bridge` gate binds each monitor
theorem to an invariant declared in `formal/ep_handshake.cfg`, so a renamed or
removed formal source cannot silently leave the runtime map stale. This is a
machine-checked coverage binding, not a claim that TLA+ is automatically
compiled into JavaScript: the formal specifications remain the source of the
invariants and the monitor's transition table is covered by its own tests.

## Capability receipts

`capability-receipt.js` adds an issuer-signed capability envelope around an
ordinary EP receipt. The envelope binds a secret preimage, an integer budget,
currency, expiry, a signed delegation chain, and an optional `m-of-n` Shamir
threshold. The envelope's `consumed` field is only an issuance invariant; spend
state lives in an atomic capability store and is never trusted from the bearer
object.

```js
import {
  createMemoryCapabilityStore,
  executeWithCapability,
  mintCapabilityReceipt,
} from '@emilia-protocol/gate/capability-receipt';

const minted = mintCapabilityReceipt(baseReceipt, {
  issuerPrivateKey,
  budget: { amount: 1_000_000, currency: 'USD' },
  expiry: '2026-12-31T00:00:00.000Z',
  revocationMode: 'cascade',
  scope: {
    profile: CAPABILITY_SCOPE_PROFILE,
    operation_id_field: 'payment_instruction_id',
    action_digests: allowedPaymentActions.map(capabilityActionDigest),
  },
});
const store = createMemoryCapabilityStore(); // tests only; use Postgres in production
store.registerCapability(minted.capabilityReceipt);
await executeWithCapability({
  capabilityReceipt: minted.capabilityReceipt,
  secret: minted.secret,
  action: { amount: 10_000, currency: 'USD' },
  observedAction: actionFromTheSystemOfRecord,
  store,
  gate,
  trustedIssuerKeys: [capabilityIssuerPublicKey],
  operationId: 'provider-idempotency-key',
  executeAction: sendPayment,
});
```

The production adapter requires a transaction callback and locks the capability
state row before reserving budget. If the external effect throws, the reserved
amount is committed as indeterminate; it is never silently reopened. The
capability path is separate from ordinary receipt consumption: the capability
store owns replay and budget state for each explicitly supplied operation ID.
The verifier requires a pinned capability issuer key. The caller's operation ID
must equal the signed scope's field in the executor-observed action. The
`action_digest` remains the v1 digest of that complete immutable action and is
persisted unchanged for exact-action evidence and reconciliation. The separate
budget projection must match the amount and currency in the verified action,
and the effect callback receives a clone of the verified action—not the
projection.

`action_fence_digest` is a separate, reservation-only identity used for
namespace-level duplicate-action exclusion. It never replaces or redefines
`action_digest` or `capabilityActionDigest()`. Exact-digest scope defaults the
fence to the exact action digest. CAID scope derives a domain-separated fence
deterministically from the pinned resolver's validated CAID, so two wrappers
with different operation IDs can retain different exact digests while mapping
to one material-action fence. Different CAIDs derive different fences.

Allowance/profile scope has no exact-digest fallback. Its trusted profile
verifier must return `{ ok: true, action_fence_digest }`, and Gate accepts the
fence only when it is a canonical `sha256:<64 lowercase hex>` digest. Returning
only `true` or `{ ok: true }` now refuses with
`capability_action_fence_digest_required`; a malformed supplied fence refuses
with `capability_action_fence_digest_invalid`. This is an intentional
fail-closed compatibility break: an exact digest that includes a
wrapper-specific operation ID is not evidence of semantic uniqueness.

Allowance status is checked twice: once while reserving authority and again,
under the same atomic state-domain lock order, immediately before provider
entry. A suspension, revocation, or superseding status that lands between those
transitions refuses provider entry. The reservation stays held until the
authenticated recovery path or its deadline resolves it; Gate does not silently
refund authority or claim that the provider was never entered.

`executeWithGateAllowance()` derives its explicit fence from the closed,
profile-validated action after removing only the signed
`operation_id_field`. The allowance `profile_id` remains the operation
namespace, so separate capability envelopes under that profile retain the
same replay domain. A deployment that intentionally permits materially
distinct, otherwise identical actions must include a stable business-action
discriminator (for example, an invoice or payout-instruction ID) as another
validated material field; changing only the wrapper operation ID cannot create
new authority. The low-level store API retains its exact-digest default for
exact-scope compatibility, but custom allowance/profile integrations must pass
the verifier-produced semantic fence explicitly.

Both digests are persisted in memory and PostgreSQL operation state. A live
fence conflict returns `action_digest`, `action_fence_digest`, and
`holding_operation_id`; `executeWithCapability()` preserves those diagnostics
instead of collapsing the store refusal to a reason alone.

#### Install the production action fence

The unique index is intentionally non-concurrent and can block capability
writes while PostgreSQL builds it. Use this operator sequence; do not apply it
against an actively written table:

1. Quiesce every writer to `ep_capability_operations`, including Gate workers,
   migration jobs, repair tools, and direct database writers. Confirm the
   quiescence independently; the preflight cannot prove that no writer exists.
2. Run the packaged, read-only preflight as the migration role:

   ```bash
   GATE_PREFLIGHT=node_modules/@emilia-protocol/gate/deploy/sql/capability-action-fence-preflight.sql
   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$GATE_PREFLIGHT"
   ```

   It omits reservation secrets and changes no rows. It prints and refuses every
   legacy `reserved` operation that lacks a provider-entry deadline (SQLSTATE
   `55000`), then prints every duplicate live
   `(operation_namespace, action_fence_digest)` group and refuses duplicates
   with SQLSTATE `23505`. When those guards pass, it also previews every legacy
   capability ID that the migration will quarantine.

   A historical `action_digest` is shown only as compatibility identity. It is
   not evidence that two wrappers describe the same material action. Never use
   this preflight or its output to infer semantic equivalence.
3. Reconcile every refused row by status while writers remain quiesced:
   - `reserved`: use the normal owner-fenced pre-entry recovery only after its
     deadline has elapsed and provider non-entry is established. Otherwise
     leave it unresolved and stop the deployment.
   - `provider_entered`: never delete or relabel it. Release is permitted only
     through the authenticated provider-non-entry lifecycle after its deadline;
     otherwise preserve it for authenticated reconciliation and stop.
   - `committed`: never delete or relabel it as `released`. Reconcile an
     `indeterminate` outcome only from exact authenticated provider evidence.
     If multiple committed rows remain, preserve all evidence and use a
     separately reviewed, auditable incident-remediation migration; this
     generic migration must remain blocked.
4. Rerun the preflight until it exits zero with empty unsafe-reservation and
   duplicate result sets. Do not use
   ad hoc `DELETE`, status rewrites, or reservation-token edits to make it pass.
5. Apply `20260803010000_capability_action_digest_fence.sql` with
   `ON_ERROR_STOP=1` while writers are still quiesced. The file owns an explicit
   `BEGIN`/`COMMIT` boundary, repeats the unsafe-reservation and duplicate
   guards, restores the digest and lifecycle constraints, and either commits the
   complete upgrade or commits nothing.
6. Treat every capability ID that had historical operations as permanently
   quarantined with `semantic_fence_ready = false`. Do not flip that flag back
   to `true`, and do not backfill a semantic mapping from its historical exact
   digests. After evidence-preserving review, issue a fresh capability with a
   new capability ID and the current semantic fence contract.
7. Verify the installed contract before restoring writers:

   ```sql
   SELECT i.indisunique,
          pg_get_indexdef(i.indexrelid) AS index_definition,
          pg_get_expr(i.indpred, i.indrelid) AS predicate
     FROM pg_index AS i
     WHERE i.indexrelid =
       to_regclass('ep_capability_operations_live_action_uniq');
   ```

   Require `indisunique = true`, a valid and ready immediate btree with no
   included columns, ordered keys
   `(operation_namespace, action_fence_digest)`, and exactly the live statuses
   `reserved`, `provider_entered`, and `committed`. Each key must use its source
   column's exact collation, the default btree operator class, and ordinary
   ascending/nulls-last options. The migration and packaged preflight refuse a
   stale, non-unique, differently collated, non-default-opclass, or otherwise
   wrong same-named index.

The built-in `urn:emilia:scope:action-digest-set-v1` profile is exact-byte
scope. `urn:emilia:scope:caid-set-v1` is also supported for interoperable
material-action scope, but only when the deployment supplies its pinned CAID
resolver as `capabilityCaidResolver`; a missing, unknown, or non-matching CAID
fails closed. The resolved CAID also supplies the material fence described
above. CAID correlates content here—it does not replace issuer trust, human
authorization, holder proof, or durable budget state.

### Gate-integrated capability enforcement

For an action that must be both human-authorized and budget-limited, pass the
capability store when constructing the Gate and supply a capability to `run()`
or `guard()`:

```js
const gate = createTrustedActionFirewall({
  capabilityStore: postgresCapabilityStore,
  capabilityTrustedIssuerKeys: [capabilityIssuerPublicKey],
  capabilityCaidResolver: resolveWithPinnedCaidRegistry, // for caid-set scopes
  // ...the ordinary Gate trust and durable evidence configuration
});

const result = await gate.run({
  selector: { protocol: 'mcp', tool: 'release_payment' },
  observedAction: actionFromTheSystemOfRecord,
  capability: {
    capabilityReceipt,
    secret,
    action: { amount: 10_000, currency: 'USD' },
    operationId: 'provider-idempotency-key',
  },
}, (authorization, operation) => sendPayment(actionFromTheSystemOfRecord, {
  idempotencyKey: operation.providerIdempotencyKey,
  authorization,
}));
```

The Gate verifies the ordinary receipt first without consuming it, requires the
capability amount and currency to equal the observed action's `amount` or
`amount_usd` and `currency`, checks the signed exact-action scope, reserves the
budget and action digest before calling `sendPayment`, and passes the stable
operation ID to the provider adapter as its idempotency key. A replay,
out-of-scope action, operation relabel, overspend, missing registration, or
envelope mismatch never enters the effect. An exception after the effect begins
commits the amount as `indeterminate` and keeps the operation closed for
authenticated reconciliation. Capability issuer keys are pinned separately
from the ordinary receipt trust list.

Delegation is issuer-authorized and budget-backed: `delegateCapabilityReceipt`
atomically reserves and commits the child budget against the parent before the
child is registered. A failed child registration is reported for
reconciliation; it never creates spendable budget out of thin air. A holder
cannot edit `delegation_chain` or enlarge a child because the issuer signs the
entire envelope.

## Gate Allowances

`@emilia-protocol/gate/allowance` turns a reviewed authorization into one
customer-signed, time-bounded operating envelope. In-envelope actions run
without another prompt; an out-of-envelope action refuses so a separately
authenticated human can approve a successor allowance.

The signed allowance binds its tenant, subject, audience, typed connector
instance, action schema, target and exact-value allowlists, per-action ceiling,
aggregate budget, authorizing-receipt digest, presentation digest, one
capability identifier, capability-issuer key digest, and expiry. Execution also
requires deployment-pinned receipt and current-status verifiers. V1 refuses
delegated allowance capabilities.

Typed reference wrappers are available for Stripe payouts, GitHub production
workflow dispatches, and Supabase RLS policy replacements. Provider clients and
credentials stay in the caller's process. See
`docs/protocol/GATE-ALLOWANCES-v1.md` and the runnable
`examples/gate-allowance/` demonstration.

### Cross-rail authority admission

`@emilia-protocol/gate/cross-rail-authority` adds the missing join between a
current allowance and a payment connector. A trusted connector projects the
exact action, provider request digest, and CAID. A signed interruption decision
states whether standing policy is enough or an exact human authorization is
required. Only after allowance verification and atomic reservation does Gate
mint an opaque, short-lived permit that the connector consumes once before
calling the provider.

The caller never receives the permit artifact or a provider credential.
Payment partners retain custody, settlement, refunds, and disputes. The module
does not claim funds availability or payment success. Provider uncertainty is
recorded as `indeterminate` and cannot be blindly retried. See
`docs/protocol/cross-rail-authority-loop-v1.md`.

Authenticated tenant-scoped approval queues and receipt lists remain part of
normal Gate operation; the neutrality boundary is no public, unauthenticated,
cross-tenant enumeration. Private records are unlisted by default. A tenant may
explicitly publish a governed aggregate and anchor that public artifact in an
independent transparency service. Raw cross-rail events and opaque permits are
never published automatically.

## Receipt programs

`createReceiptProgramKernel()` composes CAID, the Gate capability path, and the
evidence log into one bounded instruction surface. The instruction descriptor
and certificate encoding are deterministic; external effects are not. It does not create a
second ledger or bypass Gate. A successful run emits an Ed25519-signed
certificate over the exact program, provider result projection, execution
steps, and compact Gate evidence references.

```js
import {
  createReceiptProgramKernel,
  verifyReceiptProgramCertificate,
} from '@emilia-protocol/gate/receipt-program';

const certificateContext = {
  issuer: 'emilia-operator',
  tenant: 'acme',
  environment: 'production',
  audience: 'acme-audit',
  key_id: 'kms://receipt-program-1',
};

const kernel = createReceiptProgramKernel({
  gate,                              // already configured production Gate
  resolveCaid,                       // relying-party-pinned synchronous resolver
  operationIdField: 'payment_instruction_id',
  certificateSigner: {
    keyId: 'kms://receipt-program-1',
    custody: 'kms',
    publicKey: operatorPublicKey,
    sign: (bytes) => signWithKms(bytes),
  },
  certificateContext,
  projectResult: (raw) => ({
    provider: raw.provider,
    provider_operation_id: raw.provider_operation_id,
    status: raw.status,
  }),
  effectTimeoutMs: 15_000,
});

const run = await kernel.run({
  programId: 'delegated-payment-v1',
  instructionId: 'release-milestone-1',
  caid,
  selector: { protocol: 'mcp', tool: 'release_payment' },
  observedAction: actionFromTheSystemOfRecord,
  capability: {
    capabilityReceipt,
    secret,
    action: { amount: 50, currency: 'USD' },
    operationId: actionFromTheSystemOfRecord.payment_instruction_id,
  },
}, async (_authorization, operation) => ({
  provider: 'licensed-custodian',
  provider_operation_id: operation.providerIdempotencyKey,
  status: await releaseWithIdempotency(operation.providerIdempotencyKey),
}));

const checked = verifyReceiptProgramCertificate(run.certificate, {
  trustedCertificateKeys: {
    'kms://receipt-program-1': operatorPublicKey,
  },
  resolveCaid,
  expectedContext: certificateContext,
  certificateEvidence: run.certificate_evidence,
  // Must check this exact record against the relying party's pinned stream,
  // authenticated snapshot, or inclusion proof. Rehashing the object is not enough.
  verifyCertificateInclusion: verifyInPinnedEvidenceStream,
  requireAtomicCertificateEvidence: true,
});
```

Production construction requires a durable atomic evidence log and durable
capability store, external KMS/HSM signing custody, an exact certificate
context, and a pinned disclosure projector. Provider code receives only frozen
copies of authorization and operation data. A provider exception, real deadline
expiry, or invalid result projection after invocation becomes `indeterminate`
and leaves the operation closed to blind replay. A certificate is returned as
durable proof only after signing and complete-certificate evidence append
succeed; typed signer/persistence failures preserve Gate's terminal outcome.
`checked.ok` means certificate validity, not provider success—inspect
`checked.outcome` and `checked.execution_succeeded`. The certificate proves
operator-signed integrity and binding; it is not a zero-knowledge proof or
independent proof of provider truth. See the runnable `examples/receipt-program/` reference and the
[architecture profile](../../docs/architecture/RECEIPT-PROGRAM-EXECUTION-KERNEL.md).

## Zero-knowledge range receipts

`zk-range-proof.js` provides `EP-ZK-RANGE-RECEIPT-v1`. It uses Bulletproofs over
Ristretto255 to prove a hidden integer `v` satisfies `0 <= v <= max` without
revealing `v` or its blinding factor. The second commitment proves the upper
bound relation `max - v` without relying on a mutable claim. The envelope
binds a public policy hash, predicate, base-receipt digest, issuer key, and
nonce. The ordinary EP receipt signature must still be verified separately.

The cryptographic engine is an explicit optional backend:
`@aptos-labs/confidential-asset-bindings@1.1.2`. It is not pulled into the
default Gate install because its WASM/mobile distribution is large. A
deployment enabling ZK receipts must pin, audit, and pass the backend's own
proof tests. This v1 is a genuine hidden-range proof; it is not a claim that
the repository automatically compiles all TLA+ invariants into R1CS.

## Action Escrow

Action Escrow is the Gate profile for a two-party agreement whose downstream
release must obey the exact final document. The customer application supplies
the signed agreement, material terms, party acceptances, funding evidence,
milestone evidence, and action-specific release approvals. Gate verifies and
binds those inputs, advances a signed lifecycle, and consumes the release once.
Each release approval is a standard `EP-RESOLUTION-v1` WebAuthn record over a
canonical binding moment. Gate independently pins the approval option,
initiator, per-party nonce, evaluation time, exact action digest, and the
document and milestone-evidence digests rendered to the approver.

The public modules are `action-escrow`, `action-escrow-state`,
`action-escrow-postgres`, `action-escrow-custodian`,
`action-escrow-package`, and `action-escrow-verifiers`. A licensed external
provider holds or moves funds; EMILIA does not take custody, inspect work,
adjudicate disputes, or make an agreement legally enforceable. An ambiguous
provider outcome enters reconciliation and is never retried as though nothing
happened.

Construction and contractor integrations use the explicit
`EP-ACTION-ESCROW-CONTRACTOR-TEMPLATE-v1` profile. Build its DAB verifier with
`createActionEscrowContractorDocumentBindingVerifier()` and its portable
six-row package with `assembleActionEscrowContractorEvidencePackage()`. The
package carries the exact project-system sidecar bytes beside the PDF and
re-performs both under relying-party-owned verifiers. A project record is
source evidence only: it cannot fill agreement-acceptance, release-approval,
or custodian-effect rows. The legacy template and package APIs refuse the
contractor profile instead of silently ignoring its project-source binding.
Unmarked project-bound artifacts from the unreleased `0.11.1` preview remain
verifiable only through the contractor package path, including its exact
sidecar and relying-party-owned project-source verifier.

## Production custody

The three things a serious buyer (CISO, auditor, insurer) asks after the demo:

**AEC execution custody.** `createAECExecutionGate()` requires a relying-party requirement,
executor-owned action, explicit human floor, and constructor-pinned custom verifier and key
registries. Transaction input may carry evidence, but never verifier code, trust keys, or human
acceptance profiles; attempts to do so are refused before verification. Production mode additionally refuses an expiring
consumption store or a process-local evidence logger. It consumes
`aec:action:<canonical-action-digest>` before the effect, passes the effect a frozen pre-await action
snapshot, and conservatively burns or freezes the action after an indeterminate result. Every
otherwise identical intended effect therefore needs a unique action-instance nonce inside the
signed action. Use `createAtomicEvidenceLog()` from `@emilia-protocol/gate/evidence`; its backend
must atomically compare and append against one durable shared head. The gate independently
recomputes every logger acknowledgment and requires its entry bytes to equal the requested
decision; the atomic logger also requires readback to equal the exact submitted sequence and
predecessor.

**Issuer key rotation + revocation.** A flat `trustedKeys` list can't revoke a leaked key
or rotate without downtime. A key registry can — a receipt is verified only against keys
valid (and not revoked) at its issuance time. Revocation is fail-closed and immediate.

```js
import { createGate, createKeyRegistry } from '@emilia-protocol/gate';

const registry = createKeyRegistry([
  { kid: 'issuer-1', key: KEY1 },
  { kid: 'issuer-2', key: KEY2, not_before: '2026-07-01T00:00:00Z' }, // rotation window
]);
const gate = createGate({ manifest, keyRegistry: registry, store: sharedConsumptionStore });
registry.revoke('issuer-1'); // compromised — refused immediately, live, no redeploy
```

**Fleet-safe replay defense.** The in-memory store is per-process. In production, back the
consumption store with a shared key-value store whose insert-if-absent, compare-and-set, and
conditional delete operations are atomic:

```js
import { createDurableConsumptionStore } from '@emilia-protocol/gate';
const store = createDurableConsumptionStore(redisBackend); // addIfAbsent + compareAndSet + deleteIfValue + has
const gate = createGate({ manifest, keyRegistry, store });
// A receipt consumed on one pod cannot be replayed on another.
```

Reservations carry an opaque owner token and have no TTL. Only that owner may commit or release;
an abandoned reservation requires reconciliation because automatically reopening it after a crash
could repeat an effect whose response was lost. A TTL may apply only to committed rows.
The Postgres adapter rejects malformed or regressing clocks before expiry-bearing state changes.
The model-based fault gate runs 5,000 generated schedules across crash, lag, rollback, failover,
duplicate delivery, and before/after-linearization response loss; see
`security/CONSUMPTION_FAULT_STATUS.md`.

**Evidence retention.** Classify the evidence log into hot/cold/expired with legal hold, and
export the auditor/SIEM manifest (tied to the evidence head). `EP_AUDIT_HOT_DAYS` /
`EP_AUDIT_COLD_DAYS` set the horizons.

```js
gate.retention({ hotDays: 365, coldDays: 2190, legalHold: ['<evidence-hash>'] });
gate.retentionExport();  // EP-GATE-RETENTION-EXPORT-v1 manifest
```

Issuer-side **KMS/HSM signing custody** (production mode refuses dev-local private keys) lives in
EP core (`lib/key-custody.js`, `assertProductionKeyCustody` / `createExternalCustodySigner`).

## Boundary

EMILIA Gate does not stop every bad actor. It makes **legitimate infrastructure refuse unreceipted
consequential actions by default**, so the parties with leverage (clouds, payment rails, regulators,
insurers) can *require* a receipt — and "no receipt" becomes like "no TLS cert" or "unsigned binary":
not always illegal, just untrusted. Necessary, not sufficient.

## Reliance risk plane

Gate `0.20.0` adds a consequence-risk plane around the existing Reliance
Program and execution lifecycle:

- `./loss-allocation-schedule` verifies separately signed, exact-program terms;
- `./open-exposure-ledger` and `./open-exposure-ledger-postgres` reserve and
  aggregate open exposure before provider invocation;
- `./action-refusal-statement` emits a signed exact-action technical refusal;
- `./coverage-reconciliation-attestation` reconciles supplied effect and
  receipt populations for a bounded period;
- `./coverage-reconciliation-runner` verifies independently signed minimized
  source inventories, joins exact CAID/action pairs, derives conserving counts,
  and emits the report-bound attestation;
- `./receipt-census` emits governed-taxonomy aggregates with coarse primary suppression; and
- `./loss-experience-feed` carries signed external observations whose
  corrections require a trusted current-head lineage resolver.

These artifacts do not create authority. EMILIA does not bear or allocate loss,
adjudicate disputes, verify insurance coverage or solvency, or move money.
Open exposure is an operational ceiling: an `INDETERMINATE` provider outcome
stays open until an independent reconciler supplies authenticated evidence.
See `docs/architecture/RELIANCE-RISK-PLANE.md` for the composed state model and
claim boundaries.

## Standards

The mechanism is specified in `draft-schrock-ep-enforcement-point` (the Receipt-Required rail) over
`draft-schrock-ep-authorization-receipts`. Earn the **RR-1** conformance level via
`receiptRequiredConformance()` in `@emilia-protocol/require-receipt`. Reference implementation;
experimental. Apache-2.0. Fails closed.

## Authority allocation

`@emilia-protocol/gate/authority-allocation` provides the same-team runtime
counterpart for Conservation of Authority. A relying party installs one
authoritative allocation snapshot pinned to an exact authority head and epoch.
The validator refuses child action or audience widening, budget or expiry
widening, duplicate sibling branches, and aggregate cents or calls overspend.
Reservations are atomic, replay-fenced, and can be finalized only with the
winning owner token, monotonic fencing token, and exact authority head and
epoch.

`createMemoryAuthorityAllocationStore()` is deterministic, non-durable
conformance infrastructure. `createPostgresAuthorityAllocationStore()` and
`AUTHORITY_ALLOCATION_DDL` define the durable transactional boundary; they are
reference code and a database contract, not evidence that any deployment uses
or correctly operates that boundary.

## Autonomy Control Plane

`@emilia-protocol/gate/autonomy-control-plane-profile` compiles a closed,
human-rooted autonomy profile into one existing Gate Trust Program per exact
child action. It rejects action/audience/expiry widening, aggregate sibling
budget expansion, cyclic goals, proposer/evaluator/executor role collapse,
unpinned fitness evidence, promotion without a bounded canary, stale status,
and rollback without a new CAID and authorization policy.

The compiler validates typed authority and evidence bindings. It does not infer
natural-language goal entailment or prove that tests, providers, storage,
clocks, deployments, or humans are truthful. See
`docs/protocol/autonomy-control-plane-profile-v1.md` for the complete boundary.
