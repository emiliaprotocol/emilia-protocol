<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP-BOUNDED-EXECUTION-PROGRAM-v1

**Status:** public experimental protocol profile. The canonical signed syntax
has a reference signer and verifier. The runtime section and deterministic
transition vectors define the program-aware AdmissionStore contract. The
same-team in-memory and PostgreSQL surfaces are implementation and local
regression evidence; they are not evidence of an independent implementation or
a durable production deployment.

## 1. Scope

`EP-BOUNDED-EXECUTION-PROGRAM-v1` lets an authorizer sign one finite,
versioned directed acyclic graph of consequential action occurrences. It
answers one narrow Gate question: is this exact occurrence reachable now under
this signed program, with occurrence ceilings and typed attempt budgets still
available?

It does not turn an objective, natural-language instruction, generated plan,
profile name, or signature into open-ended authority. Trust Program still
decides whether the evidence required for an individual action is satisfied.
Bounded Capability Receipts still own delegated scope and aggregate resource
authority. A program-aware AdmissionStore owns the one-time execution right and
the atomic cross-action runtime state.

In particular, `authorization_digest` is only an exact byte commitment used for
binding and exclusion. Its presence, signature, or runtime ownership does not
prove that a human ceremony occurred, who participated, whether a person
consented or understood, or what was displayed. Those claims require their own
verified evidence and relying-party acceptance rules.

This profile is complementary to software-supply-chain frameworks such as
in-toto. In-toto verifies signed layouts and signed evidence that designated
functionaries performed supply-chain steps. This profile instead governs live
consequence admission: it controls a one-time execution right under current
authorization, occurrence ceilings, aggregate attempt budgets, post-entry
uncertainty, and authenticated reconciliation. It does not replace in-toto or
claim that no other system can express ordered work.

Normative `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are used as described by
BCP 14 when shown in capitals.

## 2. Closed signed syntax

The unsigned construction input is a closed object with these fields:

| Field | Requirement |
| --- | --- |
| `program_id`, `tenant_id`, `subject_id`, `audience` | Nonempty identifiers in the shared EP identifier profile. |
| `version` | Positive safe integer. Version 1 requires `supersedes_program_digest: null`; a later version requires a non-null predecessor digest. |
| `objective_digest` | SHA-256 digest of the objective material selected by the authorizer. It is a byte binding, not proof that the objective was understood. |
| `authorization_digest` | SHA-256 digest of the independent authorization evidence this program relies on. It is not itself evidence of a human ceremony. |
| `presentation_digest` | SHA-256 digest of the presentation or approval surface selected by the authorizer. It does not prove display integrity or comprehension. |
| `supersedes_program_digest` | `null` for version 1; otherwise the exact predecessor program digest. |
| `issued_at`, `valid_from`, `expires_at` | UTC RFC 3339 instants satisfying `issued_at <= valid_from < expires_at`. Expiry is exclusive. |
| `max_total_occurrences` | Mandatory positive safe integer no greater than 1,000,000. It bounds all retained occurrence records, including released occurrences. |
| `max_concurrent_effects` | Mandatory positive safe integer no greater than 1,000,000. It bounds occurrences in `INVOKING` or `INDETERMINATE` for this program. |
| `budgets` | One to 64 unique budget dimensions. |
| `nodes` | One to 256 unique nodes forming a finite DAG with at least one root. |

The identifier profile is:

```text
^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$
```

A digest is `sha256:` followed by exactly 64 lowercase hexadecimal digits. A
CAID uses the closed `caid:1:<action-type>:jcs-sha256:<43 base64url chars>`
form enforced by the shared Gate risk-artifact profile.

### 2.1 Budgets

Each budget is a closed object:

```json
{ "budget_id": "attempts", "unit": "attempt", "limit": 3 }
```

`budget_id` and `unit` are identifiers. `limit` is a positive safe integer no
greater than `Number.MAX_SAFE_INTEGER` (9,007,199,254,740,991). Budget IDs are
unique. `budget_id` is the accounting dimension; `unit` is only its label. Two
budgets MAY use the same `unit` and MUST still reserve and consume independently.

### 2.2 Nodes

Each node is a closed object:

```json
{
  "node_id": "remediate",
  "action": {
    "mode": "profile",
    "profile_id": "profile:terraform-reviewed-plan",
    "profile_digest": "sha256:<64 lowercase hex>"
  },
  "trust_program_digest": "sha256:<64 lowercase hex>",
  "depends_on": [
    { "node_id": "inspect", "outcomes": ["COMMITTED"] }
  ],
  "max_occurrences": 1,
  "charges": [
    { "budget_id": "attempts", "amount": 1 },
    { "budget_id": "change-risk", "amount": 3 }
  ]
}
```

`node_id` is unique. `max_occurrences` is a positive safe integer no greater
than 1,000,000. `trust_program_digest` pins the Trust Program that must govern
the corresponding AdmissionSnapshot.

`action` has exactly one of two shapes:

```json
{ "mode": "exact", "caid": "caid:1:...", "action_digest": "sha256:..." }
```

```json
{ "mode": "profile", "profile_id": "profile:...", "profile_digest": "sha256:..." }
```

Profile mode does not make a profile name self-authenticating. A caller-supplied
`MATCH` flag or result object is not evidence and MUST NOT satisfy a node. The
caller instead supplies opaque `action_match_evidence` to the store's configured
authenticated action-match verifier. That verifier MUST authenticate the
artifact under its pinned evidence profile and return a closed `valid: true`,
`result: MATCH` result that exactly binds tenant, profile ID and digest, program
subject, operation ID, CAID, action digest, verifier ID, evidence payload
digest, evidence trust-configuration digest, trust epoch, and the
AdmissionSnapshot trust-configuration digest.

The AdmissionSnapshot MUST already contain that evidence payload in its
singleton `aeb` input. The input subject MUST equal the signed program subject,
and its profile digest, verifier ID, payload digest, and trust-configuration
digest MUST equal the authenticated result. Missing evidence, a missing
configured verifier, verifier failure, an open result, or any substitution
fails closed. The compatibility-only legacy `action_match` assertion cannot
authorize a profile action.

`depends_on` contains at most 64 unique predecessor node IDs. Every predecessor
must exist. Each dependency has one or both unique terminal outcomes:
`COMMITTED` and `PROVEN_NOT_COMMITTED`. `RESERVED`, `RELEASED`, `INVOKING`, and
`INDETERMINATE` are not dependency outcomes. Self-dependencies, cycles, and a
graph with no root fail closed.

`charges` contains one to 64 unique budget IDs. Every ID must name a declared
budget. `amount` is positive and cannot exceed that dimension's total program
limit.

Unknown fields, duplicate identifiers, duplicate dependency outcomes,
malformed values, or omitted required fields fail closed at every signed-object
boundary.

## 3. Canonical form, signature, and digest

Before signing, an implementation MUST:

1. validate the complete construction input;
2. normalize each instant to the UTC millisecond form emitted by an RFC 3339
   implementation (for example, `2026-07-29T20:00:00.000Z`);
3. sort budgets by UTF-8 byte order of `budget_id`;
4. sort nodes by UTF-8 byte order of `node_id`;
5. sort dependencies by UTF-8 byte order of predecessor `node_id`;
6. sort charges by UTF-8 byte order of `budget_id`; and
7. sort each dependency's terminal outcome strings.

The signer constructs this closed body:

```json
{
  "@version": "EP-BOUNDED-EXECUTION-PROGRAM-v1",
  "<normalized program fields>": "...",
  "claim_boundary": "typed_reachability_attempt_budget_and_effect_concurrency_not_intent_safety_effect_truth_or_complete_mediation",
  "issuer": { "id": "customer:...", "key_id": "key:..." }
}
```

It then computes:

```text
body_jcs       = RFC8785_JCS(body)
body_digest    = "sha256:" || lowercase_hex(SHA-256(UTF8(body_jcs)))
signature_input = UTF8("EP-BOUNDED-EXECUTION-PROGRAM-v1" || 0x00 || body_jcs)
signature      = Ed25519-Sign(authorizer_private_key, signature_input)
```

The attached `proof` is closed and contains exactly:

```json
{
  "algorithm": "Ed25519",
  "key_id": "key:...",
  "body_digest": "sha256:...",
  "signature_b64u": "<canonical unpadded base64url>"
}
```

`proof.key_id` MUST equal `issuer.key_id`. `program_digest` is the SHA-256 JCS
digest of the complete signed body with `proof` omitted; for a canonical
artifact it equals `proof.body_digest`.

The conformance vector includes the deliberately unsorted construction input,
the normalized program, exact body JCS string, exact signature-input bytes as
base64url, signed artifact, public-key pin, and expected program digest.

## 4. Verification

A verifier MUST first validate the closed proof envelope, recompute the body
digest, resolve an out-of-band key pin for the exact `issuer.id +
issuer.key_id`, and verify Ed25519 over the domain-separated canonical body. A
valid signature over an invalid or noncanonical program remains a refusal.

Standalone verification also requires the relying party to supply all of:

- expected program ID;
- expected tenant ID;
- expected authorizer ID;
- expected authorization digest;
- expected audience; and
- an explicit verification time.

The complete context is mandatory. Verification accepts only while
`valid_from <= now < expires_at`.

### 4.1 Store-owned registration verification

Program registration and supersession expose a narrower relying-party context
containing exactly:

```json
{
  "expected_program_id": "program:...",
  "expected_tenant_id": "tenant:...",
  "expected_authorization_digest": "sha256:...",
  "expected_audience": "gate:..."
}
```

For store operations, the store owns the clock and verification policy. Each
store-owned key pin binds a key ID to an issuer ID, canonical Ed25519 public
key, role, and status. Only role `program_authorizer` with status `ACTIVE` is
eligible to register or supersede a v1 program. `SUSPENDED` and `REVOKED` pins
remain policy records but are excluded from the eligible trust set.

The artifact's `issuer.key_id` can select only among eligible store-owned pins.
The store derives the expected authorizer ID from the selected pin and obtains
verification time from its own clock. Unknown context fields, including
caller-supplied trusted keys, expected authorizer, key role or status, or
verification time, refuse with `context_binding_required` and cannot replace
store policy.

`verified: true` means the signature and key pin verified. It does not imply
`accepted: true`: schema, canonical form, relying-party context, or time may
still refuse. Invalid signatures and untrusted issuers report
`verified: false`.

The syntax vectors pin these refusal reasons:

- `program_signature_invalid` and `program_issuer_untrusted`;
- `program_schema_invalid`;
- `context_binding_required`;
- `authorizer_mismatch`, `program_id_mismatch`, `tenant_mismatch`,
  `authorization_mismatch`, and `audience_mismatch`; and
- `verification_time_invalid`, `program_not_active`, and `program_expired`.

## 5. Program-aware runtime

Registering an accepted artifact creates one runtime state:

```text
status = ACTIVE
status sequence = 0 with store-clock observation and expiry metadata
authorizer_id = issuer derived from the eligible store-owned key pin
total_occurrences = 0
each budget = { limit, reserved: 0, consumed: 0 }
occurrences = empty
per-node non-released and terminal-outcome counts = 0
authorization owner[tenant_id, authorization_digest] = program_digest
```

Runtime conformance requires the program state, occurrence state, ordinary
AdmissionSnapshot state, resource reservations, and one-time execution right to
share one linearizable transaction domain. A compensating sequence across
independent stores is not atomic and does not conform.

Occurrence states are:

```text
RESERVED -> INVOKING -> COMMITTED
                    \-> PROVEN_NOT_COMMITTED
                    \-> INDETERMINATE -> COMMITTED | PROVEN_NOT_COMMITTED
RESERVED -> RELEASED
```

### 5.1 Registration and the authorization-digest fence

Registration verifies with the store-owned clock and active
`program_authorizer` key pins described in Section 4. `SUSPENDED` and `REVOKED`
key pins are valid policy records but are excluded from the trusted-key set; an
artifact relying on either refuses with `program_issuer_untrusted`. The caller
supplies only the four closed relying-party bindings.

Registration MUST atomically claim the exact `(tenant_id,
authorization_digest)` pair for program-aware admission. Before creating the
program state or claim, the store MUST inspect existing ordinary admissions. If
an ordinary admission in the same tenant still has `execution_right: RESERVED`
and its authorization input carries the same digest, registration refuses with
`program_binding_mismatch`. It must not strand an already-held ordinary
execution right, and the refusal creates no program or authorization-owner
state.

After successful registration, ordinary `reserve` under that exact tenant and
authorization digest MUST refuse with `program_required` before creating an
admission, operation head, journal entry, or resource reservation. A different
tenant or a different authorization digest is outside this fence. An ordinary
admission that has been released no longer blocks registration.

The fence proves only exclusive routing for one byte commitment. It does not
verify the authorization evidence, establish a named human, or prove ceremony,
consent, comprehension, presentation integrity, or legal authority.

### 5.2 Store-authoritative current program status

The store MUST obtain current program status from its configured authoritative
source at reservation and again immediately before provider entry. The caller
MUST NOT supply or select the source, its observation, or the maximum accepted
observation age. A closed status observation binds the exact tenant ID, program
ID, program digest, version, `ACTIVE`, `SUSPENDED`, or `REVOKED` status,
nonnegative sequence, observation time, and expiry.

A program-capable store without a configured authoritative status source MUST
fail closed with `program_status_indeterminate`; locally initialized `ACTIVE`
state is not a substitute for current status. The validation instant MUST be
sampled after the source returns. Expiry and maximum observation age MUST be
evaluated against that post-response instant, so a response that becomes stale
while the source is being queried cannot authorize reservation or provider
entry.

Only a current `ACTIVE` observation permits reserve or begin. `SUSPENDED`
refuses with `program_suspended`. `REVOKED` refuses with `program_revoked` and
is sticky: a later observation cannot reopen that runtime. An unavailable or
throwing source, missing or open-shaped observation, malformed or mismatched
binding, future-dated, stale, or expired observation, regressed sequence, or a
conflicting repeated sequence fails closed with
`program_status_indeterminate`.

A status or program-validity refusal at reserve creates no occurrence,
admission, budget, resource, operation-head, journal, or execution-right state.
At begin, while the occurrence is still pre-entry `RESERVED`, the same refusal
MUST atomically release the ordinary execution right and resources, the node
occurrence capacity, and every reserved budget charge, and mark the occurrence
`RELEASED`. Its occurrence ID and total-history count remain fenced. Work
already `INVOKING` or `INDETERMINATE` remains reconcilable.

### 5.3 Reservation and deterministic AdmissionSnapshot binding

A reservation MUST atomically verify:

- active program digest, tenant, version, validity interval, fresh
  store-authoritative `ACTIVE` status, and authorization-digest fence;
- node existence and exact Trust Program digest;
- exact CAID/action digest or store-verifier-authenticated profile evidence;
- all outcome-specific dependencies;
- unused occurrence ID;
- `total_occurrences < max_total_occurrences`;
- remaining indexed per-node non-released occurrence ceiling;
- every budget condition
  `reserved + consumed + node_charge <= limit`;
- AdmissionSnapshot expiry no later than program expiry; and
- the ordinary AdmissionSnapshot and resource reservations.

For the requested occurrence, the store derives this closed binding body using
the normalized `AdmissionSnapshot.body.expires_at`:

```json
{
  "@version": "EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1",
  "tenant_id": "tenant:example",
  "program_digest": "sha256:<64 lowercase hex>",
  "node_id": "inspect",
  "occurrence_id": "occurrence:inspect:01",
  "expires_at": "2026-07-29T20:45:00.000Z"
}
```

It seals the binding into the snapshot as this deterministic resource:

```text
identity_tuple  = [tenant_id, program_digest, node_id, occurrence_id]
identity_domain = "EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:IDENTITY"
identity_digest = "sha256:" || lowercase_hex(
  SHA-256(UTF8(identity_domain) || 0x00 || RFC8785_JCS(identity_tuple))
)

digest_domain = "EP-BOUNDED-EXECUTION-PROGRAM-ADMISSION-BINDING-v1:DIGEST"
digest = "sha256:" || lowercase_hex(
  SHA-256(UTF8(digest_domain) || 0x00 || RFC8785_JCS(binding_body))
)

kind           = "execution_program"
resource_id    = "execution-program:" || identity_digest
reservation_id = "execution-program-reservation:" || identity_digest
expires_at     = binding_body.expires_at
```

The identity digest is over the structured JCS array, not a delimiter-joined
string. The resulting resource and reservation IDs are fixed-length digest
keys. Implementations MUST NOT substitute raw caller-controlled identifiers,
ambiguous delimiter concatenation, or another tuple encoding.

For an `AdmissionSnapshotInput` with no `execution_program` resource, the
program-aware reserve path MUST derive this resource and rebuild the snapshot
with it before computing the accepted snapshot digest. If an input already has
one such resource, it must be canonically identical to the derived resource.

A prebuilt `AdmissionSnapshot` identified by `snapshot_digest` cannot be
rebuilt. It MUST already carry exactly one canonically identical
`execution_program` resource. A prebuilt unbound snapshot, multiple program
bindings, or any attempted relink of tenant, program digest, node, occurrence,
or snapshot expiry refuses with `program_binding_mismatch`. The refusal creates
no occurrence, admission, budget reservation, resource owner, operation head,
or journal entry.

Before adding or accepting the binding, the store MUST also require the
candidate-manifest subject to equal the signed `subject_id`; the authorization
input payload digest to equal the signed `authorization_digest`; the
AdmissionSnapshot authorization-policy digest to equal the node's
`trust_program_digest`; and the exact or authenticated profile action match
defined above.

The normalized AdmissionSnapshot expiry MUST be no later than the signed
program expiry. A later expiry refuses with `program_expiration_mismatch`
before any occurrence, budget, resource, operation-head, journal, or execution
right state is created. Equality is permitted because both expiries are
exclusive.

On success it fences the occurrence ID, creates `RESERVED`, increments the
program's monotonic `total_occurrences`, increments the indexed non-released
count for that node, and increments each budget's `reserved` value. A refusal
makes no state change. Release decrements the node index and budget reservation,
but it does not decrement `total_occurrences`, delete the retained occurrence,
or make its occurrence ID reusable. Exhausting `max_total_occurrences` refuses
with `program_total_occurrence_exhausted` even if releases reopened the
per-node index.

A conforming transaction store SHOULD maintain atomic per-node non-released
counts and per-node terminal-outcome counts so reservation and dependency
checks do not scan retained history. These indexes MUST reconcile exactly with
retained occurrence records and update in the same transaction as each source
transition.

### 5.4 Begin, release, and expiry

Only the program-aware begin path can begin a program-linked admission. The
ordinary begin, release, and expiry paths MUST refuse with `program_required`.
A program-aware begin, release, or expiry path likewise refuses an admission
that lacks the exact execution-program association.

Program-aware begin MUST recheck store-authoritative program status, program
validity, ordinary admission currentness, and the signed concurrent-effect
ceiling. Immediately before releasing the invocation capability, the store
MUST count all occurrences for this exact program in `INVOKING` or
`INDETERMINATE`. If that count is greater than or equal to
`max_concurrent_effects`, begin MUST refuse with
`program_concurrency_exhausted` without consuming the execution right or
moving any budget charge.

Otherwise begin atomically consumes the ordinary execution right and moves
every node charge from `reserved` to `consumed` before releasing the invocation
capability. The occurrence becomes `INVOKING`. Once begin succeeds, neither a
provider refusal, timeout, nor an indeterminate result restores the occurrence
or budget.

Program-aware release and expiry are permitted only from `RESERVED`. They
decrement each reserved budget charge, release the ordinary execution right and
resources, restore node capacity, and mark the occurrence `RELEASED`. Release
after begin refuses because the execution right is consumed.

### 5.5 Outcomes and reachability

`COMMITTED` and `PROVEN_NOT_COMMITTED` are terminal provider outcomes.
`INDETERMINATE` records uncertainty after provider entry and keeps all charges
consumed. `INDETERMINATE` also continues to occupy one concurrent-effect slot:
uncertain work cannot be hidden by retrying around the ceiling. Reconciliation
may move it to either terminal outcome and then releases that slot;
reconciliation does not itself prove when the provider event occurred.

A dependency is satisfied only when at least one occurrence of each named
predecessor has a terminal state explicitly listed in that dependency.
Terminality alone is insufficient: `PROVEN_NOT_COMMITTED` does not satisfy a
dependency that names only `COMMITTED`.

`DIVERGED` is an effect relation, not a provider outcome. Recording it MUST NOT
rewrite occurrence state, authorization history, budgets, or reachability, and
it does not identify why an effect differed.

### 5.6 Supersession

Programs are immutable. Replanning creates a newly signed and independently
accepted version, and the predecessor MUST be the active program head. The
successor MUST bind the exact predecessor program digest, have exactly
`predecessor.version + 1`, and preserve the predecessor's tenant ID, program ID,
subject ID, audience, objective digest, presentation digest, and store-derived
program-authorizer identity. These identity, objective, and presentation
bindings are frozen for v1 supersession.

The successor MUST carry a distinct authorization digest that differs from the
predecessor and has never been registered in the store's authorization-owner
domain. The caller supplies that fresh digest in the closed four-field
registration context. Reuse, a skipped version, changed frozen binding, changed
authorizer, wrong predecessor, or an already-owned authorization digest fails
closed without changing the active head.

Any predecessor occurrence still in `RESERVED` blocks supersession. After
supersession, the predecessor refuses new reservations and new invocation
starts. Already invoking or indeterminate work remains reconcilable. The
successor starts with `total_occurrences` zero, zero reserved and consumed
budgets, fresh node and terminal indexes, and no occurrences. Budget,
occurrence, evidence, and terminal state do not silently carry forward. A
successor can depend on earlier effects only through separately verified
evidence admitted by its own action-specific Trust Program. Authorization-digest
fences remain keyed by their distinct tenant-plus-digest commitments.

## 6. Conformance vector contract

[`conformance/vectors/bounded-execution-program.v1.json`](../../conformance/vectors/bounded-execution-program.v1.json)
is generated by
[`generate-bounded-execution-program.mjs`](../../conformance/vectors/generate-bounded-execution-program.mjs).
It has two language-neutral sections.

### 6.1 Syntax cases

`syntax.common` supplies the default trusted-key map and relying-party
verification context. Each case selects an artifact, may replace the trusted
key set with `none`, may omit all required relying-party context, and may apply
the listed verification overrides. A conforming verifier compares this closed
projection:

```json
{
  "accepted": false,
  "verified": true,
  "reason": "program_schema_invalid",
  "program_digest": "sha256:... or null",
  "authorizer_id": "customer:... or null",
  "claim_boundary": "typed_reachability_attempt_budget_and_effect_concurrency_not_intent_safety_effect_truth_or_complete_mediation"
}
```

Several hostile artifacts carry valid signatures over invalid payloads. They
ensure an implementation does not confuse signature validity with canonical
program acceptance.

### 6.2 Runtime traces

`runtime.store_configurations` supplies store-owned clocks, verification
policies, key roles/statuses, status-oracle mode, and authenticated profile
matcher mode. `runtime.admission_binding` gives the exact structured-identity
and body-digest fixtures plus deterministic `execution_program` resources.
`runtime.programs` maps every base, successor, hostile successor, total-ceiling,
and duplicate-unit fixture to its exact verified program and digest. Every trace
starts from empty runtime state. Apply each `operation` in order and compare both
`expect.result` and the complete `expect.state`. A refused step MUST leave that
state unchanged.

The 16 traces cover store-owned policy and time, key role/status, the closed
four-field registration context, authenticated profile evidence and legacy
assertion refusal, exact actions, current status at reserve and begin,
fail-closed pre-entry release, admission expiry capping, outcome-specific
dependencies, budget reservation and consumption, duplicate unit labels,
indeterminate reconciliation, divergent effect separation, ordinary-path
bypass, indexed and total occurrence ceilings, deterministic structured-ID
snapshot sealing, prebuilt-unbound and relink refusal, authorization-digest
ownership, exact version-plus-one supersession, frozen bindings, fresh
authorization, and fresh successor state.

Regenerate or validate byte-for-byte from the repository root:

```sh
node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-program.mjs

node --import ./scripts/ts-loader/register.mjs \
  conformance/vectors/generate-bounded-execution-program.mjs --check

node --import ./scripts/ts-loader/register.mjs --test \
  packages/gate/execution-program-runtime-trace-replay.test.ts

node --import ./scripts/ts-loader/register.mjs --test \
  packages/gate/bounded-execution-program.test.ts \
  packages/gate/execution-program-admission-store.test.ts

npm run typecheck:rest
```

The bundled loader is required while the bounded-program reference module is a
TypeScript-first source module.

## 7. Reference implementation status

The Apache-2.0 same-team reference implements closed program construction,
normalization, Ed25519 signing and verification, store-owned registration
verification, authenticated profile matching, current-status processing,
deterministic AdmissionSnapshot binding, and the program-aware in-memory and
PostgreSQL admission surfaces. The repository also includes language-neutral
vectors and bounded state-machine analysis.

PostgreSQL status is local-conformance only. The adapter and SQL RPC contract
are covered by an opt-in lifecycle test against a real PostgreSQL instance when
`ADMISSION_STORE_POSTGRES_TEST_URL` is configured. A passing local test is
same-team implementation and regression evidence for that checkout and test
database; it is not evidence of an independent implementation, cross-vendor
interoperability, managed service, durable production deployment, or complete
mediation of production mutation paths.

## 8. Claim boundary

Passing every syntax case establishes that an implementation agrees with these
canonical bytes, signatures, closed-shape checks, context bindings, and time
boundaries. Passing every runtime trace establishes agreement with the abstract
store-owned registration, authenticated action matching, current-status
handling, admission-resource binding, total-history and indexed-count rules,
authorization fence, typed budgets, provider-entry concurrency ceiling, and
state transitions encoded by those traces.

It does not establish:

- that natural-language intent was understood or correctly compiled;
- that an authorization digest proves a human ceremony, identity, consent,
  comprehension, or display integrity;
- that an action profile is sound;
- that a plan is safe, lawful, optimal, or free of prompt injection;
- that provider evidence, observed effects, or production event chronology are
  true;
- that every mutation path was mediated by Gate;
- that a production store is durable, atomic, or linearizable;
- why an observed effect diverged;
- independent implementation, cross-vendor interoperability, deployment,
  standardization, certification, or legal effect.

The honest claim is: an occurrence was or was not admitted under one exact
signed execution program according to this typed reachability, attempt-budget,
and concurrent-effect contract. It is not “intent verified,” “prompt injection
detected,” or “effect truth proven.”
