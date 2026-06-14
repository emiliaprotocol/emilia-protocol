<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 EMILIA Protocol, Inc. -->

# EMILIA Eye Advisory Specification

**Implementer-facing companion to the Eye Internet-Draft.**

| | |
|---|---|
| **Status** | Experimental |
| **Audience** | Implementers of Eye observation sources, Eye operators, and Enforcement-Point (Guard) integrators |
| **Wire-format tags** | `eye-observation-v1`, `eye-advisory-v1` |
| **Companion to** | the Eye Internet-Draft (individual submission, work in progress) |
| **Related** | the EP authorization-receipt draft (`EP-RECEIPT-v1`); `docs/architecture/EMILIA_EYE.md`; `docs/api/EYE_API.md`; `PIPs/PIP-005-eye.md` |

> **The Law.** Eye never makes the final trust decision. Eye warns. EP verifies.
> Signoff owns. If Eye is ever the sole gate between an entity and an action, the
> integration is non-conformant. Everything below is constrained by this invariant.

This document is the normative, schema-level companion to the Eye draft. The draft
states *what Eye is and why*; this document states *what an implementer writes down
and tests against*. It defines the Observation and Advisory schemas, the signal
registry, the `status` → `recommended_action` → posture mapping table, the
"never the sole gate" conformance check as a testable assertion, and the Eye → Guard
escalation contract.

Eye is an **advisory profile**, not the trust core. It composes on top of the shared
verifier core that EP profiles verify against; it does not own that core. Eye supplies
a contextual signal that a separate Enforcement Point (the Guard) MAY consume as one
input among several. Eye produces no allow/deny verdict and is never authoritative on
its own.

---

## 1. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they
appear in all capitals, as shown here.

**Observation.** A discrete, TTL-bounded signal submitted by a trusted source about
a specific scope. The raw input to Eye.

**Advisory.** The output of Eye's evaluation for a scope: a status, reason codes, a
recommended action, and the set of contributing observations. TTL-bounded and
recomputed; never a standing artifact.

**Scope.** The `(scope_type, scope_ref)` pair an observation or advisory concerns,
disambiguated by `scope_binding_hash`.

**Eye operator.** The party that runs an Eye deployment, ingests observations from
trusted sources, and serves advisories. Authenticated per-tenant.

**Enforcement Point (Guard).** The EP component that consumes a policy decision and
enforces it (`allow`, `allow_with_signoff`, `deny`, `observe`). Eye is one input to
the policy the Guard enforces; the Guard, not Eye, decides.

**Posture.** The enforcement strength the Guard applies to an action: the assurance
level required, whether signoff is required, and whether the action is held for human
review.

**Integrity binding (current).** Observations and advisories are **hash-bound**
(SHA-256 over canonical JSON with alphabetically sorted keys) via `scope_binding_hash`
and `advisory_hash`. They are **not** asymmetrically signed in v1. See
[Section 9](#9-signing-status-and-limits-honest). Anything stated as "verifiable
offline" in this document is explicitly scoped to the receipt the Guard emits
(`EP-RECEIPT-v1`), **not** to the advisory itself.

---

## 2. Observation Schema (`eye-observation-v1`)

An observation is the raw input. Sources submit observations; they MUST NOT submit
advisories. Advisories are computed only by the Eye operator.

```json
{
  "eye_version": "eye-observation-v1",
  "observation_id": "obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
  "source_id": "fraud-signal-provider-alpha",
  "source_type": "partner",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "signal_code": "device_fingerprint_changed",
  "severity": "high",
  "evidence_ref": "https://signals.provider-alpha.com/cases/case-2026-4491",
  "detail": {
    "previous_fingerprint_hash": "a1b2c3d4e5f6",
    "current_fingerprint_hash": "f6e5d4c3b2a1",
    "confidence": 0.92
  },
  "observed_at": "2026-03-25T18:42:00Z",
  "expires_at": "2026-03-26T18:42:00Z",
  "created_at": "2026-03-25T18:42:01Z"
}
```

### 2.1 Fields

| Field | Type | Req. | Rules |
|---|---|:--:|---|
| `eye_version` | string | MUST | Constant `eye-observation-v1`. |
| `observation_id` | UUID | MUST | Operator-assigned. Unique per tenant. |
| `source_id` | string | MUST | MUST match a source registered as trusted for the tenant. |
| `source_type` | enum | MUST | `internal` \| `partner` \| `regulatory` \| `infrastructure`. MUST match the registered source's type. |
| `scope_type` | enum | MUST | `entity` \| `action` \| `resource` \| `environment`. |
| `scope_ref` | string | MUST | Non-empty, ≤ 512 chars. Reference to the scoped object. |
| `scope_binding_hash` | string | MUST | SHA-256 over the canonical scope material (see [Section 4](#4-scope-binding)). Hex, `sha256:`-prefixed. |
| `signal_code` | string | MUST | MUST match a registered entry in the signal registry ([Section 5](#5-signal-registry)). Unknown codes MUST be rejected (`UNKNOWN_SIGNAL_CODE`). |
| `severity` | enum | MUST | `info` \| `low` \| `medium` \| `high` \| `critical`. SHOULD be consistent with the signal's registered severity floor. |
| `evidence_ref` | string | SHOULD | Pointer to supporting evidence (URL, document ID, external case number). |
| `detail` | object | MAY | Structured, signal-type-specific payload. Defaults to `{}`. |
| `observed_at` | ISO 8601 | MUST | When the source observed the signal. MUST NOT be in the future by more than 60 s. |
| `expires_at` | ISO 8601 | MUST | TTL expiry. Inactive after this time. Derived from `observed_at + ttl_seconds`, clamped to the observation TTL bounds. |
| `created_at` | ISO 8601 | MUST | When Eye recorded the observation. |

### 2.2 Constraints

- An observation MUST NOT carry a `status`, `recommended_action`, or any decision
  field. Sources observe; they do not advise.
- The store is append-only. Observations MUST NOT be mutated after `created_at`.
  Correction is by superseding observation plus, where appropriate, a suppression.
- A source MUST NOT submit observations for a `source_type` it is not registered for
  (`SOURCE_TYPE_MISMATCH`).
- Idempotency key is `(source_id, scope_ref, signal_code, observed_at)`; a duplicate
  MUST return `DUPLICATE_OBSERVATION`.

---

## 3. Advisory Schema (`eye-advisory-v1`)

An advisory is the computed output for a scope. It is the only object the Guard's
policy layer reads from Eye.

```json
{
  "eye_version": "eye-advisory-v1",
  "advisory_id": "adv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "status": "elevated",
  "reason_codes": ["device_fingerprint_changed", "high_severity_signal_active"],
  "contributing_observations": ["obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f"],
  "recommended_action": "step_up_auth",
  "detail": {
    "highest_severity": "high",
    "active_signal_codes": ["device_fingerprint_changed"],
    "suppressed_count": 0
  },
  "advisory_hash": "sha256:5f0e...c1a4",
  "issued_at": "2026-03-25T19:00:00Z",
  "expires_at": "2026-03-25T20:00:00Z",
  "superseded_by": null
}
```

### 3.1 Fields

| Field | Type | Req. | Rules |
|---|---|:--:|---|
| `eye_version` | string | MUST | Constant `eye-advisory-v1`. |
| `advisory_id` | UUID | MUST | Operator-assigned. |
| `scope_type` | enum | MUST | Same domain as the observation. |
| `scope_ref` | string | MUST | The scope this advisory concerns. |
| `scope_binding_hash` | string | MUST | MUST equal the binding computed for `(scope_type, scope_ref, context)`. The Guard MUST recompute and compare (see [Section 7.3](#73-binding-check-mandatory)). |
| `status` | enum | MUST | `clear` \| `caution` \| `elevated` \| `review_required`. |
| `reason_codes` | string[] | MUST | MUST be non-empty for any non-`clear` status. MUST be empty `[]` for `clear`. |
| `contributing_observations` | UUID[] | MUST | `observation_id` values that resolved to this status. MUST be empty for `clear`. |
| `recommended_action` | enum | MUST | `none` \| `log` \| `step_up_auth` \| `require_signoff` \| `escalate` (see [Section 6](#6-status--recommended_action--posture-mapping)). |
| `detail` | object | MAY | `highest_severity`, `active_signal_codes`, `suppressed_count`, and signal-specific context. |
| `advisory_hash` | string | MUST | SHA-256 over the canonical advisory fields with alphabetically sorted keys, **excluding** `advisory_hash` and `superseded_by`. Integrity binding, not a signature. |
| `issued_at` | ISO 8601 | MUST | When the advisory was computed. |
| `expires_at` | ISO 8601 | MUST | Advisory TTL. Consumers MUST treat a past-`expires_at` advisory as stale and re-query ([Section 7.2](#72-freshness-check-mandatory)). |
| `superseded_by` | UUID \| null | MUST | `advisory_id` of a newer evaluation, or `null`. |

### 3.2 Status resolution (deterministic)

Status is resolved from the **active, non-suppressed** observations for the scope by
highest severity present:

| Highest active severity | Resolved `status` |
|---|---|
| `critical` | `review_required` |
| `high` | `elevated` |
| `medium` | `caution` |
| `low` or `info` | `caution` |
| (none active) | `clear` |

Suppressed observations are excluded from resolution but counted in
`detail.suppressed_count`. A suppression that has expired re-exposes its underlying
observation and adds the `suppression_expired` computed reason code.

---

## 4. Scope Binding

`scope_binding_hash` binds an observation or advisory to one specific scope context so
that a signal raised for scope A cannot be replayed against scope B, even when
`scope_ref` values collide across `scope_type` values.

The implementation computes the hash over the canonical scope-binding fields
(`lib/eye/binding.js`, `EYE_SCOPE_BINDING_FIELDS`): a JSON object built from
`actor_ref`, `subject_ref`, `action_type`, `target_ref`, `issuer_ref`,
`context_hash`, `issued_at`, `expires_at`, with **alphabetically sorted keys**, then
SHA-256:

```
scope_binding_hash = "sha256:" + hex( SHA-256( JSON_sorted_keys( {
  action_type, actor_ref, context_hash, expires_at,
  issuer_ref, issued_at, subject_ref, target_ref
} ) ) )
```

Fields not applicable to a scope type MUST be present and set to `null` (not omitted),
so the canonical form is stable.

**Rules.**

- The Eye operator MUST compute every binding through the single canonical function;
  no other code path may compute it (this is enforced in the reference
  implementation).
- The Guard MUST recompute the binding from the action context it is gating and reject
  any advisory whose `scope_binding_hash` does not match ([Section 7.3](#73-binding-check-mandatory)).
- The binding is an **integrity** mechanism only. It proves the advisory was computed
  for this scope **if and only if** the verifier independently recomputes it. It is not
  an authenticity proof of the issuer; see [Section 9](#9-signing-status-and-limits-honest).

---

## 5. Signal Registry

Every `signal_code` MUST be registered before it can appear in an observation. The
registry is the source of truth for the code, its expected scope type, the severity
the operator treats as the floor for that signal, and the reason code it contributes
to an advisory.

`confidence_class` is one of `deterministic` (an external authority asserted the fact,
e.g. a sanctions list hit), `trusted` (a registered partner's measured signal), or
`heuristic` (a model- or pattern-derived inference). The Guard MAY weight heuristic
signals lower than deterministic ones, but MUST NOT treat any class as authoritative on
its own.

### 5.1 Initial registry (v1)

| `signal_code` | Category | Default `scope_type` | Severity floor | `confidence_class` | Reason code emitted |
|---|---|---|---|---|---|
| `sanctions_match` | Government | entity | critical | deterministic | `external_regulatory_alert` |
| `watchlist_match` | Government | entity | high | deterministic | `external_regulatory_alert` |
| `regulatory_action` | Government | entity | critical | deterministic | `external_regulatory_alert` |
| `pep_match` | Government | entity | medium | trusted | `authority_under_review` |
| `adverse_media` | Government | entity | medium | heuristic | `authority_under_review` |
| `payment_destination_flagged` | Financial | action | high | trusted | `payment_destination_flagged` |
| `high_value_transfer` | Financial | action | medium | deterministic | `velocity_anomaly` |
| `velocity_anomaly` | Financial | action | medium | heuristic | `velocity_anomaly` |
| `structuring_indicator` | Financial | action | high | heuristic | `velocity_anomaly` |
| `cross_border_risk` | Financial | action | medium | trusted | `geographic_anomaly` |
| `privilege_escalation` | Enterprise | entity | high | trusted | `authority_under_review` |
| `anomalous_access_pattern` | Enterprise | entity | medium | heuristic | `geographic_anomaly` |
| `data_exfiltration_signal` | Enterprise | action | high | heuristic | `payment_destination_flagged` |
| `insider_threat_indicator` | Enterprise | entity | high | heuristic | `authority_under_review` |
| `device_fingerprint_changed` | Enterprise | entity | high | trusted | `device_fingerprint_changed` |
| `geographic_anomaly` | Enterprise | environment | medium | heuristic | `geographic_anomaly` |
| `temporal_anomaly` | Enterprise | action | medium | heuristic | `temporal_anomaly` |
| `agent_drift` | AI / Agent | entity | medium | heuristic | `authority_under_review` |
| `prompt_injection_attempt` | AI / Agent | action | high | heuristic | `authority_under_review` |
| `autonomous_action_anomaly` | AI / Agent | action | high | heuristic | `authority_under_review` |
| `delegation_chain_break` | AI / Agent | entity | high | deterministic | `authority_under_review` |
| `credential_compromise` | Issuer | entity | critical | deterministic | `credential_issuer_compromised` |
| `issuer_trust_degradation` | Issuer | resource | high | trusted | `credential_issuer_compromised` |
| `revocation_cascade` | Issuer | resource | high | deterministic | `credential_issuer_compromised` |
| `stale_attestation` | Issuer | entity | low | deterministic | `credential_expiry_imminent` |
| `binding_mismatch` | Issuer | entity | high | deterministic | `credential_issuer_compromised` |
| `infrastructure_degraded` | Infrastructure | environment | medium | trusted | `infrastructure_degraded` |

### 5.2 Computed reason codes

These are emitted by the evaluator, not carried by a single observation:

| Reason code | Condition |
|---|---|
| `high_severity_signal_active` | At least one active observation is `high` or `critical`. |
| `multiple_signals_active` | More than one distinct `signal_code` is active for the scope. |
| `suppression_expired` | A previously active suppression has expired, re-exposing its observation. |

### 5.3 Registration rules

- A new `signal_code` MUST be added to the registry (category, default scope type,
  severity floor, confidence class, reason code) before any source may submit it.
- The `severity` on an observation MUST NOT be lower than the registry severity floor
  for its `signal_code`; the operator SHOULD clamp upward and record the original.
- Registry entries are additive. Renaming or removing a `signal_code` MUST be a new
  spec revision, never a silent change.

---

## 6. `status` → `recommended_action` → Posture Mapping

`recommended_action` is **advice**, not a command. The Guard's policy maps the
advisory onto an internal policy action and a posture. The table below is the default
mapping the reference implementation ships; a deployment MAY tighten it but MUST NOT
loosen it (e.g. it MUST NOT map `review_required` to a non-escalating posture).

| `status` | `recommended_action` | Guard policy action (`EYE_POLICY_ACTIONS`) | Posture effect | Blocks? |
|---|---|---|---|---|
| `clear` | `none` | `allow_normal_flow` | Default path. No change. | No |
| `caution` | `log` | `allow_normal_flow` | Advisory logged into receipt context. No requirement change. | No |
| `elevated` | `step_up_auth` | `require_strict_ep_handshake` | Raise required assurance (e.g. to phishing-resistant MFA); MAY add presentations. | No (tightens) |
| `elevated` | `require_signoff` | `require_accountable_signoff` | Force `allow_with_signoff` even where the base action would be `allow`. | Holds for signoff |
| `review_required` | `require_signoff` | `require_accountable_signoff` | Force `allow_with_signoff`; named human MUST own the outcome. | Holds for signoff |
| `review_required` | `escalate` | `hold_for_manual_review` | Hold the action for manual review/handling out of band. | Holds for review |

Notes:

- `recommended_action` is bounded by `status`: an evaluator MUST NOT emit `escalate`
  for `caution`, nor `none` for `review_required`. The valid pairs are exactly the rows
  above.
- A non-`clear` advisory can only ever **tighten** the Guard's posture. It can never
  downgrade a `deny`, never weaken a required assurance level, and never remove a
  signoff requirement that the base policy already imposes. This is the monotonicity
  property formalized in [Section 8](#8-conformance-never-the-sole-gate).
- `caution`/`log` exists precisely so a deployment can run Eye in shadow without
  changing enforcement while it builds confidence in a signal source.

---

## 7. Eye → Guard Escalation Contract

This section defines exactly how a non-`clear` advisory tightens an Enforcement-Point
decision. The Guard's decision vocabulary is `allow`, `allow_with_signoff`, `deny`,
`observe`. Eye is one input to the policy that produces that decision; Eye produces no
decision itself.

### 7.1 Where Eye plugs in

```
                  base policy decision (no Eye)
                            │
   Eye advisory  ───────────┼───────────►  posture combinator  ───►  final Guard decision
   (status, action)         │                    (tighten-only)        {allow, allow_with_signoff,
                            │                                            deny, observe}
   recompute binding ◄──────┘
```

The Guard:

1. Computes its **base decision** from policy as if Eye did not exist.
2. Queries Eye for the advisory on the action's scope.
3. Applies the freshness, binding, and source checks below.
4. Combines the advisory's posture with the base decision using the **tighten-only**
   combinator ([Section 7.4](#74-tighten-only-combinator)).
5. Records the advisory (`advisory_id`, `status`, `reason_codes`,
   `scope_binding_hash`) in the receipt context (`EP-RECEIPT-v1` claim contexts) so the
   reason for any tightening is verifiable after the fact.

### 7.2 Freshness check (MUST)

If `advisory.expires_at` is in the past, the advisory is stale. The Guard MUST NOT use
a stale advisory to *relax* anything and MUST re-query. If Eye is unreachable, the
Guard MUST proceed on its base decision (Eye is fail-open as an input: its
*unavailability* never blocks, and its *staleness* never relaxes). Eye being down MUST
NOT, by itself, deny an action — because Eye is never the sole gate.

### 7.3 Binding check (MUST)

The Guard MUST recompute `scope_binding_hash` from the action context it is gating and
compare it to `advisory.scope_binding_hash`. On mismatch the Guard MUST discard the
advisory (treat as `clear`/absent) and SHOULD log a `binding_mismatch` event. A
mismatched advisory MUST NOT tighten *or* relax the decision; it is simply not for this
action.

### 7.4 Tighten-only combinator

Order the postures by strength:

```
allow  <  observe  <  allow_with_signoff  <  hold_for_manual_review  <  deny
```

The final decision is `max(base_decision, eye_posture)` under this ordering, with one
exception: Eye can never *introduce* a `deny` on its own (Eye does not deny). The most
Eye can do is force `allow_with_signoff` or `hold_for_manual_review`. A hard `deny`
comes only from the base policy (e.g. sanctions hit, impossible travel,
known-compromised device).

Concretely:

| Base decision | Eye posture | Final decision |
|---|---|---|
| `allow` | none / `allow_normal_flow` | `allow` |
| `allow` | `require_strict_ep_handshake` | `allow` with raised assurance + added presentations |
| `allow` | `require_accountable_signoff` | `allow_with_signoff` |
| `allow` | `hold_for_manual_review` | held for manual review (no auto-allow) |
| `allow_with_signoff` | any Eye posture | `allow_with_signoff` (or held, if Eye says hold) — never relaxed below signoff |
| `deny` | any Eye posture | `deny` (Eye cannot relax a deny) |
| `observe` (enforcement mode) | any Eye posture | logged only; the would-be decision is recorded but not enforced |

### 7.5 Signoff context propagation (SHOULD)

When Eye contributes to a signoff requirement, the Guard SHOULD include the advisory's
`reason_codes` and `detail` in the signoff challenge's `consequences_summary`, so the
accountable human sees *why* review was triggered (e.g. "signoff required because the
credential issuer was reported compromised — Eye advisory `adv_…`"). This mirrors the
initiator-attestation discipline used elsewhere in EP: the human is told the real
reason, never a fabricated one.

---

## 8. Conformance: "Never the Sole Gate"

The architectural law is testable. An integration is conformant only if the following
assertions all hold. They are stated as predicates over the Guard's decision function
so they can be encoded directly as unit/property tests.

Let:

- `base(a)` = the Guard decision for action `a` with **no** Eye input.
- `final(a, adv)` = the Guard decision for `a` given Eye advisory `adv`.
- `strength(d)` = the rank of decision `d` under
  `allow < observe < allow_with_signoff < hold_for_manual_review < deny`.

### 8.1 Assertion A — Eye cannot be the sole gate (the core check)

> For every action `a` and every advisory `adv`, the decision when Eye is **removed**
> must be at least as strong as a bare `allow`. Removing Eye must never *unblock* an
> action that some non-Eye control would block, and Eye's presence must never be the
> *only* thing standing between the actor and the action.

```
ASSERT  for all a:
          base(a) is well-defined WITHOUT querying Eye
ASSERT  for all a, adv:
          if final(a, adv) blocks a   // i.e. not a plain allow
          then  base(a) blocks a            // base policy also blocks/holds
                OR adv.status != "clear"     // OR Eye merely tightened on top of allow
ASSERT  for all a, adv:
          final(a, adv) == "allow"  implies  base(a) == "allow"
```

The third clause is the operational heart of the law: **the system may only ever reach
a final `allow` when the base policy already reached `allow` on its own.** Eye can take
an `allow` and tighten it; Eye can never manufacture an `allow`. Therefore Eye is never
the sole thing permitting an action, and (by Assertion B) never the sole thing
permitting *or* denying one.

### 8.2 Assertion B — Monotone tighten-only

> An Eye advisory may only raise the strength of the decision, never lower it.

```
ASSERT  for all a, adv:
          strength( final(a, adv) )  >=  strength( base(a) )
```

### 8.3 Assertion C — Eye never originates a deny

> Eye cannot turn an otherwise-permitted action into a hard `deny`. The most Eye can
> force is signoff or manual hold.

```
ASSERT  for all a, adv:
          if base(a) != "deny"  then  final(a, adv) != "deny"
```

### 8.4 Assertion D — Availability fail-open, freshness no-relax

> Eye being unavailable or stale never blocks, and never relaxes.

```
ASSERT  final(a, EYE_UNAVAILABLE) == base(a)
ASSERT  for all a, adv where adv.expires_at < now:
          strength( final(a, adv) )  >=  strength( base(a) )   // stale never relaxes
          AND the Guard re-queries before relying on adv
```

### 8.5 Assertion E — Binding gate

> A binding mismatch makes the advisory inert (neither tightens nor relaxes).

```
ASSERT  for all a, adv where recompute_binding(a) != adv.scope_binding_hash:
          final(a, adv) == base(a)
```

### 8.6 Reference test shape

```js
// pseudo-test; pairs base policy outcomes with every advisory and checks the law
for (const a of representativeActions) {
  const b = guardDecideWithoutEye(a);            // base(a)
  for (const adv of [clear, caution, elevated, reviewRequired, staleAdv, mismatchedAdv]) {
    const f = guardDecideWithEye(a, adv);        // final(a, adv)
    assert(strength(f) >= strength(b));                                  // B
    if (b !== 'deny') assert(f !== 'deny');                             // C
    if (f === 'allow') assert(b === 'allow');                           // A (core)
    if (adv === EYE_UNAVAILABLE) assert(f === b);                       // D
    if (mismatchedBinding(a, adv)) assert(f === b);                     // E
  }
}
```

A deployment claiming Eye conformance MUST ship a passing instance of these
assertions over its own policy surface. Failing any of A–E means the integration is
**non-conformant** and MUST NOT be described as Eye-conformant.

---

## 9. Signing Status and Limits (Honest)

This section states what Eye does **not** yet provide, so implementers do not overclaim.

- **Advisories are not asymmetrically signed in v1.** `scope_binding_hash` and
  `advisory_hash` are SHA-256 integrity bindings over canonical JSON, stored alongside
  the record. They give integrity **only to a verifier that independently recomputes
  them**; they are not a signature and prove nothing about issuer identity on their own.
- **No offline-verifiable advisory credential.** An advisory is plain JSON over an
  authenticated (bearer-token, per-tenant) channel. A third party cannot verify an
  advisory's source and integrity without querying the issuing Eye deployment or
  trusting the transport. The **receipt** the Guard emits (`EP-RECEIPT-v1`) is the
  offline-verifiable artifact; the advisory is an *input* recorded inside it.
- **No issuer-identity binding on the advisory.** The operator is implicit
  (authenticated tenant), not cryptographically asserted in the advisory body.
- **TTL is enforced at query time, not in the object.** A cached past-`expires_at`
  advisory is just an old record; consumers MUST re-query (Assertion D).
- **Append-only at the store.** Mutation of advisories is prevented at the database
  layer (append-only trigger). This protects the audit trail; it is not a substitute
  for signing.

### 9.1 Forward-compatible path (informative, not required for v1)

A future revision MAY make advisories self-verifiable by composing existing standards
rather than inventing an envelope:

- Carry the advisory as a **Security Event Token (RFC 8417)** JWT payload — `iss`,
  `iat`, `jti`, and an `events` member keyed by an Eye event-type URI — signed (JWS)
  with the Eye operator's key, with `scope_binding_hash` inside the signed payload.
- Transmit advisories as **CAEP-style events over an SSF stream** (OpenID Shared
  Signals Framework) for asynchronous push/poll delivery, supplying the verifiable
  scope-binding and the "never the sole gate" invariant that SSF/CAEP deliberately
  leave undefined.

These are composition targets, not commitments. Until then, treat Eye as an
**advisory input** whose authenticity rests on the authenticated channel and whose
durable, verifiable record is the EP receipt.

---

## 10. Security Considerations

- **Sole-gate misuse is the primary risk.** The whole point of [Section 8](#8-conformance-never-the-sole-gate)
  is to make it impossible to ship a system where a `clear` advisory is read as
  "authorized." Integrators MUST encode Assertions A–E as tests; a green build is the
  evidence of conformance, not a claim in prose.
- **Stale-relax and downgrade attacks.** An attacker who can replay an old `clear`
  advisory MUST NOT be able to relax enforcement. Assertions B and D close this:
  advisories only ever tighten, and staleness never relaxes.
- **Cross-scope replay.** The binding check (Assertion E) prevents an advisory raised
  for one scope from affecting another.
- **Source poisoning.** Eye trusts its registered sources. A compromised source can
  raise spurious signals (causing over-tightening) or withhold real ones (causing
  under-tightening). Over-tightening fails safe (more signoff/review). Under-tightening
  is bounded by the fact that Eye is never the sole gate — the base policy still
  applies. Operators SHOULD weight `heuristic`-class signals below `deterministic`
  ones and SHOULD require evidence references for high/critical observations.
- **Advisory integrity without signing.** Because v1 advisories are unsigned
  ([Section 9](#9-signing-status-and-limits-honest)), the durable trust anchor is the
  EP receipt, not the advisory. Do not represent an unsigned advisory as a verifiable
  credential.

---

## 11. Relationship to Other Work

- **EP authorization receipts (`EP-RECEIPT-v1`).** Eye is an input recorded inside the
  receipt; the receipt is the verifiable artifact. Eye does not replace any part of the
  receipt flow.
- **AuthZEN / OPA / Cedar.** Policy-decision semantics live in the PDP. The Guard acts
  as a PEP consuming a PDP decision; Eye supplies one context input to that decision and
  defines no policy language of its own.
- **SET (RFC 8417) and SSF/CAEP.** Candidate composition targets for a future
  signed/transported advisory ([Section 9.1](#91-forward-compatible-path-informative-not-required-for-v1)),
  not reinvented here.
- **RATS / EAT.** Device-posture attestation results MAY be one of Eye's observation
  sources; Eye does not perform attestation.

---

*This is an experimental, individual specification. It describes a profile that
composes on top of a shared verifier core; it does not claim ownership of that core,
working-group adoption, or production deployment.*
