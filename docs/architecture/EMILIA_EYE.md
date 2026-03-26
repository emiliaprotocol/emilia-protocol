# EMILIA Protocol -- Emilia Eye

## What Emilia Eye Is

Emilia Eye is a warning layer that observes contextual signals about entities, actions, and environments and produces advisory outputs for downstream trust decisions. It does not make trust decisions. It does not block actions. It does not grant or deny access. It warns.

Eye ingests observations from trusted sources, evaluates them against registered signal definitions, and emits advisories that downstream systems (EP Handshake, Signoff, or application policy) may use to adjust their enforcement posture. The adjustment is theirs to make. Eye's role ends at the advisory.

### What Eye Is NOT

**Not an access control system.** Eye does not issue allow/deny verdicts. It produces status levels and reason codes. A system that treats Eye advisories as authorization decisions has misunderstood the architecture.

**Not a reputation system.** Eye does not maintain persistent scores or rankings for entities. Observations have TTLs. Advisories expire. There is no cumulative reputation ledger.

**Not a blocking layer.** Eye never prevents an action from executing. It provides information that a policy layer may use to trigger additional verification, escalation, or review. The policy layer decides. Eye informs.

**Not a public reporting system.** Eye does not expose observations or advisories to the entities they concern. Observations flow from trusted sources to the system operator. There is no public-facing scoreboard, no entity lookup, no self-service dispute mechanism in V1.

### The Law

**Eye never makes the final trust decision.**

This is the architectural invariant that governs every design choice in this specification. Eye warns. EP verifies. Signoff owns. If Eye is ever the sole gate between an entity and an action, the integration is non-conformant.

## Why It Exists

### The Signal Gap

EP's trust model is synchronous and binary: at verification time, identity is bound, authority is checked, policy is satisfied, and the handshake is accepted or rejected. This model is correct for point-in-time trust decisions but does not account for contextual signals that accumulate between handshakes.

Examples of contextual signals:

- A credential issuer has been compromised since the last handshake.
- An entity's device fingerprint has changed in a pattern consistent with account takeover.
- An action target (e.g., a payment destination) was flagged by an external fraud signal.
- A geographic or temporal anomaly suggests the entity is not operating in their normal context.

These signals do not invalidate the entity's identity or authority. They raise the question of whether the current trust posture is appropriate for the current context. Eye exists to surface that question.

### What Eye Adds to EP

EP enforces trust requirements at the handshake boundary. Eye extends the trust surface by injecting contextual awareness into the policy evaluation path. When Eye reports a non-clear status for a scope, EP policy may respond by:

- Requiring a higher assurance level for authentication.
- Triggering signoff for an action class that would not normally require it.
- Adding additional presentations to the handshake.
- Logging the advisory for post-hoc audit without changing the enforcement path.

The response is always defined by EP policy. Eye does not prescribe the response.

## Object Model

### Observation

An observation is a discrete signal submitted by a trusted source about a specific scope. It is the raw input to Eye.

| Field | Type | Description |
|---|---|---|
| `observation_id` | UUID | Unique identifier |
| `source_id` | string | Identifier of the trusted source that submitted this observation |
| `source_type` | enum | `internal`, `partner`, `regulatory`, `infrastructure` |
| `scope_type` | enum | `entity`, `action`, `resource`, `environment` |
| `scope_ref` | string | Reference to the scoped object (entity_ref, action_type, resource_ref, etc.) |
| `scope_binding_hash` | string | SHA-256 hash binding the observation to a specific scope context |
| `signal_code` | string | Registered signal identifier (e.g., `credential_issuer_compromised`, `device_fingerprint_changed`) |
| `severity` | enum | `info`, `low`, `medium`, `high`, `critical` |
| `evidence_ref` | string | Reference to supporting evidence (URL, document ID, external case number) |
| `detail` | JSON | Structured detail specific to the signal type |
| `observed_at` | ISO 8601 | When the observation was made |
| `expires_at` | ISO 8601 | TTL expiry; observation is inactive after this time |
| `created_at` | ISO 8601 | When the observation was recorded in Eye |

### Advisory

An advisory is the output of Eye's evaluation. It represents the current assessed status for a specific scope, derived from one or more active observations.

| Field | Type | Description |
|---|---|---|
| `advisory_id` | UUID | Unique identifier |
| `scope_type` | enum | `entity`, `action`, `resource`, `environment` |
| `scope_ref` | string | Reference to the scoped object |
| `scope_binding_hash` | string | SHA-256 hash binding the advisory to the scope context |
| `status` | enum | `clear`, `caution`, `elevated`, `review_required` |
| `reason_codes` | array | List of reason codes explaining the status (never empty for non-clear) |
| `contributing_observations` | array | List of `observation_id` values that contributed to this advisory |
| `recommended_action` | enum | `none`, `log`, `step_up_auth`, `require_signoff`, `escalate` |
| `detail` | JSON | Structured advisory detail |
| `issued_at` | ISO 8601 | When the advisory was computed |
| `expires_at` | ISO 8601 | Advisory TTL; consumers must re-check after expiry |
| `superseded_by` | UUID | If this advisory has been replaced by a newer evaluation, reference to successor |

### Suppression

A suppression is a local, auditable override that marks a specific observation or advisory as acknowledged and not actionable for a defined period. Suppressions are scoped to the operator's deployment. They do not propagate to other deployments or to the observation source.

| Field | Type | Description |
|---|---|---|
| `suppression_id` | UUID | Unique identifier |
| `target_type` | enum | `observation`, `advisory` |
| `target_id` | UUID | The observation or advisory being suppressed |
| `scope_ref` | string | The scope this suppression applies to |
| `reason` | string | Human-readable justification for the suppression |
| `suppressed_by` | string | Entity reference of the actor who created the suppression |
| `authority_class` | string | Authority class of the suppressing actor |
| `expires_at` | ISO 8601 | Suppression expiry; the observation/advisory becomes active again after this time |
| `created_at` | ISO 8601 | When the suppression was created |

## Status Model

Eye produces four status levels. Each level has a defined meaning and a defined relationship to downstream action.

| Status | Meaning | Downstream Implication |
|---|---|---|
| `clear` | No active observations for this scope. No signals of concern. | No additional enforcement required. Policy proceeds on its default path. |
| `caution` | Low-severity observations exist. Context has changed but not in a way that suggests immediate risk. | Policy may log the advisory. No enforcement change required. |
| `elevated` | Medium-to-high severity observations exist. Context suggests increased risk that warrants additional verification. | Policy may step up authentication, require additional presentations, or trigger signoff for action classes that would not normally require it. |
| `review_required` | Critical observations exist. Context suggests the action should not proceed without explicit human review. | Policy should require signoff or escalation. The action class is effectively elevated to signoff-required for this specific instance. |

### Status Resolution

When multiple active observations exist for a scope, the status is resolved to the highest severity level present:

- Any `critical` observation produces `review_required`.
- Any `high` observation produces `elevated` (unless a critical is also present).
- Any `medium` observation produces `caution` (unless a higher severity is also present).
- Only `info` or `low` observations produce `caution`.
- No active observations produce `clear`.

Suppressed observations are excluded from status resolution.

## Scope Binding

Every observation and advisory is bound to a specific scope via `scope_type`, `scope_ref`, and `scope_binding_hash`. The binding hash is computed from the canonical scope material:

```
scope_binding_hash = SHA-256(scope_type + ":" + scope_ref + ":" + context_material)
```

Where `context_material` is scope-type-specific:

- `entity`: entity_ref + tenant_id
- `action`: action_type + resource_ref
- `resource`: resource_ref + resource_type
- `environment`: environment_id + region

The scope binding ensures that observations cannot be applied to a different scope than the one they were created for, even if scope_ref values collide across scope types.

## TTL Defaults

All Eye objects are time-bounded. There are no permanent observations, advisories, or suppressions.

| Object | Default TTL | Minimum | Maximum |
|---|---|---|---|
| Observation | 24 hours | 5 minutes | 30 days |
| Advisory | 1 hour | 5 minutes | 24 hours |
| Suppression | 7 days | 1 hour | 90 days |

Advisory TTLs are intentionally shorter than observation TTLs. An advisory reflects a point-in-time evaluation. If the underlying observations change (new observations arrive, existing ones expire, suppressions are applied), the advisory must be recomputed. Consumers that cache advisories beyond their TTL are operating on stale data.

## Relationship to EP

Eye is an input to EP, not a replacement for any part of it.

```
Observations (from trusted sources)
    |
    v
Emilia Eye (evaluates, produces advisories)
    |
    v
EP Policy Layer (reads advisories, adjusts enforcement posture)
    |
    v
EP Handshake (enforces adjusted requirements)
    |
    v
EP Signoff (if policy requires human accountability)
```

Eye advisories are consumed by the EP policy layer during policy resolution. The policy may include rules that reference Eye status:

- `if eye_status == "review_required" then signoff_required = true`
- `if eye_status == "elevated" then required_assurance = "high"`
- `if eye_status != "clear" then log_advisory = true`

These rules are written by the policy author. Eye does not inject rules into policy. It provides data that policy rules may reference.

### Integration Points

1. **Policy resolution.** At handshake verification time, the policy resolver queries Eye for the current advisory on the handshake's scope. The advisory status and reason codes are available as policy inputs.
2. **Signoff challenge context.** If Eye's advisory contributed to a signoff requirement, the advisory detail is included in the signoff challenge's `consequences_summary` so the accountable human can see why additional review was triggered.
3. **Audit trail.** Eye advisories that were active at the time of a handshake are recorded in the handshake event log for post-hoc analysis.
