# EMILIA Protocol -- Eye API

## Scope

This document specifies the HTTP API for Emilia Eye. All endpoints are scoped to the authenticated tenant. All requests require a valid bearer token with the appropriate Eye permission scope.

Base path: `/eye`

---

## 1. POST /eye/observations

Submit a new observation from a trusted source.

### Request

```json
{
  "source_id": "fraud-signal-provider-alpha",
  "source_type": "partner",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "signal_code": "device_fingerprint_changed",
  "severity": "high",
  "evidence_ref": "https://signals.provider-alpha.com/cases/case-2026-4491",
  "detail": {
    "previous_fingerprint_hash": "a1b2c3d4e5f6",
    "current_fingerprint_hash": "f6e5d4c3b2a1",
    "change_detected_at": "2026-03-25T18:42:00Z",
    "confidence": 0.92
  },
  "observed_at": "2026-03-25T18:42:00Z",
  "ttl_seconds": 86400
}
```

### Required Fields

| Field | Type | Constraints |
|---|---|---|
| `source_id` | string | Must match a registered trusted source for this tenant |
| `source_type` | enum | `internal`, `partner`, `regulatory`, `infrastructure` |
| `scope_type` | enum | `entity`, `action`, `resource`, `environment` |
| `scope_ref` | string | Non-empty. Max 512 characters. |
| `signal_code` | string | Must match a registered signal definition |
| `severity` | enum | `info`, `low`, `medium`, `high`, `critical` |
| `observed_at` | ISO 8601 | Must not be in the future by more than 60 seconds |

### Optional Fields

| Field | Type | Default |
|---|---|---|
| `evidence_ref` | string | null |
| `detail` | JSON | `{}` |
| `ttl_seconds` | integer | 86400 (24 hours). Clamped to [300, 2592000]. |

### Response (201 Created)

```json
{
  "observation_id": "obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "expires_at": "2026-03-26T18:42:00Z",
  "created_at": "2026-03-25T18:42:01Z"
}
```

### Error Responses

| Status | Code | Description |
|---|---|---|
| 400 | `INVALID_OBSERVATION` | Request body failed validation |
| 400 | `UNKNOWN_SIGNAL_CODE` | `signal_code` does not match a registered signal definition |
| 403 | `SOURCE_NOT_TRUSTED` | `source_id` is not registered as a trusted source for this tenant |
| 403 | `SOURCE_TYPE_MISMATCH` | `source_type` does not match the registered source's type |
| 409 | `DUPLICATE_OBSERVATION` | Idempotency conflict; an observation with matching source_id + scope_ref + signal_code + observed_at already exists |
| 422 | `TTL_OUT_OF_RANGE` | `ttl_seconds` is outside the allowed range after clamping |

---

## 2. POST /eye/check

Query Eye for the current advisory on a specific scope. This is the primary integration point for EP policy resolution.

### Request

```json
{
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "context": {
    "action_type": "payment_destination_change",
    "resource_ref": "payee:pay_44f1a2b3",
    "environment": "production"
  }
}
```

### Required Fields

| Field | Type | Constraints |
|---|---|---|
| `scope_type` | enum | `entity`, `action`, `resource`, `environment` |
| `scope_ref` | string | Non-empty |

### Optional Fields

| Field | Type | Description |
|---|---|---|
| `context` | JSON | Additional context for advisory evaluation. Passed to signal evaluation rules but does not change scope binding. |

### Response (200 OK)

```json
{
  "advisory_id": "adv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "status": "elevated",
  "reason_codes": [
    "device_fingerprint_changed",
    "high_severity_signal_active"
  ],
  "recommended_action": "step_up_auth",
  "contributing_observation_count": 1,
  "detail": {
    "highest_severity": "high",
    "active_signal_codes": ["device_fingerprint_changed"],
    "suppressed_count": 0
  },
  "issued_at": "2026-03-25T19:00:00Z",
  "expires_at": "2026-03-25T20:00:00Z"
}
```

When no active observations exist for the scope:

```json
{
  "advisory_id": "adv_0000aaaa-bbbb-cccc-dddd-eeee0000ffff",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "status": "clear",
  "reason_codes": [],
  "recommended_action": "none",
  "contributing_observation_count": 0,
  "detail": {},
  "issued_at": "2026-03-25T19:00:00Z",
  "expires_at": "2026-03-25T20:00:00Z"
}
```

### Error Responses

| Status | Code | Description |
|---|---|---|
| 400 | `INVALID_CHECK_REQUEST` | Request body failed validation |
| 404 | `SCOPE_NOT_FOUND` | The scope_ref does not match any known entity, action, resource, or environment |

---

## 3. GET /eye/advisories/{id}

Retrieve a specific advisory by ID. Used for audit trail reconstruction and suppression reference.

### Path Parameters

| Parameter | Type | Description |
|---|---|---|
| `id` | UUID | The `advisory_id` to retrieve |

### Response (200 OK)

```json
{
  "advisory_id": "adv_1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "scope_type": "entity",
  "scope_ref": "entity:usr_8a3f2b1c",
  "scope_binding_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "status": "elevated",
  "reason_codes": [
    "device_fingerprint_changed",
    "high_severity_signal_active"
  ],
  "recommended_action": "step_up_auth",
  "contributing_observations": [
    {
      "observation_id": "obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
      "signal_code": "device_fingerprint_changed",
      "severity": "high",
      "source_type": "partner",
      "observed_at": "2026-03-25T18:42:00Z",
      "expires_at": "2026-03-26T18:42:00Z"
    }
  ],
  "detail": {
    "highest_severity": "high",
    "active_signal_codes": ["device_fingerprint_changed"],
    "suppressed_count": 0
  },
  "issued_at": "2026-03-25T19:00:00Z",
  "expires_at": "2026-03-25T20:00:00Z",
  "superseded_by": null
}
```

### Error Responses

| Status | Code | Description |
|---|---|---|
| 404 | `ADVISORY_NOT_FOUND` | No advisory exists with this ID |

---

## 4. POST /eye/suppressions

Create a suppression that marks a specific observation or advisory as acknowledged and not actionable for a defined period.

### Request

```json
{
  "target_type": "observation",
  "target_id": "obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
  "reason": "Device change verified by support ticket SUPPORT-4491. User confirmed new device via out-of-band call.",
  "ttl_seconds": 604800
}
```

### Required Fields

| Field | Type | Constraints |
|---|---|---|
| `target_type` | enum | `observation`, `advisory` |
| `target_id` | UUID | Must reference an existing, non-expired observation or advisory |
| `reason` | string | Non-empty. Min 20 characters. Must describe why the suppression is justified. |

### Optional Fields

| Field | Type | Default |
|---|---|---|
| `ttl_seconds` | integer | 604800 (7 days). Clamped to [3600, 7776000]. |

### Response (201 Created)

```json
{
  "suppression_id": "sup_a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "target_type": "observation",
  "target_id": "obs_f7e8d9c0-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
  "scope_ref": "entity:usr_8a3f2b1c",
  "suppressed_by": "entity:admin_j.chen",
  "authority_class": "security_analyst",
  "expires_at": "2026-04-01T19:00:00Z",
  "created_at": "2026-03-25T19:00:00Z"
}
```

The `suppressed_by` and `authority_class` fields are derived from the authenticated caller's session. They cannot be specified in the request.

### Error Responses

| Status | Code | Description |
|---|---|---|
| 400 | `INVALID_SUPPRESSION` | Request body failed validation |
| 400 | `REASON_TOO_SHORT` | `reason` is shorter than 20 characters |
| 403 | `SUPPRESSION_NOT_AUTHORIZED` | Authenticated caller does not have the required authority class to suppress this target |
| 404 | `TARGET_NOT_FOUND` | `target_id` does not reference an existing observation or advisory |
| 409 | `TARGET_ALREADY_SUPPRESSED` | An active suppression already exists for this target |
| 410 | `TARGET_EXPIRED` | The target observation or advisory has already expired |

---

## Reason Codes

Reason codes are strings that explain why a non-clear advisory was issued. Every non-clear advisory carries at least one reason code. Reason codes are namespaced by signal type.

### Signal-Derived Reason Codes

| Code | Severity Trigger | Description |
|---|---|---|
| `credential_issuer_compromised` | critical | The issuer of a credential used by this entity has been reported compromised |
| `device_fingerprint_changed` | high | Entity's device fingerprint changed in a pattern inconsistent with normal usage |
| `geographic_anomaly` | medium | Entity is operating from a location inconsistent with their established pattern |
| `temporal_anomaly` | medium | Action is being attempted at a time inconsistent with the entity's established pattern |
| `payment_destination_flagged` | high | The target payment destination has been flagged by an external fraud signal |
| `authority_under_review` | high | The entity's authority class is under active review by a governance process |
| `credential_expiry_imminent` | low | A credential used by this entity expires within the warning window |
| `infrastructure_degraded` | medium | The infrastructure environment is in a degraded state that may affect trust verification reliability |
| `external_regulatory_alert` | critical | A regulatory body has issued an alert relevant to this scope |
| `velocity_anomaly` | medium | Action frequency exceeds established baseline for this entity or resource |

### Computed Reason Codes

| Code | Description |
|---|---|
| `high_severity_signal_active` | At least one active observation has severity `high` or `critical` |
| `multiple_signals_active` | More than one distinct signal is active for this scope |
| `suppression_expired` | A previously active suppression has expired, re-exposing the underlying observation |
