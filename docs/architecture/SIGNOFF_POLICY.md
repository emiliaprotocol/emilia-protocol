# EP Accountable Signoff -- Policy Specification

**Document Status:** Proposed Standard
**Version:** 1.0
**Date:** 2026-03-20
**Parent:** PROTOCOL-STANDARD.md Section 24
**License:** Apache-2.0

---

## 1. Scope

This document specifies the policy model for EP Accountable Signoff. It defines the base signoff policy object, the three policy categories (handshake policy, signoff policy, consumption policy), the signoff policy controls, and three worked examples demonstrating policy application in production contexts.

This specification is normative for implementations that adopt the Accountable Signoff extension (PROTOCOL-STANDARD.md Section 24).

---

## 2. Base Signoff Policy Object

A signoff policy is a structured rule set that determines whether a given action class requires human signoff, who may sign, at what assurance level, through what channel, and under what constraints.

### 2.1 Required Fields

Every signoff policy object MUST contain the following fields:

| Field | Type | Constraints | Description |
|---|---|---|---|
| `policy_key` | string | Unique within the implementation; lowercase, hyphens, max 128 chars | Stable identifier for this policy |
| `policy_version` | integer | Monotonically increasing; starts at 1 | Version number; incremented on every policy change |
| `policy_hash` | string | SHA-256 of the canonical JSON serialization of all rule fields | Integrity commitment; pinned to challenges at creation time |
| `action_class` | string | Must reference a registered action class | The action class this policy governs |
| `risk_class` | enum | `standard`, `elevated`, `high`, `critical` | Risk classification assigned to the governed action class |
| `signoff_required` | boolean | | Whether actions in this class require human signoff |
| `signoff_authority_class` | string | Must reference a registered authority class | The minimum authority class required for the signoff actor |
| `signoff_assurance_minimum` | enum | `low`, `substantial`, `high` | Minimum authentication assurance the signoff actor must achieve |
| `signoff_methods` | array of string | At least one entry when `signoff_required` is true | Permitted authentication methods: `passkey`, `platform_biometric`, `secure_app`, `out_of_band`, `sms_transitional` |
| `signoff_channel` | string | | Delivery channel for the challenge: `secure_app`, `out_of_band`, `sms_transitional` |
| `signoff_challenge_ttl` | integer | Clamped to [120, 3600] seconds | Maximum time the challenge remains valid |
| `signoff_attestation_ttl` | integer | Clamped to [60, 1800] seconds | Maximum time the attestation remains valid after approval |
| `dual_signoff_required` | boolean | | Whether a second independent signoff is always required |
| `dual_signoff_threshold` | number or null | Non-negative when present | Value or risk threshold above which dual signoff activates (null if `dual_signoff_required` is true unconditionally) |
| `dual_signoff_authority_classes` | array of string or null | At least two distinct entries when dual signoff is active | Authority classes for the two signers |
| `out_of_band_required` | boolean | | Whether the challenge MUST be delivered via an out-of-band channel |
| `enabled` | boolean | | Whether this policy is currently active |
| `created_at` | ISO 8601 | | Policy creation timestamp |
| `updated_at` | ISO 8601 | | Last modification timestamp |

### 2.2 Optional Fields

| Field | Type | Description |
|---|---|---|
| `description` | string | Human-readable description of the policy's purpose |
| `escalation_authority_class` | string | Authority class to route to if the signoff actor escalates |
| `max_escalation_depth` | integer | Maximum number of escalation levels (default: 3) |
| `consequences_template` | string | Template for the human-readable consequences summary rendered in the challenge |
| `action_diff_required` | boolean | Whether the challenge MUST include a before/after diff (default: false) |
| `metadata` | JSON | Implementation-specific metadata; MUST NOT contain policy-controlling fields |

### 2.3 Policy Hash Computation

The `policy_hash` MUST be computed as the SHA-256 of the canonical JSON serialization of all fields listed in Section 2.1 except `policy_hash` itself, `created_at`, and `updated_at`. Canonical serialization follows the EP standard: lexicographically sorted keys, no insignificant whitespace, deterministic encoding.

The hash is pinned to each challenge at creation time. This ensures that if a policy is updated between challenge creation and challenge resolution, the challenge is evaluated against the policy version that was in effect when it was issued.

---

## 3. Policy Categories

Signoff policy operates within a three-layer policy architecture. Each layer governs a distinct phase of the signoff lifecycle.

### 3.1 Handshake Policy

**Governs:** Whether signoff is required for a given handshake.

The handshake policy is evaluated when a handshake is verified. If the handshake's action class matches a signoff policy with `signoff_required = true`, the signoff gate activates.

**Handshake policy fields relevant to signoff:**

| Field | Type | Description |
|---|---|---|
| `signoff_required` | boolean | Activates the signoff gate |
| `action_class` | string | Matches against registered signoff policies |
| `risk_class` | enum | Determines which signoff policy applies if multiple candidates exist |

**Evaluation order:**

1. The handshake is verified using standard handshake verification rules (PROTOCOL-STANDARD.md Section 23.4).
2. The handshake's `action_class` is looked up in the signoff policy registry.
3. If a matching policy exists with `signoff_required = true` and `enabled = true`, the signoff gate activates.
4. If no matching policy exists, execution proceeds without signoff.

### 3.2 Signoff Policy

**Governs:** The signoff challenge and attestation lifecycle.

Once the signoff gate activates, the signoff policy controls the challenge creation, delivery, actor selection, assurance requirements, and attestation constraints.

**Key controls:**

- **Who may sign:** Determined by `signoff_authority_class`. The signoff actor's entity record MUST declare an authority class that matches or exceeds the policy requirement. Authority class hierarchy is implementation-defined but MUST be documented.
- **Assurance level:** Determined by `signoff_assurance_minimum`. The authentication method used by the signoff actor MUST achieve at least this assurance level.
- **Methods:** Determined by `signoff_methods`. The authentication method MUST be one of the permitted methods.
- **Channel:** Determined by `signoff_channel`. The challenge MUST be delivered via this channel.
- **Dual signoff:** Determined by `dual_signoff_required` or by comparing the transaction value against `dual_signoff_threshold`.
- **Out-of-band:** Determined by `out_of_band_required`. When true, the challenge MUST NOT be delivered through the same channel as the action request.

### 3.3 Consumption Policy

**Governs:** The conditions under which an attestation may be consumed for execution.

Consumption policy is implicit in the protocol rules (PROTOCOL-STANDARD.md Section 24.7) but implementations MAY define additional consumption constraints:

| Control | Type | Description |
|---|---|---|
| `max_consumption_delay` | integer | Maximum seconds between attestation creation and consumption attempt. Defaults to `signoff_attestation_ttl`. |
| `binding_verification_required` | boolean | Whether `binding_hash` verification across all objects is mandatory at consumption time. Default: true. MUST NOT be set to false in production. |
| `execution_context_match` | boolean | Whether the consuming system must verify that the execution context matches the challenge's `action_type` and `resource_ref`. Default: true. |

---

## 4. Signoff Policy Controls -- Detailed Specification

### 4.1 signoff_required

Type: boolean.

When `true`, any handshake with a matching `action_class` MUST trigger the signoff gate. When `false`, the policy is informational and does not activate the gate.

A policy with `signoff_required = false` and `enabled = true` is valid. It documents the action class without requiring signoff. This is useful for action classes that are under evaluation for future signoff requirements.

### 4.2 signoff_authority_class

Type: string.

Specifies the minimum authority class required to sign off on actions governed by this policy. The signoff actor's entity record MUST include an authority class that satisfies the policy.

Authority class matching is implementation-defined. Implementations MUST document their authority class hierarchy and the matching semantics. A typical hierarchy:

```
operator < admin < treasury_officer < compliance_officer < executive
```

Where `<` means "is subsumed by." An actor with `executive` authority satisfies a policy requiring `admin`.

### 4.3 signoff_assurance_minimum

Type: enum. Values: `low`, `substantial`, `high`.

Specifies the minimum authentication assurance level the signoff actor must achieve. The mapping from authentication methods to assurance levels is:

| Method | Assurance Level |
|---|---|
| `sms_transitional` | `low` |
| `secure_app` | `substantial` |
| `passkey` | `high` |
| `platform_biometric` | `high` |
| `out_of_band` | `substantial` or `high` (depends on out-of-band mechanism) |

A policy requiring `high` assurance accepts only `passkey` or `platform_biometric`. A policy requiring `substantial` assurance accepts `secure_app`, `passkey`, `platform_biometric`, or `out_of_band` (when the out-of-band mechanism achieves `substantial` or higher).

### 4.4 signoff_methods

Type: array of string.

Enumerates the authentication methods permitted for this policy. The signoff actor MUST use one of the listed methods. If the actor's available methods do not intersect with the policy's permitted methods, the challenge MUST be escalated or denied.

### 4.5 signoff_channel

Type: string.

Specifies the delivery channel for the challenge. Values:

- `secure_app` -- challenge delivered via a dedicated, authenticated application (mobile or desktop).
- `out_of_band` -- challenge delivered via a channel separate from the action request (e.g., phone call, physical token, separate device).
- `sms_transitional` -- challenge delivered via SMS. Implementations SHOULD treat this as a transitional mechanism and plan migration to `secure_app` or `out_of_band`.

### 4.6 Dual Signoff

Dual signoff requires two independent humans to approve the same action. It is controlled by two fields:

- `dual_signoff_required` (boolean): When `true`, dual signoff is mandatory for all actions governed by this policy regardless of value.
- `dual_signoff_threshold` (number or null): When present and `dual_signoff_required` is `false`, dual signoff activates when the transaction value (or risk metric) exceeds this threshold.

**Dual signoff rules:**

1. The two signoff actors MUST hold distinct entity references.
2. Both actors MUST satisfy the policy's `signoff_authority_class` requirement, or each must satisfy one of the entries in `dual_signoff_authority_classes`.
3. Both actors MUST independently view the challenge, authenticate at the required assurance level, and approve.
4. Two separate attestations are created, one per actor.
5. The consumption record MUST reference both attestation IDs.
6. If either actor denies, the action is denied.
7. If either actor escalates, the escalation applies to the entire action.

### 4.7 Out-of-Band Requirement

When `out_of_band_required = true`, the challenge MUST be delivered through a channel that is physically or logically separate from the channel through which the action was requested.

The purpose is to prevent an attacker who has compromised the primary channel from also intercepting and approving the signoff challenge. If an agent requests a payment redirect through an API, the signoff challenge MUST NOT be delivered through the same API session.

---

## 5. Worked Examples

### 5.1 Payment Destination Change

**Scenario:** An agent requests to change the payment destination for a vendor account from one bank account to another. This is a high-risk action because a compromised payment destination diverts all future payments.

**Policy:**

```json
{
  "policy_key": "payment-destination-change-v1",
  "policy_version": 1,
  "action_class": "payment_destination_change",
  "risk_class": "high",
  "signoff_required": true,
  "signoff_authority_class": "treasury_officer",
  "signoff_assurance_minimum": "high",
  "signoff_methods": ["passkey", "platform_biometric"],
  "signoff_channel": "secure_app",
  "signoff_challenge_ttl": 900,
  "signoff_attestation_ttl": 300,
  "dual_signoff_required": false,
  "dual_signoff_threshold": 50000,
  "dual_signoff_authority_classes": ["treasury_officer", "compliance_officer"],
  "out_of_band_required": false,
  "action_diff_required": true,
  "consequences_template": "Payment destination for {{resource_ref}} will change from {{before.destination}} to {{after.destination}}. All future disbursements will route to the new destination.",
  "enabled": true
}
```

**Flow:**

1. Agent submits a handshake with `action_type: payment_destination_change`.
2. Handshake verified. Policy lookup finds `payment-destination-change-v1` with `signoff_required: true`.
3. Challenge created with:
   - `authority_class: treasury_officer`
   - `required_assurance: high`
   - `channel: secure_app`
   - `action_diff` populated with before/after bank account details
   - `dual_signoff_required: false` (assuming transaction value < $50K)
4. Challenge delivered to the designated treasury officer's secure app.
5. Treasury officer views the full action diff, authenticates with a passkey (assurance: high), and approves.
6. Attestation created. Execution proceeds atomically.

**If the transaction value exceeds $50K:**

- `dual_signoff_required` activates via the threshold.
- A second challenge is issued to a `compliance_officer`.
- Both must independently approve before consumption can proceed.

### 5.2 Government Benefits Redirect

**Scenario:** A citizen's agent requests to redirect government benefit payments to a new bank account. This is a critical-risk action because misdirected benefits can cause severe harm to vulnerable populations and are difficult to reverse.

**Policy:**

```json
{
  "policy_key": "benefits-redirect-v1",
  "policy_version": 1,
  "action_class": "benefits_payment_redirect",
  "risk_class": "critical",
  "signoff_required": true,
  "signoff_authority_class": "benefits_case_officer",
  "signoff_assurance_minimum": "substantial",
  "signoff_methods": ["secure_app", "out_of_band"],
  "signoff_channel": "out_of_band",
  "signoff_challenge_ttl": 1800,
  "signoff_attestation_ttl": 600,
  "dual_signoff_required": false,
  "dual_signoff_threshold": null,
  "dual_signoff_authority_classes": null,
  "out_of_band_required": true,
  "action_diff_required": true,
  "escalation_authority_class": "benefits_supervisor",
  "consequences_template": "Benefit payments for {{resource_ref}} will be redirected from {{before.destination}} to {{after.destination}}. This change affects recurring payments and cannot be reversed without a new redirect request.",
  "enabled": true
}
```

**Flow:**

1. Agent submits a handshake with `action_type: benefits_payment_redirect`.
2. Handshake verified. Policy lookup finds `benefits-redirect-v1` with `signoff_required: true`.
3. Challenge created with:
   - `authority_class: benefits_case_officer`
   - `required_assurance: substantial`
   - `channel: out_of_band` (challenge delivered via phone call or separate secure device, NOT through the agent's API session)
   - `action_diff` populated with before/after bank account details for the benefit recipient
   - `out_of_band_required: true`
4. Challenge delivered out-of-band to the assigned case officer.
5. Case officer reviews the redirect details, authenticates via secure app or out-of-band mechanism (assurance: substantial), and decides.

**Escalation path:**

- If the case officer is unsure or the redirect pattern is unusual, they escalate.
- A new challenge is issued to `benefits_supervisor` (the `escalation_authority_class`).
- The supervisor reviews with full context, including the original case officer's escalation reason.
- The supervisor may approve, deny, or escalate further (up to `max_escalation_depth`).

**Key design choices:**

- `out_of_band_required: true` prevents an attacker who has compromised the agent's API session from intercepting the challenge.
- `signoff_assurance_minimum: substantial` (not `high`) balances security with accessibility for government workers who may not have passkey-capable devices.
- No dual signoff threshold because the population at risk (benefits recipients) warrants individual case officer judgment regardless of amount.

### 5.3 Agent Destructive Action

**Scenario:** An agent with admin-level delegation requests to execute a destructive operation on production infrastructure (e.g., dropping a database table, revoking all API keys, or decommissioning a service).

**Policy:**

```json
{
  "policy_key": "agent-destructive-action-v1",
  "policy_version": 1,
  "action_class": "agent_destructive_action",
  "risk_class": "critical",
  "signoff_required": true,
  "signoff_authority_class": "admin",
  "signoff_assurance_minimum": "high",
  "signoff_methods": ["passkey", "platform_biometric"],
  "signoff_channel": "secure_app",
  "signoff_challenge_ttl": 600,
  "signoff_attestation_ttl": 120,
  "dual_signoff_required": true,
  "dual_signoff_threshold": null,
  "dual_signoff_authority_classes": ["admin", "admin"],
  "out_of_band_required": false,
  "action_diff_required": true,
  "consequences_template": "Agent {{initiator}} will execute destructive action '{{action_type}}' on resource '{{resource_ref}}'. This action is irreversible. Affected scope: {{consequences_summary}}.",
  "enabled": true
}
```

**Flow:**

1. Agent submits a handshake with `action_type: agent_destructive_action` and `resource_ref` identifying the target resource.
2. Handshake verified. Policy lookup finds `agent-destructive-action-v1` with `signoff_required: true`.
3. Challenge created with:
   - `authority_class: admin`
   - `required_assurance: high`
   - `channel: secure_app`
   - `dual_signoff_required: true` (unconditional; no threshold)
   - `action_diff` populated with the exact destructive operation and its scope
4. Challenge delivered to two distinct admin-authority actors via secure app.
5. Both admins independently:
   - View the full destructive action description and its consequences.
   - Authenticate with passkey or platform biometric (assurance: high).
   - Approve or deny.
6. If both approve, two attestations are created.
7. Consumption requires both attestation IDs and verifies `binding_hash` consistency across all objects.

**Key design choices:**

- `dual_signoff_required: true` with no threshold means every destructive action requires two admins, regardless of scope.
- `signoff_attestation_ttl: 120` (2 minutes) is deliberately short. Once two admins have approved a destructive action, it should execute immediately or not at all. A long attestation window creates risk of context drift.
- `signoff_assurance_minimum: high` with only `passkey` and `platform_biometric` permitted ensures the approving human is physically present at an authenticated device. `secure_app` alone is insufficient for destructive actions.
- Both dual signoff authority classes are `admin`. This means two distinct admin-class actors (not one admin and one lower-authority actor). The actors MUST hold different entity references.

---

## 6. Policy Lifecycle

### 6.1 Policy Versioning

Every modification to a signoff policy MUST increment `policy_version` and recompute `policy_hash`. Previous versions are retained in an append-only policy history.

Challenges reference a specific `policy_version` and `policy_hash`. A challenge is always evaluated against the policy version that was in effect when it was created, not the current version. This prevents retroactive policy changes from altering in-flight signoff flows.

### 6.2 Policy Activation and Deactivation

A policy is active when `enabled = true`. Deactivating a policy (`enabled = false`) does not affect challenges already created under that policy. New handshakes matching the deactivated policy's `action_class` will not trigger the signoff gate.

Reactivating a policy increments the version.

### 6.3 Policy Conflict Resolution

When multiple policies match a given `action_class`, the policy with the highest `risk_class` takes precedence. If `risk_class` is equal, the policy with the most restrictive `signoff_assurance_minimum` takes precedence. Implementations MUST NOT silently select the least restrictive policy.

---

## 7. Conformance

### 7.1 A Conformant Implementation Adopting Signoff Policies MUST:

1. Store signoff policies as structured objects with all required fields from Section 2.1.
2. Compute `policy_hash` as specified in Section 2.3.
3. Pin `policy_version` and `policy_hash` to challenges at creation time.
4. Enforce `signoff_challenge_ttl` within [120, 3600] seconds and `signoff_attestation_ttl` within [60, 1800] seconds.
5. Validate that the signoff actor's authority class satisfies the policy's `signoff_authority_class` requirement.
6. Validate that the authentication method used is listed in the policy's `signoff_methods`.
7. Validate that the achieved authentication assurance meets or exceeds `signoff_assurance_minimum`.
8. Enforce dual signoff actor distinctness when dual signoff is active.
9. Enforce out-of-band delivery when `out_of_band_required = true`.
10. Resolve policy conflicts using the precedence rules in Section 6.3.

### 7.2 A Conformant Implementation Adopting Signoff Policies SHOULD:

1. Retain a complete append-only history of policy versions.
2. Support the `consequences_template` field with variable substitution for human-readable challenge rendering.
3. Support configurable escalation paths via `escalation_authority_class`.
4. Provide an administrative interface for policy creation, versioning, and deactivation.

---

*EP Accountable Signoff -- Policy Specification v1.0*
*EMILIA Protocol*
*Apache-2.0*
*Specification Date: 2026-03-20*
