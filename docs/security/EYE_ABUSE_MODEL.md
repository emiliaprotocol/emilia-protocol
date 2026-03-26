# EMILIA Protocol -- Eye Abuse Model

## Scope

This document covers threats specific to the Emilia Eye warning layer. It does not repeat threats covered in the EP Threat Model (role spoofing, policy drift, artifact replay, etc.), which apply to the EP trust enforcement layer independently. Where Eye interacts with EP (e.g., advisory consumption during policy resolution), the relevant EP mitigations remain in force.

Each threat is listed with its attack vector, impact, and mitigation.

---

## 1. Signal Poisoning

**Threat.** A compromised or malicious trusted source submits fabricated observations to manipulate advisory outputs. The attacker's goal is to cause a target entity or resource to be flagged with elevated or review_required status, triggering unnecessary enforcement escalation.

**Impact.** Denial of service via forced step-up authentication or signoff requirements. Operational disruption for targeted entities. Erosion of trust in the warning layer if operators learn that signals are unreliable.

**Mitigation.** Source registration with explicit trust grants. Each `source_id` must be registered with the tenant before observations are accepted. Registration includes the source's `source_type`, allowed `signal_code` values, and maximum `severity` the source may assert. Observations from unregistered sources are rejected with `SOURCE_NOT_TRUSTED`. Observations with a severity exceeding the source's registered maximum are rejected with `SEVERITY_EXCEEDS_SOURCE_GRANT`. Source registrations are auditable and revocable.

---

## 2. False-Positive Floods

**Threat.** A trusted source (compromised or misconfigured) submits a high volume of low-to-medium severity observations across many scopes, causing widespread `caution` or `elevated` advisories. The volume is too large to suppress individually.

**Impact.** Warning fatigue. Operators stop investigating advisories because too many are false positives. Genuine signals are lost in the noise.

**Mitigation.** Per-source rate limits enforced at the observation ingestion endpoint. Rate limits are configurable per source and per signal_code. When a source exceeds its rate limit, subsequent observations are queued (not dropped) and an `eye_source_rate_limited` event is emitted. Operators are alerted to rate limit events. If the pattern persists, the source registration can be suspended without affecting observations from other sources.

---

## 3. Stale-Signal Reuse

**Threat.** An observation with a long TTL continues to affect advisories long after the underlying condition has been resolved. The observation is technically valid (not expired) but no longer reflects reality.

**Impact.** Persistent false elevation of advisory status. Entities are subjected to unnecessary enforcement escalation for conditions that no longer exist.

**Mitigation.** Short default TTLs. Observation default TTL is 24 hours, clamped to a maximum of 30 days. Advisory TTL is 1 hour, clamped to a maximum of 24 hours. Sources that need to maintain a signal beyond the TTL must resubmit the observation, confirming the condition still holds. Operators can suppress stale observations with an auditable suppression record. The `POST /eye/check` endpoint always evaluates against current, non-expired, non-suppressed observations. There is no cache that survives TTL expiry.

---

## 4. Warning Laundering

**Threat.** An attacker creates observations through a legitimate source to build a pattern of warnings against a target entity, then uses those warnings as justification for an external action (contract termination, partnership withdrawal, access revocation) that would not be justified by the underlying facts alone.

**Impact.** Reputational damage to targeted entities. Abuse of the warning system as a weapon rather than a safety mechanism.

**Mitigation.** Action binding. Eye advisories carry a `recommended_action` field that is scoped to the EP enforcement layer (`none`, `log`, `step_up_auth`, `require_signoff`, `escalate`). Advisories are not designed for and must not be used as evidence in external decisions. The advisory `detail` field does not contain personally identifiable information about the target entity beyond the `scope_ref`. Observations require `evidence_ref` for any severity above `low`, creating a verifiable chain back to the underlying condition. Operators are contractually bound (via the Eye terms of service) to not use advisory data for purposes outside of trust enforcement.

---

## 5. Malicious Suppression

**Threat.** An authorized operator suppresses a legitimate warning to allow a compromised or fraudulent action to proceed without the additional enforcement that Eye would have triggered.

**Impact.** The warning layer is bypassed by an insider. The action proceeds under a `clear` status that does not reflect the actual risk.

**Mitigation.** Suppressions are auditable. Every suppression records `suppressed_by`, `authority_class`, `reason`, `target_id`, `expires_at`, and `created_at` in an append-only log. Suppressions require a `reason` field with a minimum length of 20 characters. Suppressions require the caller to hold a registered authority class with suppression permissions. Suppression events are emitted to the tenant's event stream for SIEM integration. Post-hoc audit can detect patterns: frequent suppressions by the same actor, suppressions immediately before high-value actions, suppressions of critical-severity observations. Suppressions are local to the operator's deployment and cannot affect the source's observation or other operators' advisory evaluations.

---

## 6. Source Impersonation

**Threat.** An attacker submits observations using a `source_id` that belongs to a legitimate trusted source, injecting fabricated signals under the source's identity.

**Impact.** Same as signal poisoning, but with the added credibility of a trusted source identity.

**Mitigation.** Source authentication. Observation submission requires a bearer token scoped to the specific `source_id`. The token is issued during source registration and is distinct from the tenant's general API token. Token rotation is supported. If a source's token is compromised, it can be revoked and reissued without affecting other sources. All observation submissions are logged with the authenticated source identity, not just the claimed `source_id`.

---

## 7. Warning Fatigue

**Threat.** Even without malicious intent, a system that produces too many non-clear advisories will cause operators and downstream systems to ignore Eye's output. If `elevated` is the normal state, `elevated` means nothing.

**Impact.** Eye becomes operationally irrelevant. Genuine warnings are not acted upon because the baseline noise level is too high.

**Mitigation.** Status model design. Eye has four status levels, not two. `clear` is the expected default. `caution` exists as a low-urgency tier that does not require enforcement changes. This prevents medium-severity signals from producing the same operator response as critical signals. Advisory TTLs are short (default 1 hour), ensuring that transient conditions do not produce persistent noise. The `recommended_action` field gives downstream systems a graduated response path rather than a binary alert/no-alert signal. Implementations SHOULD monitor the ratio of `clear` to non-clear advisories per scope type. A sustained non-clear rate above 15% across all scopes is a signal that signal definitions or severity mappings need recalibration.

---

## 8. Defamation Risk

**Threat.** Observations and advisories contain assertions about entities that, if disclosed, could constitute defamation. An entity learns that Eye has flagged them with `device_fingerprint_changed` or `authority_under_review` and challenges the assertion legally.

**Impact.** Legal liability for the operator. Reputational damage to the Eye ecosystem.

**Mitigation.** No public scoreboards. Eye does not expose observations or advisories to the entities they concern. Advisory data flows from Eye to the operator's policy layer. It is not surfaced in user-facing interfaces, public APIs, or entity-accessible dashboards. Observations carry `evidence_ref` for severity above `low`, providing a verifiable basis for the assertion. Operators control whether advisory information is disclosed to entities and are responsible for their own disclosure policies. The `detail` field is structured data, not free-text allegations. Signal codes are defined by registered signal definitions, not authored by individual sources.

---

## Safety Rules

The following rules are architectural constraints, not configuration options. They apply to all Eye deployments.

### 1. Short TTLs

All observations, advisories, and suppressions have mandatory TTLs with enforced maximums. There are no permanent flags. A signal that is not resubmitted expires.

### 2. Action Binding

Eye advisories produce `recommended_action` values scoped to the EP enforcement layer. Eye never prescribes actions outside of trust enforcement (no account locks, no access revocations, no external notifications). Policy decides. Eye informs.

### 3. Explainable Reasons

Every non-clear advisory carries `reason_codes` derived from registered signal definitions. There are no opaque risk scores or unexplained status changes. The operator can always determine why a non-clear status was issued.

### 4. Local Suppressions Only

Suppressions apply to the operator's deployment only. A suppression does not modify the source's observation, does not affect other operators' advisory evaluations, and does not propagate to the Eye signal registry.

### 5. No Public Scoreboards

Eye does not maintain or expose entity-level trust scores, reputation indices, or public-facing warning status. Advisory data is internal to the operator's trust enforcement pipeline.

### 6. Evidence Refs Required

Observations with severity above `low` must include an `evidence_ref` pointing to supporting evidence. Observations without evidence at `medium` severity or above are rejected.

### 7. Policy Still Decides

Eye's `recommended_action` is a recommendation. The EP policy layer makes the enforcement decision. An operator may choose to ignore Eye's recommendation entirely. The protocol does not enforce Eye advisory consumption.

---

## Disallowed in V1

The following capabilities are explicitly excluded from V1. They represent attack surface that requires additional design work before safe deployment.

### Anonymous Reports

V1 does not accept observations from unregistered or anonymous sources. Every observation must originate from a registered `source_id` with an authenticated token. Anonymous tip lines, crowd-sourced signals, and unattributed reports are not supported.

### Crowd-Generated Claims

V1 does not support observations generated by aggregation of crowd or community input. Signals derived from user votes, community flags, or collective assessment are excluded. All observations must originate from a single identifiable source that is accountable for the signal's accuracy.

### Public User Submissions

V1 does not provide a mechanism for end users (the entities that observations concern) to submit observations about other entities. There is no "report this user" flow. Observations flow from trusted institutional sources to the operator's Eye deployment. The path is source-to-operator, not user-to-operator.

These exclusions are not permanent. They reflect a V1 design decision to limit abuse surface until the mitigation framework for crowd-sourced and anonymous signals is fully specified.
