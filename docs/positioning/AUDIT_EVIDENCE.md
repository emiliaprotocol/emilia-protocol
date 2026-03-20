# EP Audit Evidence Capabilities

This document describes the evidence that EMILIA Protocol produces for auditors, regulators, and forensic investigators. All evidence is generated as a byproduct of normal protocol operation -- no additional instrumentation or post-hoc collection is required.

---

## 1. Protocol Event Exports

**What it is**: A complete, append-only record of every trust-changing state transition across all aggregate types.

**Coverage**: All 17 command types across receipts, commits, disputes, trust reports, and handshakes. Every operation that modifies trust state produces a protocol event.

**Fields per event**:

| Field | Description |
|---|---|
| `event_id` | Unique identifier (UUID) |
| `aggregate_type` | Object type: receipt, commit, dispute, report, handshake |
| `aggregate_id` | Identifier of the specific object that changed |
| `command_type` | Operation performed (e.g., `issue_commit`, `verify_handshake`, `file_dispute`) |
| `parent_event_hash` | Hash of the previous event in the aggregate's event chain |
| `payload_hash` | Content-addressed hash of the event payload |
| `actor_authority_id` | Authenticated actor who performed the operation |
| `idempotency_key` | Content-addressed dedup key for the command |
| `created_at` | Timestamp of event creation |

**Integrity guarantee**: Database triggers prevent UPDATE and DELETE on `protocol_events`. Events are written before state changes (Invariant 9) -- if the event write fails, the operation does not proceed.

**Source**: `lib/protocol-write.js` (`appendProtocolEvent()`, `buildProtocolEvent()`).

---

## 2. Handshake Event Timeline

**What it is**: A complete lifecycle record for every handshake, from initiation through verification to consumption or expiry.

**Event types**:

| Event Type | When Emitted |
|---|---|
| `initiated` | Handshake created with parties, policy, and binding material |
| `presentation_added` | Entity submits credentials for their party role |
| `status_changed` | Handshake transitions between lifecycle states |
| `verified` | Handshake verification completed with accepted outcome |
| `rejected` | Handshake verification completed with rejected outcome (includes reason codes) |
| `expired` | Binding TTL elapsed |
| `revoked` | Handshake explicitly revoked by authorized actor |

**Fields per event**:

| Field | Description |
|---|---|
| `event_id` | Unique identifier (UUID) |
| `handshake_id` | Handshake this event belongs to |
| `event_type` | Lifecycle event type (see above) |
| `actor_entity_ref` | Entity that triggered the event |
| `detail` | Structured JSON with event-specific data (reason codes, outcome, verification result) |
| `created_at` | Timestamp |

**Mandatory emission**: `requireHandshakeEvent()` in `lib/handshake/events.js` throws `EVENT_WRITE_REQUIRED` on failure. All lifecycle functions (create, present, verify, finalize) call this before state changes.

**Integrity guarantee**: Append-only with database triggers preventing UPDATE and DELETE.

---

## 3. Binding Material Verification

**What it is**: The ability to recompute and compare cryptographic hashes that bind an authorization to its specific action context.

**Verification process**:

1. Retrieve the handshake binding record containing the stored `binding_hash`.
2. Retrieve the binding material fields: `action_type`, `resource_ref`, `policy_id`, `policy_version`, `policy_hash`, `interaction_id`, `party_set_hash`, `payload_hash`, `context_hash`, `nonce`, `expires_at`, `binding_material_version`.
3. Recompute: `SHA-256(JSON.stringify(bindingMaterial, sorted_keys))`.
4. Compare the recomputed hash against the stored `binding_hash`.

If the hashes match, the binding material has not been altered since initiation. If they differ, the binding material or the stored hash has been tampered with.

**Field completeness enforcement**: `CANONICAL_BINDING_FIELDS` in `lib/handshake/invariants.js` defines the exact field set. At initiation, `_handleInitiateHandshake()` in `lib/handshake/create.js` asserts that all canonical fields are present and no extra fields exist (`BINDING_INVARIANT_VIOLATION` on failure).

**Audit use**: Auditors can independently verify that the action authorized by a handshake matches the action that was executed, by recomputing the binding hash from the action's parameters and comparing against the stored hash.

---

## 4. Consumption Proof

**What it is**: Evidence that an authorization artifact was consumed exactly once, by a specific actor, at a specific time.

**Records**:

| Field | Description |
|---|---|
| Binding `consumed_at` | Timestamp when the binding was consumed |
| Consuming actor | Entity that triggered the verification leading to consumption |
| Consumption record | Entry in `handshake_consumptions` table with unique constraint |

**One-time guarantee enforcement**:
- Hard gate in `_handleVerifyHandshake()` rejects already-consumed bindings before processing
- Conditional database update with `IS NULL` filter (compare-and-swap)
- Unique constraint on `handshake_consumptions` prevents duplicate records
- `handshake_consumptions` is in `TRUST_TABLES`, preventing direct writes from routes

**Audit use**: For any action, auditors can verify that the authorizing handshake binding was consumed exactly once, identify the consuming actor, and confirm the consumption timestamp. Absence of a consumption record for an executed action indicates a control failure.

---

## 5. Policy Snapshot

**What it is**: The policy rules and version that governed a specific handshake at the time it was initiated, preserved via cryptographic hash.

**What is captured**:
- `policy_id`: Reference to the policy record
- `policy_version`: Version number at bind time
- `policy_hash`: `SHA-256(JSON.stringify(policy.rules, sorted_keys))` computed at initiation

**Drift detection**: At verification time, the policy is re-loaded and re-hashed. If the hash differs from the stored `policy_hash`, the handshake is rejected with `policy_hash_mismatch`. This means auditors can confirm that the policy applied at verification was identical to the policy that existed at initiation.

**Audit use**: For any handshake, auditors can retrieve the `policy_hash` and compare it against the current policy's hash to determine whether the policy has changed since the handshake was initiated. Combined with policy version history, this provides point-in-time policy reconstruction.

**Source**: `lib/handshake/policy.js` (`resolvePolicy()`), `lib/handshake/create.js` (hash computation), `lib/handshake/verify.js` (hash verification).

---

## 6. Write-Path Enforcement Evidence

**What it is**: Evidence that the trust-table write discipline (Invariant 1) is enforced at runtime and build time.

### Runtime Guard Configuration

- `lib/write-guard.js` defines the `TRUST_TABLES` list (13 tables) and the blocked operations (`insert`, `update`, `upsert`, `delete`).
- `getGuardedClient()` returns a Proxy that intercepts and blocks these operations. Violation throws `WRITE_DISCIPLINE_VIOLATION`.
- Route handlers receive the guarded client; only the canonical write layer (`protocolWrite()` and its delegates) uses the unguarded service client.

### CI Guard Execution

- `scripts/check-write-discipline.js`: Executed on every build. Scans route files for imports of forbidden canonical functions and `getServiceClient` usage. Produces a violation report with file paths, line numbers, and forbidden patterns. Exit code 1 on any violation.
- `scripts/check-protocol-discipline.js`: Executed on every build. Scans all application and library files for direct trust-table mutation patterns (`.from('trust_table').insert()`) outside the allowlisted write layer. Also detects embedded issuer key patterns (`checkEmbeddedIssuerKeys()`).

**Audit use**: Auditors can review CI build logs to confirm that write-discipline and protocol-discipline checks ran on every deployment. They can inspect the guard configuration to verify the list of protected tables and blocked operations. Failed guard checks produce explicit violation reports.

---

## 7. Conformance Test Results

**What it is**: Results from the EP conformance test suite that validates all protocol invariants and adversarial resistance properties.

### Invariant Tests (47 tests)

Validate all 10 conformance invariants documented in `docs/conformance/INVARIANTS.md`:

| Invariant | What Tests Verify |
|---|---|
| 1. Write discipline | Guarded client blocks mutations on each trust table |
| 2. Actor identity from auth | Mismatched actor/party combinations rejected |
| 3. Authority from registry | Unknown, revoked, expired, not-yet-valid issuers handled correctly |
| 4. No embedded keys | CI guard detects embedded key patterns |
| 5. No ephemeral trust | Default untrusted state; unverified presentations produce rejection codes |
| 6. Role-authorized actors | Cross-party presentation attempts rejected |
| 7. Policy fail-closed | Missing/modified policies cause rejection |
| 8. One-time consumption | Double-consumption attempts rejected; race condition handling verified |
| 9. Events before state | Failed event writes prevent state changes |
| 10. Canonical binding hash | Hash determinism; modified fields produce different hashes; missing/extra fields rejected |

### Adversarial Tests (24 tests)

Cover all 10 threat model entries documented in `docs/security/THREAT_MODEL.md`:

| Threat | What Tests Verify |
|---|---|
| Role spoofing | Cross-entity presentation rejected with ROLE_SPOOFING |
| Issuer spoofing | Untrusted/revoked issuers produce rejection |
| Policy drift | Modified policy detected via hash mismatch |
| Artifact replay | Nonce mismatch, expiry, and consumption all independently prevent replay |
| Approval reuse | Second consumption attempt rejected; concurrent race handled |
| Direct route bypass | Runtime proxy blocks; CI guards detect violations |
| Stale trust root | Missing policy produces rejection |
| Ambiguous delegation | Expired and out-of-scope delegations rejected |
| Event omission | Failed event writes halt operations |
| Race-condition double use | Conditional update ensures single consumption |

**Audit use**: Test suite execution reports provide evidence that all invariants and threat mitigations are functioning. These tests can be run by auditors independently against any EP deployment to verify conformance. Test failures indicate control degradation.

---

## Evidence Export Summary

| Evidence Category | Format | Integrity Mechanism | Recommended Export Frequency |
|---|---|---|---|
| Protocol events | Structured records (JSON/SQL export) | Append-only table, parent event hash chain | Continuous or daily |
| Handshake events | Structured records (JSON/SQL export) | Append-only table, database triggers | Continuous or daily |
| Binding material | Structured records with recomputable hashes | SHA-256 canonical binding hash | On demand per investigation |
| Consumption proof | Timestamped records with actor attribution | Unique constraint, conditional update | On demand per investigation |
| Policy snapshots | Policy rules + version + hash | SHA-256 policy hash pinned at bind time | On policy change |
| Write-path enforcement | CI logs, guard configuration | Build-time execution, runtime proxy | Per deployment |
| Conformance test results | Test execution reports | 47 invariant + 24 adversarial tests | Per release |

All evidence types can be produced without additional instrumentation. They are byproducts of EP's normal operation, generated by the same mechanisms that enforce the protocol's trust properties.
