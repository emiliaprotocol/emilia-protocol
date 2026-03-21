# EP Financial Services Vertical Reference

**Status: Canonical**
**Last updated: March 2026**
**Owner: Core team**

This document maps the 5 core EP handshake endpoints to vendor remittance change authorization in financial services. The same endpoints serve every vertical -- only the policy content and party configuration change.

---

## Use Case: Vendor Remittance Change

An accounts payable operator (or automated system) modifies the bank routing details for an existing vendor. The change must be authorized by the requesting party, independently verified by a second party, bound to the exact vendor and routing parameters, consumed exactly once, and logged for SOX compliance, internal audit, and forensic investigation.

---

## The 5 Core Endpoints

| # | Endpoint | Purpose |
|---|---|---|
| 1 | `POST /api/handshake` | Initiate a handshake binding the vendor change request |
| 2 | `GET /api/handshake/{id}` | Query handshake status (used by AP dashboard, treasury review) |
| 3 | `POST /api/handshake/{id}/present` | Submit credentials for both requestor and verifier |
| 4 | `POST /api/handshake/{id}/verify` | Verify all invariants and consume the binding |
| 5 | `POST /api/handshake/{id}/revoke` | Revoke (fraud hold, compliance block, requestor withdrawal) |

---

## Policy Example

```json
{
  "policy_id": "fin-vendor-remittance-change-v2",
  "policy_version": 2,
  "rules": {
    "required_assurance_level": "high",
    "required_roles": {
      "initiator": {
        "min_assurance": "substantial",
        "required_claims": ["employee_id", "department", "ap_authorization_tier"]
      },
      "responder": {
        "min_assurance": "substantial",
        "required_claims": ["employee_id", "department", "treasury_verification_role"]
      }
    },
    "action_constraints": {
      "action_type": "vendor_remittance_change",
      "max_ttl_seconds": 600,
      "delegation_allowed": true,
      "delegation_scope": ["fin-vendor-remittance-change-v2"]
    }
  }
}
```

**Key policy properties:**
- `required_assurance_level: high` -- the overall handshake requires "high" assurance (dual-party verification).
- Two required roles: `initiator` (AP operator) and `responder` (treasury verifier). Both must present credentials with `substantial` assurance.
- `required_claims` differ by role: the initiator proves AP authorization tier; the responder proves treasury verification role.
- `max_ttl_seconds: 600` -- the binding expires after 10 minutes. Sufficient for a callback verification but prevents overnight stale approvals.

---

## Handshake Flow

### Step 1: Initiate (AP System)

The accounts payable system calls `POST /api/handshake` when an operator submits a vendor bank detail change.

```
POST /api/handshake
{
  "mode": "mutual",
  "policy_id": "fin-vendor-remittance-change-v2",
  "action_type": "vendor_remittance_change",
  "resource_ref": "vendor:ACME-CORP-7291:remittance:primary",
  "parties": [
    {
      "party_role": "initiator",
      "entity_ref": "operator:mchen@institution.com",
      "assurance_level": "substantial"
    },
    {
      "party_role": "responder",
      "entity_ref": "verifier:treasury-ops@institution.com",
      "assurance_level": "substantial"
    }
  ],
  "payload": {
    "vendor_id": "ACME-CORP-7291",
    "vendor_name_hash": "SHA256-OF-VENDOR-LEGAL-NAME",
    "old_routing_hash": "SHA256-OF-OLD-ABA-AND-ACCOUNT",
    "new_routing_hash": "SHA256-OF-NEW-ABA-AND-ACCOUNT",
    "change_source": "vendor_letter",
    "change_ticket": "AP-2026-11847",
    "amount_threshold_exceeded": true
  }
}
```

**What EP does:**
- Verifies the authenticated caller matches the initiator `entity_ref`.
- Resolves the policy, computes `policy_hash`, generates nonce, computes canonical binding hash.
- Sets binding expiry to 600 seconds.
- Emits `handshake_initiated` event.
- Returns handshake ID and binding details.

**Why `mutual` mode:** Vendor remittance changes require independent verification. The `mutual` mode enforces that both parties present credentials before verification can succeed.

### Step 2: Present -- Initiator (AP Operator)

```
POST /api/handshake/{id}/present
{
  "party_role": "initiator",
  "presentation_type": "corporate_credential",
  "issuer_ref": "institution-iam-root-2025",
  "presentation_hash": "SHA256-OF-CREDENTIAL",
  "normalized_claims": {
    "employee_id": "MC-11847",
    "department": "Accounts Payable",
    "ap_authorization_tier": "tier_2_vendor_changes"
  }
}
```

### Step 3: Present -- Responder (Treasury Verifier)

The treasury operations team receives a verification request (via existing workflow -- email, queue, dashboard). The treasury verifier presents their own credentials.

```
POST /api/handshake/{id}/present
{
  "party_role": "responder",
  "presentation_type": "corporate_credential",
  "issuer_ref": "institution-iam-root-2025",
  "presentation_hash": "SHA256-OF-CREDENTIAL",
  "normalized_claims": {
    "employee_id": "JL-55201",
    "department": "Treasury Operations",
    "treasury_verification_role": "vendor_payment_verifier"
  }
}
```

**What EP does for both presentations:**
- Actor-party binding check: authenticated entity must match party `entity_ref`. Mismatch = `ROLE_SPOOFING`.
- Issuer resolution against `authorities` table. Fail-closed on unknown/revoked/expired issuers.
- Claims stored and hashed for later policy evaluation.

### Step 4: Verify and Consume

```
POST /api/handshake/{id}/verify
{
  "action_hash": "EXPECTED-BINDING-HASH",
  "policy_hash": "EXPECTED-POLICY-HASH"
}
```

**Verification pipeline:**
1. Consumption gate: reject if already consumed.
2. State gate: must be `pending_verification`.
3. Hash checks: action hash and policy hash must match.
4. Binding checks: expiry, nonce, payload hash.
5. Party checks: both `initiator` and `responder` must have presentations (mutual mode).
6. Assurance checks: both parties meet `substantial`.
7. Issuer checks: both authorities must be valid.
8. Claims checks: initiator has `ap_authorization_tier`, responder has `treasury_verification_role`.
9. Outcome: zero reason codes = `accepted`.

**On acceptance:** Binding consumed. AP system executes the vendor routing change. `handshake_verified` event emitted.

**On rejection:** Change does not execute. Reason codes returned. `handshake_rejected` event emitted.

---

## Consumption Semantics

- **One-time**: The same approval cannot authorize a second vendor change or a duplicate of the same change.
- **Database-enforced**: `consumed_at IS NULL` conditional update + unique constraint on `handshake_consumptions`.
- **Concurrent-safe**: If two systems attempt to consume the same binding simultaneously, exactly one succeeds.
- **Non-replayable**: Nonce + expiry + consumption triple. A captured approval cannot be re-presented.

---

## Evidence Trail

| Record | Contains | SOX Relevance |
|---|---|---|
| Handshake events | Full lifecycle with actor refs and timestamps | Section 302/404: authorization trail for material financial changes |
| Protocol events | Command type, actor authority, payload hash, parent event hash | Continuous control monitoring evidence |
| Binding material | Vendor ID, old/new routing hashes, policy hash, nonce, expiry | Proof that approval was bound to exact parameters |
| Dual presentations | Both AP operator and treasury verifier credentials, issuer verification | Segregation of duties evidence |
| Consumption record | Consumed_at, consumed_by, consumed_for | One-time use proof, prevents duplicate payment redirect |

### What This Proves to an Auditor

1. **Segregation of duties** -- two distinct authenticated parties, from different departments, with different required claims, both verified against the authority registry.
2. **Parameter binding** -- the exact vendor, the exact old and new routing details, bound by hash. Any modification invalidates the approval.
3. **Policy compliance** -- the policy version and hash that governed the decision are recorded. Policy drift is detectable.
4. **Temporal constraints** -- 10-minute TTL prevents stale approvals. Timestamps prove the verification occurred within the window.
5. **Non-reuse** -- consumption record with unique constraint proves the approval was used exactly once.
6. **Tamper resistance** -- append-only event tables with database triggers preventing modification.

---

## Integration Checklist

- [ ] Register corporate IAM authority in the `authorities` table
- [ ] Define vendor remittance change policy with dual-party requirements
- [ ] Add handshake initiation to AP vendor change workflow
- [ ] Add initiator presentation submission (AP operator credentials)
- [ ] Add responder notification and presentation workflow (treasury verification)
- [ ] Add verification call as the authorization gate before executing the routing change
- [ ] Configure event export to SIEM/GRC platform
- [ ] Run conformance tests (47 invariant tests, 24 adversarial tests)

**Estimated integration time**: 1--2 weeks for the AP system integration; 1 additional week for treasury verification workflow if building a new notification/queue.

---

*EMILIA Protocol -- emiliaprotocol.ai -- github.com/emiliaprotocol/emilia-protocol -- Apache 2.0*
