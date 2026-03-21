# EMILIA Protocol -- Trust Roots

## Scope

This document describes how EP establishes, manages, and enforces trust roots. A trust root is a registry entry in the `authorities` table that anchors issuer trust for handshake presentations. Without a valid trust root, no externally-issued presentation can be verified.

---

## 1. Issuer Registry Model

**Registry**: The `authorities` table is the single source of truth for issuer trust. Each row represents one trusted authority key.

**Registry fields**:
- `authority_id`: Internal primary key.
- `key_id`: The external identifier used by presentations (`issuer_ref`). Presentations reference this field to claim issuer identity.
- `status`: One of `active`, `revoked`. Only `active` authorities pass trust checks.
- `valid_from`: ISO 8601 timestamp. The authority is not trusted before this time.
- `valid_to`: ISO 8601 timestamp. The authority is not trusted after this time.

**Lookup**: Issuer trust is resolved by matching `presentation.issuer_ref` against `authorities.key_id`. The presentation payload itself is never used as a source of key material.

**CI guard**: `scripts/check-protocol-discipline.js` scans for patterns like `presentation.publicKey`, `presentation.signingKey`, and `payload.key` to prevent embedded key trust.

---

## 2. Trust Root Lifecycle

### 2.1 Provisioning

New trust roots are added to the `authorities` table with:
- A unique `key_id` corresponding to the issuer's public key identifier.
- `status` set to `active`.
- `valid_from` set to the intended activation time (or `now` for immediate activation).
- `valid_to` set to the intended expiry (or `null` for no expiry).

Provisioning is a privileged operation. Only the `system` actor or authorized administrative flows may insert into `authorities` (enforced by write-guard; `authorities` is a trust table).

### 2.2 Rotation

Key rotation follows a two-phase model:
1. **Provision new key**: Insert a new `authorities` row with the new `key_id` and `valid_from` set to overlap with the old key's validity.
2. **Deprecate old key**: Set `valid_to` on the old row to a future time that allows in-flight handshakes to complete.

There is no atomic "swap" operation. Both keys are concurrently valid during the overlap window. Handshakes initiated with the old key remain valid until their binding expires or the old key's `valid_to` passes.

### 2.3 Revocation

Setting `status = 'revoked'` on an authority row immediately untrusts the issuer. Any in-flight or future presentation referencing the revoked `key_id` will receive `issuer_status: 'authority_revoked'` and `verified: false`.

Revocation is immediate and non-reversible in the trust evaluation path. A revoked authority cannot be "unrevoked" -- a new authority row with a new `key_id` must be provisioned instead.

---

## 3. Issuer Validation Pipeline

When `_handleAddPresentation()` processes a presentation with an `issuer_ref`, it runs the following pipeline. The default state before resolution is `issuerTrusted = false` (fail-closed).

**Step 1 -- Registry lookup**: Query `authorities` by `key_id = issuer_ref`.

**Step 2 -- Status classification**:

| Condition | `issuerTrusted` | `issuerTrustReason` | `revocation_status` |
|---|---|---|---|
| Authority found, status `active`, within validity window | `true` | `authority_valid` | `good` |
| Authority found, status `revoked` | `false` | `authority_revoked` | `revoked` |
| Authority found, `valid_to` in the past | `false` | `authority_expired` | `expired` |
| Authority found, `valid_from` in the future | `false` | `authority_not_yet_valid` | `not_yet_valid` |
| Authority not found in registry | `false` | `authority_not_found` | `unknown` |
| Authority table missing or unreachable | `false` | `authority_table_missing` | `registry_unavailable` |

**Step 3 -- Self-asserted presentations**: If `issuer_ref` is null, the presentation is self-asserted. `issuerTrusted` is set to `true` with reason `self_asserted`. Trust determination is deferred to policy rules at verification time.

**Invariant enforcement**: `checkIssuerTrusted()` and `checkAuthorityNotRevoked()` in `lib/handshake/invariants.js` provide pure-function checks used by `runAllInvariants()` during verification.

---

## 4. Trust Root Compromise Response

If a trust root key is compromised:

1. **Immediate revocation**: Set `status = 'revoked'` on the compromised authority row. All subsequent presentations referencing this `key_id` are rejected.
2. **Audit**: Query `handshake_presentations` for all presentations where `issuer_ref` matches the compromised `key_id` and `verified = true`. These represent handshakes that may have been authorized under a compromised key.
3. **Handshake invalidation**: Active (unconsumed) handshakes that relied on the compromised issuer should be expired or revoked via status transition.
4. **Re-provisioning**: Issue a new authority row with a fresh `key_id`. Upstream issuers must update their signing infrastructure to use the new key.

There is no "re-sign" mechanism. Presentations issued under the compromised key cannot be migrated. New presentations must be submitted.

---

## 5. Multi-Issuer Scenarios

EP supports multiple concurrent trust roots. A single handshake may involve presentations from different issuers, each validated independently against the registry.

**Resolution**: Each presentation's `issuer_ref` is resolved separately. One presentation's issuer failure does not affect another's trust status. The handshake outcome depends on policy rules that define which parties and assurance levels are required.

**Policy interaction**: Policy rules specify `required_parties` with optional `assurance_level` thresholds. A party's presentation is only useful if its issuer is trusted. If the policy requires a `responder` presentation at `substantial` assurance and the responder's issuer is revoked, that requirement is unmet.

**Cross-domain trust**: EP does not implement federated trust root discovery. Each deployment maintains its own `authorities` table. Cross-domain trust is established by provisioning the remote domain's issuer key into the local registry.

---

## 6. Connection to Policy Binding

Trust roots anchor the bottom of the policy binding chain:

```
policy_hash (pinned at initiation)
  -> policy.rules.required_parties (defines who must present)
    -> presentation.issuer_ref (claims issuer identity)
      -> authorities.key_id (registry-rooted trust root)
        -> validity window + revocation status (trust evaluation)
```

If the trust root is invalid at verification time, the presentation fails trust evaluation, the required party condition is unmet, and the handshake is rejected. Policy hash pinning ensures that the trust requirements themselves cannot be weakened between initiation and verification.

**Write protection**: The `authorities` table is listed in `TRUST_TABLES` in `lib/write-guard.js`. Direct writes from route handlers are blocked; only `protocolWrite()` and the canonical layer may modify authority records.
