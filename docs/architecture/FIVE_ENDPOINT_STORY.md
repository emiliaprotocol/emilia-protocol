# The Five-Endpoint Story

**Version:** 1.0
**Read time:** 3 minutes

The Emilia Protocol (EP) is a protocol-grade trust substrate for high-risk action enforcement. It answers one question: **"Should this exact high-risk action be allowed to proceed under this exact policy by this exact actor right now, and can every step be proven later?"**

The entire protocol reduces to five operations.

---

## Endpoint 1: Create Policy

```
POST /api/policies
```

**What it does.** Establishes the rules that a trust ceremony will enforce. A policy declares: what claims each party must present, what assurance level is required, how bindings expire, and what evidence must be stored.

**What it binds.** Nothing yet. A policy is a template, not a commitment.

**What it proves.** That the rules existed before the ceremony began. The policy is hashed at bind time; any subsequent modification is detectable.

**Minimal payload:**
```json
{
  "policy_key": "software_install_v1",
  "rules": {
    "required_parties": {
      "initiator": {
        "required_claims": ["entity_id", "action_type"],
        "minimum_assurance": "medium"
      },
      "responder": {
        "required_claims": ["publisher_verified"],
        "minimum_assurance": "substantial"
      }
    },
    "binding": {
      "payload_hash_required": true,
      "nonce_required": true,
      "expiry_minutes": 10
    },
    "storage": {
      "store_raw_payload": false,
      "store_normalized_claims": true
    }
  }
}
```

---

## Endpoint 2: Initiate Handshake

```
POST /api/handshake
```

**What it does.** Creates a pending trust ceremony between identified parties under a named policy. Generates a cryptographic binding: a nonce, a payload hash, a party-set hash, a context hash, and an expiration. The binding is computed once and becomes the immutable reference for the entire ceremony.

**What it binds.** The action (what), the parties (who), the policy (under what rules), and a time window (how long). The binding hash covers all of these. Changing any input after initiation invalidates the ceremony.

**What it proves.** That a specific set of parties agreed to enter a trust ceremony under specific rules at a specific time, for a specific action.

**Minimal payload:**
```json
{
  "mode": "mutual",
  "policy_id": "software_install_v1",
  "parties": [
    { "role": "initiator", "entity_ref": "ep_ent_alice", "assurance_level": "medium" },
    { "role": "responder", "entity_ref": "ep_ent_package_xyz", "assurance_level": "substantial" }
  ],
  "action_type": "install",
  "resource_ref": "npm:package-xyz@3.2.1"
}
```

**Returns:** `handshake_id`, `binding.nonce`, `binding.payload_hash`, `binding.expires_at`

---

## Endpoint 3: Present

```
POST /api/handshake/{handshakeId}/present
```

**What it does.** A party submits their credentials or evidence into the ceremony. Each party presents independently. Presentations are normalized, hashed, and stored. Issuer trust is resolved against the authority registry: unknown issuers are untrusted by default (fail-closed).

**What it binds.** The presentation to the party, the party to the handshake. The authenticated caller must match the party's `entity_ref` (no role spoofing).

**What it proves.** That a specific party presented specific claims, verified by a specific issuer (or self-asserted), at a specific time. The presentation hash is immutable.

**Minimal payload:**
```json
{
  "party_role": "responder",
  "presentation": {
    "type": "publisher_attestation",
    "issuer_ref": "npm-registry-key-2025",
    "data": {
      "publisher_verified": true,
      "provenance": "sigstore",
      "package": "package-xyz",
      "version": "3.2.1"
    }
  }
}
```

---

## Endpoint 4: Verify

```
POST /api/handshake/{handshakeId}/verify
```

**What it does.** Evaluates the entire ceremony. Checks: binding expiry, nonce integrity, payload hash match, all required presentations present, assurance levels met, issuer trust status, delegation scope (if delegated mode), policy claim requirements, and policy hash integrity (tamper detection). Produces a single outcome: `accepted`, `partial`, `rejected`, or `expired`.

**What it binds.** The outcome to the evidence. The result record captures the policy version, reason codes, assurance achieved, and binding hash at evaluation time.

**What it proves.** That all parties met (or failed to meet) the policy requirements, and that the policy was not modified between initiation and verification. This is the protocol's primary output: a verifiable trust decision.

**Minimal payload:**
```json
{
  "payload_hash": "a1b2c3...",
  "nonce": "d4e5f6..."
}
```

**Returns:**
```json
{
  "handshake_id": "hs_...",
  "outcome": "accepted",
  "reason_codes": [],
  "assurance_achieved": "substantial",
  "policy_version": "software_install_v1"
}
```

---

## Endpoint 5: Consume

```
POST /api/handshake/{handshakeId}/consume
```

**What it does.** Atomically consumes a verified handshake for exactly one downstream action. A verified handshake can only be consumed once. The consumption record links the trust ceremony to the action it authorized. Double-consumption is prevented by a database unique constraint (not application logic).

**What it binds.** The trust decision to the action. After consumption, the handshake cannot authorize any other action.

**What it proves.** That the action was authorized by a specific trust ceremony, and that the authorization was used exactly once. This is the replay protection guarantee.

**Minimal payload:**
```json
{
  "binding_hash": "a1b2c3...",
  "consumed_by_type": "commit_issue",
  "consumed_by_id": "epc_abc123"
}
```

---

## The Lifecycle

```
Policy exists
    |
    v
Initiate  -->  binding created (nonce + hash + expiry)
    |
    v
Present   -->  each party submits credentials (1..n times)
    |
    v
Verify    -->  all evidence evaluated against policy --> outcome
    |
    v
Consume   -->  outcome linked to exactly one action (one-time use)
```

Five operations. One trust ceremony. Immutable evidence at every step.

Everything else in EP -- scoring, feeds, leaderboards, entity management, dispute resolution, identity continuity -- is product built on top of these five operations. The protocol is the handshake. The handshake is the protocol.
