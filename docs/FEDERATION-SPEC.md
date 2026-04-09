# EP Federation Specification v1.0

**Status:** Draft  
**Date:** 2026-04-07  
**PIP:** PIP-006 (forthcoming)  

---

## Abstract

This specification defines how multiple independent EP operators can issue, verify, and cross-reference trust receipts without trusting each other. Federation makes EP a protocol that survives any single operator's failure — the same property that makes TCP/IP survive any single router's failure.

---

## Design Principles

1. **Operators don't trust each other.** They verify each other's receipts via cryptographic proofs.
2. **No central registry.** Discovery is via `/.well-known/ep-trust.json` (already implemented).
3. **Shared anchor layer.** All operators anchor Merkle roots to the same chain (Base L2). Cross-verification uses on-chain data.
4. **Receipts are portable.** An EP-RECEIPT-v1 document from Operator A can be verified by Operator B without calling A's API.
5. **Trust profiles are local.** Each operator computes their own trust profiles from the receipts they've seen. No global score.

---

## Operator Requirements

### Minimum Conformant Operator

An EP-conformant operator MUST:

1. **Implement EP Core v1.0** (PIP-001): Trust Receipt, Trust Profile, Trust Decision
2. **Issue EP-RECEIPT-v1 documents** with Ed25519 signatures
3. **Publish entity public keys** at `/.well-known/ep-keys.json`
4. **Publish operator metadata** at `/.well-known/ep-trust.json`
5. **Anchor Merkle roots** to Base L2 (or declare unanchored with reduced trust weight)
6. **Accept and verify** EP-RECEIPT-v1 documents from other operators

### Recommended Extensions

An operator SHOULD also implement:
- PIP-002 (Handshake) for pre-action enforcement
- PIP-003 (Signoff) for human accountability
- PIP-005 (Eye) for observation and advisory

---

## Discovery Protocol

### /.well-known/ep-trust.json (existing, extended)

```json
{
  "version": "1.0",
  "operator_id": "ep_op_jpmorgan",
  "operator_name": "JPMorgan Chase EP Node",
  "protocol_version": "EP-v1.0",
  "extensions": ["handshake", "signoff", "commit", "eye"],
  "endpoints": {
    "receipts": "https://ep.jpmorgan.com/api/receipts",
    "trust_profile": "https://ep.jpmorgan.com/api/trust/profile",
    "trust_decision": "https://ep.jpmorgan.com/api/trust/evaluate",
    "verify_receipt": "https://ep.jpmorgan.com/api/verify"
  },
  "keys_url": "https://ep.jpmorgan.com/.well-known/ep-keys.json",
  "anchor": {
    "chain": "base:8453",
    "wallet_address": "0x..."
  },
  "federation": {
    "accepts_cross_operator_receipts": true,
    "trusted_operators": ["ep_op_treasury", "ep_op_anthropic"],
    "trust_policy_for_unknown_operators": "review"
  }
}
```

### /.well-known/ep-keys.json (new)

```json
{
  "version": "1.0",
  "operator_id": "ep_op_jpmorgan",
  "keys": {
    "ep_entity_alice": {
      "algorithm": "Ed25519",
      "public_key": "base64url-encoded SPKI DER",
      "created_at": "2026-01-15T00:00:00Z",
      "status": "active"
    }
  },
  "rotation_policy": {
    "max_key_age_days": 365,
    "revocation_endpoint": "/api/keys/revoke"
  }
}
```

---

## Cross-Operator Receipt Verification

When Operator B receives an EP-RECEIPT-v1 document issued by Operator A:

```
1. Extract signer entity_id from doc.signature.signer
2. Discover Operator A's keys URL:
   a. If doc.signature.key_discovery is a full URL, fetch it
   b. Otherwise, look up the entity's operator via federation registry
3. Fetch Operator A's /.well-known/ep-keys.json
4. Find the signer's public key
5. Verify Ed25519 signature over canonical payload
6. If anchor present:
   a. Verify Merkle proof locally
   b. (Optional) Verify on-chain root at anchor.transaction_hash via Base L2 RPC
7. Receipt is verified: Operator B can now include it in their own trust profile computations
```

**Cross-operator receipt weight:** Operators MAY apply a configurable weight (default 0.8x) to receipts from other operators, reflecting the reduced trust in evidence they didn't originate.

---

## Federation Registry

The federation registry is a **public, append-only, decentralized** list of EP operators.

### Phase 1 (launch): GitHub-based registry
- A public repository (`emilia-protocol/federation-registry`) containing one JSON file per operator
- Operators submit PRs to register; maintainers verify conformance before merging
- Simple, auditable, no infrastructure dependency

### Phase 2 (scale): On-chain registry
- Operator registration as a smart contract on Base L2
- Operators stake a small amount of ETH to register (anti-spam, not tokenomics)
- Key rotation and revocation events emitted as contract events

### Phase 3 (maturity): DNS-based discovery
- `_ep-operator.jpmorgan.com` TXT record pointing to `/.well-known/ep-trust.json`
- Fully decentralized, no registry needed, leverages existing DNS infrastructure

---

## Trust Profile Portability

An entity that has receipts across multiple operators can:

1. **Export a receipt bundle** (EP-BUNDLE-v1) from each operator
2. **Present the bundle** to a verifier, who independently verifies each receipt
3. **The verifier computes a composite trust profile** from all verified receipts

This means an entity's trust is not locked to any single operator. If Operator A goes offline, the entity's receipts from A are still verifiable (via anchor proofs), and their receipts from Operators B, C, D are unaffected.

---

## Security Considerations

1. **Key compromise:** If an operator's signing key is compromised, only receipts signed after the compromise are affected. Receipts anchored before the compromise are still verifiable via on-chain proofs.
2. **Rogue operator:** An operator could issue fraudulent receipts. Cross-operator trust weights (0.8x default) and the ability for verifiers to exclude untrusted operators mitigate this.
3. **Federation registry takeover:** Phase 1 (GitHub) is vulnerable to maintainer compromise. Phase 2 (on-chain) eliminates this by making registration permissionless with anti-spam stake.
4. **Split-brain:** Two operators could issue conflicting receipts about the same interaction. EP handles this via bilateral confirmation — only confirmed receipts receive full weight.
