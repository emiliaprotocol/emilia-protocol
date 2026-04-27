# PIP-001: EP Core v1.0 Freeze

**Status:** Accepted  
**Type:** Core  
**Created:** 2026-04-07  
**Author(s):** Iman Schrock  

## Abstract

This PIP formally freezes EP Core v1.0 — the three interoperable trust objects that form the foundation of the EMILIA Protocol. After this freeze, Core objects can only be extended, never modified. Any breaking change requires a new major version with a 24-month deprecation window.

## EP Core v1.0 — Frozen Objects

### 1. Trust Receipt

A portable, signed record of a trust-relevant interaction between entities.

**Required fields:**
| Field | Type | Description |
|-------|------|-------------|
| `receipt_id` | string | Globally unique identifier (`ep_r_*` prefix) |
| `issuer` | string | Entity that created the receipt |
| `subject` | string | Entity the receipt is about |
| `claim` | object | `{ action_type, outcome, context, domain? }` |
| `receipt_hash` | string | SHA-256 of the canonical receipt content |
| `created_at` | ISO-8601 | Creation timestamp |

**Signature envelope (EP-RECEIPT-v1):**
| Field | Type | Description |
|-------|------|-------------|
| `signature.algorithm` | string | `Ed25519` |
| `signature.value` | string | Base64url-encoded Ed25519 signature over canonical payload |
| `signature.signer` | string | Entity ID of the signer |
| `signature.key_discovery` | string | URL path to discover the signer's public key |

**Anchor envelope (optional):**
| Field | Type | Description |
|-------|------|-------------|
| `anchor.chain` | string | `base:{chainId}` |
| `anchor.transaction_hash` | string | On-chain transaction hash |
| `anchor.block_number` | integer | Block number |
| `anchor.merkle_root` | string | Merkle root anchored on-chain |
| `anchor.merkle_proof` | array | Proof of inclusion |
| `anchor.leaf_hash` | string | This receipt's hash (leaf in the tree) |

### 2. Trust Profile

A structured summary of an entity's trust state, derived from receipts.

**Required fields:**
| Field | Type | Description |
|-------|------|-------------|
| `entity_id` | string | The profiled entity |
| `score` | number | Overall trust score (0.0–1.0) |
| `confidence` | string | `pending` / `insufficient` / `provisional` / `emerging` / `confident` |
| `evidence_depth` | integer | Total receipt count |
| `positive_rate` | number | Fraction of positive outcomes (0.0–1.0) |
| `provenance_composition` | object | Breakdown by provenance tier |
| `domain_scores` | object | Per-domain trust scores |
| `computed_at` | ISO-8601 | When this profile was last computed |

### 3. Trust Decision

A policy-evaluated decision for a specific action.

**Required fields:**
| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | `allow` / `review` / `deny` |
| `entity_id` | string | The evaluated entity |
| `policy_used` | string | Policy identifier |
| `reasons` | array | Human-readable decision reasons |
| `evidence_sufficient` | boolean | Whether evidence met policy threshold |
| `appeal_available` | boolean | Whether the entity can contest this decision |
| `decided_at` | ISO-8601 | Decision timestamp |

## Frozen Verification Algorithm

The standalone verification algorithm for Trust Receipts is:

```
1. Parse the EP-RECEIPT-v1 document
2. Canonicalize the payload: JSON.stringify(payload, sorted_keys)
3. Verify Ed25519 signature over canonical payload bytes
4. If anchor present:
   a. Walk the Merkle proof from leaf_hash to root
   b. Compare computed root with anchor.merkle_root
   c. (Optionally) verify anchor.merkle_root on-chain at anchor.transaction_hash
5. Receipt is verified if: signature valid AND (no anchor OR anchor valid)
```

## Extension Mechanism

Extensions build on Core without modifying it:
- **Handshake** (PIP-002): Multi-party trust ceremony using receipts as evidence
- **Signoff** (PIP-003): Human accountability gate consuming a verified handshake
- **Commit** (PIP-004): Atomic action seal referencing receipts and handshakes
- **Eye** (PIP-005): Observation layer producing advisories that inform policy

## Backwards Compatibility

This is the genesis freeze. No prior version to maintain compatibility with.

## Security Considerations

- Ed25519 provides 128-bit security level (equivalent to RSA-3072)
- SHA-256 for hashing is collision-resistant to ~2^128
- Merkle proofs are O(log n) in tree size — verification is fast
- Key discovery via `/.well-known/` follows RFC 8615
