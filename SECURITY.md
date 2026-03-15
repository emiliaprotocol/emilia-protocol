# Security

## Reporting Vulnerabilities

Email security@emiliaprotocol.ai with a description of the vulnerability, steps to reproduce, and expected vs actual behavior. We will acknowledge within 48 hours and provide an initial assessment within 7 days.

Do not open public GitHub issues for security vulnerabilities.

## Threat Model

### Receipt Forgery
**Attack:** Submitter fabricates a receipt for a transaction that never happened.
**Mitigations:**
- Receipts are SHA-256 hashed with canonical JSON (sorted keys, no whitespace)
- Chain-linked: each receipt includes the previous receipt's hash
- Merkle root anchored on Base L2 — tampering is cryptographically detectable
- Bilateral attestations: counterparty can confirm or dispute
- Provenance tiers: self-attested receipts carry 0.3x weight vs bilateral at 0.8x

**Status:** Implemented. Tested in conformance suite (JS + Python cross-language verification).

### Sybil Farms (Fake Identity Volume)
**Attack:** Create many fake entities to submit favorable receipts and inflate trust.
**Mitigations:**
- Unestablished submitters carry 0.1x weight
- Sybil quality gate caps unestablished evidence at 2.0 for dampening — pure volume cannot overcome the trust barrier
- Registration rate limiting (10/hour per IP)
- Server-derived owner_id (SHA-256 of client IP) prevents identity spoofing
- Graph analysis: thin-graph (0.5x), closed-loop (0.4x), cluster (0.1x) penalties

**Status:** Implemented. 14 adversarial tests verify damage ceilings.

### Reciprocal Loops (A scores B, B scores A)
**Attack:** Two entities trade favorable receipts to inflate each other's trust.
**Mitigations:**
- Graph analysis detects closed loops and applies 0.4x weight penalty
- Cluster detection applies 0.1x penalty for tight rings
- Effective evidence dampening means even high-weight reciprocal receipts are capped

**Status:** Implemented. Adversarial tests verify.

### Trust Farming (Slow Buildup)
**Attack:** Gradually submit fake receipts over months to avoid velocity detection.
**Mitigations:**
- 90-day half-life time decay: old receipts lose weight naturally
- Anomaly detection: tracks score velocity and flags sudden changes
- Establishment requires effective_evidence ≥ 5.0 AND unique_submitters ≥ 3

**Status:** Implemented. Adversarial tests verify old receipts decay below threshold.

### Appeal/Report Spam
**Attack:** Flood the dispute/report system to overwhelm operators or suppress legitimate entities.
**Mitigations:**
- Dispute filing: 5/hour per API key
- Human reports: 3/hour per IP
- Reports do not directly affect trust — they create review objects only
- Constitutional principle: humans may trigger review, but do not directly write trust truth

**Status:** Implemented. Rate limiting enforced in middleware.

### Operator Misuse
**Attack:** A rogue operator reverses legitimate receipts or dismisses valid disputes.
**Mitigations:**
- Reversed receipts are neutralized (graph_weight → 0), never deleted — audit trail preserved
- Score recomputation happens immediately on reversal
- All dispute states are queryable via public API
- Evidence redaction tiers protect privacy while maintaining transparency

**Status:** Implemented. E2E tests verify reversal propagation.

### Context Poisoning
**Attack:** Entity performs well in one context to earn trust, then exploits it in another.
**Mitigations:**
- Context-aware evaluation: trust profiles can be filtered by category, geo, value band
- Policy evaluation includes context — "trusted for electronics" does not mean "trusted for furniture"
- Install preflight evaluates software entities against host-specific policies

**Status:** Implemented. Adversarial tests verify split-behavior detection.

## Architecture Security Properties

- **Append-only ledger:** Receipts are never deleted, only neutralized via dispute reversal
- **Immutability triggers:** Database triggers prevent modification of receipt fields after creation
- **Four-factor weighting:** submitter × time × graph × provenance — all four must be favorable for high trust
- **Identity-aware throttling:** Write operations use API key prefix + IP; read operations use IP only
- **Idempotent writes:** Duplicate transaction_ref returns existing receipt, not a new one

## What EP Does Not Protect Against

- **Real-world fraud:** EP evaluates digital trust signals. It cannot verify physical delivery or product quality directly — that requires oracle adapters (future work).
- **Compromised API keys:** If an entity's API key is stolen, the attacker can submit receipts as that entity. Rotate keys if compromised.
- **Coordinated state-level attacks:** EP is designed for commercial and software trust, not nation-state adversaries.

## Cryptographic Specifications

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Receipt hashing | SHA-256 | Canonical JSON input (sorted keys) |
| Chain linking | SHA-256 | Each receipt includes previous_hash |
| Batch anchoring | Merkle tree → Base L2 | Root published on-chain |
| API key derivation | crypto.randomBytes(32) | Stored as SHA-256 hash |
| Owner ID | SHA-256(client_ip) | First 32 hex chars |

## Conformance

Any implementation claiming EP compatibility must pass the conformance suite:
- `conformance/fixtures.json` — canonical hash vectors, provenance weights, four-factor weight vectors
- `conformance/conformance.test.js` — JavaScript verification
- `conformance/verify_hashes.py` — Python cross-language verification
