# Property-Based Tests — EP Protocol Invariants

Section 2.4 of the reviewer's next-phase document.

## Overview

The property-based test suite (`tests/property-based.test.js`) uses [fast-check](https://github.com/dubzzz/fast-check) to verify that EP protocol invariants hold across hundreds of randomly generated inputs. Unlike example-based tests, property tests explore the input space stochastically, catching edge cases that hand-written fixtures miss.

## What Is Property-Tested

### 1. Binding Canonicalization Stability

**Property:** `canonicalizeBinding(material) === canonicalizeBinding(reversed)` for any key insertion order.

**Why:** The binding hash must be deterministic regardless of how JavaScript objects are constructed. If canonicalization were sensitive to insertion order, two logically identical bindings could produce different hashes, breaking verification.

### 2. Hash Determinism

**Property:** `hashBinding(m) === hashBinding(m)` for any binding material `m`.

**Why:** A non-deterministic hash would mean a binding could not be verified after creation. This is a foundational requirement for the entire binding verification chain.

### 3. Collision Resistance Per Field

**Properties tested per field:**
- Different `action_type` produces different hash
- Different `policy_hash` produces different hash
- Different `party_set_hash` produces different hash
- Different `nonce` produces different hash
- Different `resource_ref` produces different hash

**Why:** Each canonical binding field must contribute to the hash. If changing a field does not change the hash, that field is not cryptographically bound, and an attacker could swap it without detection. These tests verify that every security-critical field is included in the hash computation.

### 4. Canonical Field Coverage

**Property:** `Object.keys(buildBindingMaterial(params)).sort()` equals `CANONICAL_BINDING_FIELDS.sort()` for all valid inputs.

**Why:** The binding material must contain exactly the canonical fields — no more, no fewer. Extra fields could leak data or create ambiguity. Missing fields would weaken the binding. This test ensures `buildBindingMaterial` and `CANONICAL_BINDING_FIELDS` stay in sync.

### 5. Hash Output Format

**Property:** `hashBinding(m)` always matches `/^[0-9a-f]{64}$/`.

**Why:** Downstream systems (database storage, API responses, verification logic) depend on the hash being a 64-character lowercase hex string (SHA-256). Malformed output would break storage, comparison, or display.

### 6. Party Set Order Independence

**Property:** `computePartySetHash(parties) === computePartySetHash(parties.reverse())`.

**Why:** Party sets are conceptually unordered (the set {initiator: A, responder: B} is the same regardless of which party is listed first). The hash must be order-independent so that different construction sequences produce the same binding.

### 7. Party Set Collision Resistance

**Property:** Different party sets produce different hashes.

**Why:** If two distinct party sets hashed to the same value, an attacker could substitute one party set for another without changing the binding hash.

### 8. State Machine Terminal/Non-Terminal Partition

**Properties:**
- Terminal states (`rejected`, `expired`, `revoked`) are a subset of `HANDSHAKE_STATUSES`
- Non-terminal states (`initiated`, `pending_verification`, `verified`) are a subset of `HANDSHAKE_STATUSES`
- No state is both terminal and non-terminal
- Terminal and non-terminal together cover all statuses

**Why:** The state machine must have a clean partition. If a state were accidentally omitted or duplicated, handshakes could get stuck in unhandled states or transition incorrectly.

### 9. Consumption Idempotency Key Determinism

**Property:** The SHA-256 of `entity|type|ref` is deterministic for any string inputs.

**Why:** Consumption idempotency keys prevent double-consumption of handshake bindings. If the key computation were non-deterministic, the same consumption could be processed twice, violating the at-most-once guarantee.

## Test Configuration

- **Generator runs:** 100-200 per property (configurable via `numRuns`)
- **Input space:** Random hex strings (64 chars), ISO dates (2020-2030), action types from the protocol enum, arbitrary UTF-8 strings for identifiers
- **Preconditions:** `fc.pre()` is used to filter degenerate cases (e.g., ensuring two hashes are actually different before testing collision resistance)

## Running

```bash
npx vitest run tests/property-based.test.js
```

## Relationship to Other Test Suites

| Suite | Focus |
|---|---|
| `handshake-adversarial.test.js` | Attack scenarios, race conditions, double consumption |
| `property-based.test.js` | Structural invariants across random inputs |
| Conformance matrix (`TEST_MATRIX.md`) | Traceability to reviewer requirements |
