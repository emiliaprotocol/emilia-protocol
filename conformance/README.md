# EP Conformance Suite

Canonical test fixtures and verification tests for EMILIA Protocol implementations.

Any implementation claiming EP compatibility **must** produce identical outputs for these inputs.

## What's tested

| Category | What it verifies |
|----------|-----------------|
| **Hash determinism** | Same receipt → same SHA-256 hash, regardless of key order, across languages |
| **Sybil resistance** | Fake receipts from unestablished entities produce low effective evidence and dampened scores |
| **Policy evaluation** | Built-in policies (strict/standard/permissive/discovery) produce correct Trust Decisions (allow/review/deny) for canonical inputs |
| **Confidence levels** | Effective evidence thresholds map to correct confidence labels |
| **Weight model** | v2 weights match published values and sum to 1.00 |
| **Establishment rules** | Effective evidence ≥ 5.0 AND ≥ 3 unique submitters = established |

## Files

- `fixtures.json` — Canonical inputs and expected outputs. Language-agnostic.
- `conformance.test.js` — Vitest runner for the JavaScript reference implementation.

## Running

```bash
npx vitest run conformance/
```

## For other languages

Load `fixtures.json`, implement canonical JSON serialization (sorted keys, no whitespace), compute SHA-256, and compare against `expected_hash` values.

The canonical JSON algorithm:
1. For objects: sort keys lexicographically, recurse into values
2. For arrays: preserve order, recurse into elements
3. For primitives: use standard JSON serialization
4. No whitespace between tokens

If your implementation produces the same hashes for all 4 hash fixtures, your canonical JSON + hashing is compatible.

## Adding fixtures

All fixtures are generated from the reference implementation. To add a new fixture:

1. Define the receipt in `fixtures.json`
2. Run the reference implementation to compute the expected hash
3. Add the expected hash to the fixture
4. Add a corresponding test in `conformance.test.js`

## License

Apache 2.0 — same as EMILIA Protocol.
