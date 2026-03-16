# EMILIA Protocol — Conformance

## What conformance means

An implementation is EP-conformant if it produces identical outputs to the reference implementation for all canonical test vectors.

## Conformance suite

The canonical conformance suite lives in `conformance/`:

| File | Purpose |
|------|---------|
| `fixtures.json` | Canonical test vectors (hashes, scoring, policies, establishment, confidence, provenance, trust profiles) |
| `conformance.test.js` | JavaScript conformance runner |
| `verify_hashes.py` | Cross-language hash verification (Python) |

## How to verify conformance

### JavaScript implementation
```bash
npx vitest run conformance/conformance.test.js
```

### Python implementation
```bash
python3 conformance/verify_hashes.py
```

### Any other language
1. Parse `conformance/fixtures.json`
2. For each hash fixture: compute SHA-256 of the canonical JSON representation and compare
3. For each scoring fixture: compute the trust profile and compare against expected outputs
4. For each policy fixture: evaluate the policy and compare pass/fail

## Conformance levels

| Level | Requirements |
|-------|-------------|
| **Hash-compatible** | All hash fixtures produce identical SHA-256 outputs |
| **Score-compatible** | All scoring fixtures produce outputs within ±0.1 tolerance |
| **Policy-compatible** | All policy fixtures produce identical pass/fail decisions |
| **Full conformance** | All of the above, plus establishment rules and confidence levels match |

## Protocol invariants

These invariants must hold in any conformant implementation:

1. **Hash determinism** — identical receipt inputs produce identical SHA-256 hashes regardless of implementation language
2. **Trust barrier** — pure unestablished volume cannot cross the establishment threshold (qualityGatedEvidence caps unestablished contribution at 2.0)
3. **Policy monotonicity** — if an entity passes `strict`, it passes `standard`, `permissive`, and `discovery`
4. **Appeal supremacy** — trust must never be more powerful than appeal; every negative trust effect must be challengeable

## Self-certification

Conformance is self-certified against the published suite. The working group maintains the canonical fixtures. Implementations that pass all fixtures may display:

> **EP Conformant** — verified against fixtures v1.0

## Reporting issues

If you find a case where the reference implementation contradicts the spec or the fixtures, file a GitHub issue. Protocol correctness is more important than backward compatibility.
