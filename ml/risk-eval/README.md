# EP Risk-Classifier eval harness

This harness benchmarks advisory classifiers against `cases.jsonl` while
preserving the deterministic policy as the binding floor. Design rationale:
[`docs/ml/risk-classifier.md`](../../docs/ml/risk-classifier.md).

## Gate the shipped deterministic layer

```bash
npm run ml:selftest
npm run ml:eval
npm run ml:gate
```

`npm run ml:eval` runs the heuristic with `--min-perimeter=100`, so either a
dangerous covered-case miss or perimeter coverage below 100% exits nonzero.
The threshold is explicit and reusable:

```bash
node ml/risk-eval/eval.mjs heuristic --min-perimeter=100
```

The rules baseline remains an informational comparison:

```bash
node ml/risk-eval/eval.mjs
```

## What the eval checks

- **Covered cases** are deterministic-engine regressions. Seeing an expected
  gate (`deny` or `allow_with_signoff`) as `allow` is a dangerous miss.
- **Perimeter cases** are fuzzy/novel actions exact rules miss. Their coverage
  becomes a hard gate only when `--min-perimeter=<0..100>` is supplied.

Append one JSON object per line to add a case:

```json
{"id":"...","tier":"covered|perimeter","input":{"actionType":"...","targetChangedFields":[],"riskFlags":[]},"expected":{"decision":"allow|allow_with_signoff|deny"},"note":"..."}
```

## Remote self-hosted model contract

`classifiers/tinker.mjs` is a transport adapter, not a model or weights claim.
It evaluates `evaluateGuardPolicy(input)` first, then calls
`EP_RISK_MODEL_URL`. The endpoint must return:

```json
{"tier":"allow|allow_with_signoff|deny","injection_suspected":false}
```

The adapter enforces these invariants:

- a remote lower tier never lowers deterministic signoff or deny;
- remote `deny` remains advisory and raises a bare allow only to signoff;
- `injection_suspected: true` raises a bare allow to signoff;
- invalid JSON/schema/tier, timeout, HTTP error, and network error fail closed
  to signoff when the deterministic result was allow;
- failure evidence is returned in `advisory`; there is no silent allow fallback.

Configuration:

```bash
export EP_RISK_MODEL_URL=http://localhost:8000/classify
export EP_RISK_MODEL_TIMEOUT_MS=2000  # optional; integer 1..60000
node ml/risk-eval/eval.mjs tinker --min-perimeter=100
```

No endpoint is called by `npm run ml:gate`. The remote behavior is covered with
an injected fake transport in `tinker.selftest.mjs`.

> Importing the engine logs a one-time Node
> `MODULE_TYPELESS_PACKAGE_JSON` warning because the repository package is
> CommonJS while the engine uses ESM syntax. It does not affect the gate.
